// chromeless — the browser that isn't there.
//
// A single-file macOS browser with almost no chrome: no toolbar, no address
// bar, and no tab bar until you open a second tab — just the page, in a bare
// rounded window. Built on WKWebView (the Safari engine). Made for clean
// screenshots and fullscreen video.
//
//   ⌘L  search / open url        ⇧⌘S  snapshot page → Desktop
//   ⌘R  reload                   ⌘P   pin window on top
//   ⌘[ ⌘]  back / forward        ⌃⌘F  fullscreen
//   ⌘= ⌘- ⌘0  zoom               ⌘drag  move the window
//   ⌘T  new tab                  ⌃Tab  next tab
//   ⇧⌘T  reopen a closed tab     ⇧⌘N   private window
//   ⌘F  find in page             ⌘G ⇧⌘G  next / previous match
//   ⇧⌘B  allow ads here          ⌃⇧⌘E  pick an element to hide
//   ⇧⌘A  ai sidebar for this tab
//   F12  web inspector          ⌥⌘I  the same thing
//   ⌘click  link → background tab   ⇧⌘click  → foreground tab
//
// CLI screenshot mode:
//   chromeless https://example.com --snap out.png --size 1440x900 --wait 2

import Cocoa
import Security
import WebKit

// MARK: - Passkey capability

// WKWebView performs WebAuthn (passkeys via iCloud Keychain / Touch ID) only for
// apps signed with Apple's restricted web-browser.public-key-credential
// entitlement, which needs an Apple-issued provisioning profile — macOS kills
// ad-hoc builds that claim it. So: if this build carries the entitlement,
// passkeys just work; if not, hide the WebAuthn API so sites feature-detect the
// absence and offer their fallback sign-in (password, phone prompt) instead of
// a passkey ceremony that is guaranteed to fail. See README for enabling it.
let hasPasskeyEntitlement: Bool = {
    guard let task = SecTaskCreateFromSelf(nil) else { return false }
    let value = SecTaskCopyValueForEntitlement(
        task, "com.apple.developer.web-browser.public-key-credential" as CFString, nil)
    return (value as? Bool) == true
}()

// MARK: - URL smarts

func smartURL(_ input: String) -> URL? {
    let t = input.trimmingCharacters(in: .whitespacesAndNewlines)
    if t.isEmpty { return nil }
    if t.hasPrefix("/") || t.hasPrefix("~") {
        let path = (t as NSString).expandingTildeInPath
        if FileManager.default.fileExists(atPath: path) { return URL(fileURLWithPath: path) }
    }
    if t.contains("://") { return URL(string: t) }
    let lower = t.lowercased()
    for host in ["localhost", "127.0.0.1", "0.0.0.0", "[::1]"] where lower.hasPrefix(host) {
        return URL(string: "http://" + t)
    }
    if !t.contains(" "), t.contains(".") { return URL(string: "https://" + t) }
    let q = t.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? t
    return URL(string: "https://www.google.com/search?q=" + q)
}

// MARK: - Launch options

struct SnapJob { let path: String; let wait: TimeInterval }

struct LaunchOptions {
    var url: URL? = nil
    var snap: SnapJob? = nil
    var size: NSSize? = nil
    var restoreLastPage = false
    var profile: String? = nil
    var listProfiles = false
    var privateWindow = false
    var remote = false
}

func parseLaunchOptions() -> LaunchOptions {
    var opts = LaunchOptions()
    var snapPath: String? = nil
    var wait: TimeInterval = 1.0
    let args = Array(CommandLine.arguments.dropFirst())
    var i = 0
    while i < args.count {
        let a = args[i]
        switch a {
        case "--help", "-h":
            print("""
            chromeless — the browser that isn't there

            usage: chromeless [url] [options]
              --snap <path>     load the page, save a PNG of it, and quit
              --size <WxH>      window size in points (e.g. 1440x900)
              --wait <seconds>  extra settle time before --snap (default 1.0)
              --restore         reopen the last saved page instead of the start page
              --profile <name>  use a specific profile
              --profiles        list profiles and exit
              --private         open a private window (nothing is saved)
              --remote          listen on the control socket so tools can drive the browser
              --adblock-selftest  check the filter converter and exit
              --adblock-compiletest  convert every installed list and compile it for real

            examples:
              chromeless youtube.com
              chromeless localhost:3000 --snap shot.png --size 1280x800
              chromeless --profile work onedrive.live.com
            """)
            exit(0)
        case "--snap":
            i += 1
            if i < args.count { snapPath = args[i] }
        case "--size":
            i += 1
            if i < args.count {
                let parts = args[i].lowercased().split(separator: "x").compactMap { Double($0) }
                if parts.count == 2 { opts.size = NSSize(width: parts[0], height: parts[1]) }
            }
        case "--wait":
            i += 1
            if i < args.count { wait = Double(args[i]) ?? 1.0 }
        case "--restore":
            opts.restoreLastPage = true
        case "--profile":
            i += 1
            if i < args.count { opts.profile = args[i] }
        case "--profiles":
            opts.listProfiles = true
        case "--private":
            opts.privateWindow = true
        case "--remote":
            opts.remote = true
        case "--adblock-selftest":
            runAdBlockSelfTest()
        case "--adblock-compiletest":
            runAdBlockCompileTest()
        default:
            if a.hasPrefix("-") {
                fputs("chromeless: ignoring unknown option \(a)\n", stderr)
            } else if let u = smartURL(a) {
                opts.url = u
            }
        }
        i += 1
    }
    if let p = snapPath {
        let abs = p.hasPrefix("/") ? p : FileManager.default.currentDirectoryPath + "/" + p
        opts.snap = SnapJob(path: abs, wait: wait)
    }
    return opts
}

let launchOptions = parseLaunchOptions()

// MARK: - Profiles

struct BrowserProfile: Codable, Identifiable, Equatable {
    var id: String
    var name: String
    var dataStoreID: String
    var lastURL: String?
    var history: [String]
    var createdAt: Date
    var updatedAt: Date

    var dataStoreUUID: UUID {
        UUID(uuidString: dataStoreID) ?? UUID(uuidString: "F4D7F032-4548-4E72-98A3-3F6F9946E6E3")!
    }
}

struct ProfileArchive: Codable {
    var defaultProfileID: String?
    var profiles: [BrowserProfile]
}

final class ProfileStore {
    private static let defaultDataStoreID = "F4D7F032-4548-4E72-98A3-3F6F9946E6E3"
    private(set) var defaultProfileID = "default"
    private(set) var profiles: [BrowserProfile] = []
    private let directoryURL: URL
    private let fileURL: URL

    init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        directoryURL = appSupport.appendingPathComponent("Chromeless/Profiles", isDirectory: true)
        fileURL = directoryURL.appendingPathComponent("profiles.json")
        load()
    }

    var defaultProfile: BrowserProfile {
        profiles.first { $0.id == defaultProfileID }
            ?? profiles.first { $0.id == "default" }
            ?? profiles[0]
    }

    var usesPersistentProfileStores: Bool {
        if #available(macOS 14.0, *) { return true }
        return false
    }

    func profile(matching value: String?) -> BrowserProfile? {
        guard let value, !value.isEmpty else { return defaultProfile }
        let needle = value.lowercased()
        return profiles.first {
            $0.id.lowercased() == needle || $0.name.lowercased() == needle
        }
    }

    func websiteDataStore(for profile: BrowserProfile) -> WKWebsiteDataStore {
        if #available(macOS 14.0, *) {
            return WKWebsiteDataStore(forIdentifier: profile.dataStoreUUID)
        }
        return .nonPersistent()
    }

    func createProfile(named rawName: String) throws -> BrowserProfile {
        let cleanName = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        let name = cleanName.isEmpty ? "New Profile" : cleanName
        let id = uniqueID(from: name)
        let now = Date()
        let profile = BrowserProfile(
            id: id,
            name: name,
            dataStoreID: UUID().uuidString,
            lastURL: nil,
            history: [],
            createdAt: now,
            updatedAt: now)
        profiles.append(profile)
        try ensureDirectory(for: profile)
        save()
        return profile
    }

    func setDefaultProfile(_ profile: BrowserProfile) {
        guard profiles.contains(where: { $0.id == profile.id }) else { return }
        defaultProfileID = profile.id
        save()
    }

    func deleteProfile(_ profile: BrowserProfile, completion: @escaping (Error?) -> Void) {
        guard profiles.count > 1 else {
            completion(NSError(
                domain: "ChromelessProfiles", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Chromeless needs at least one profile."]))
            return
        }
        guard let index = profiles.firstIndex(where: { $0.id == profile.id }) else {
            completion(NSError(
                domain: "ChromelessProfiles", code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Profile not found."]))
            return
        }

        let removed = profiles.remove(at: index)
        if defaultProfileID == removed.id {
            defaultProfileID = profiles.first { $0.id == "default" }?.id ?? profiles[0].id
        }
        save()

        do {
            let folder = directoryURL.appendingPathComponent(removed.id, isDirectory: true)
            if FileManager.default.fileExists(atPath: folder.path) {
                try FileManager.default.removeItem(at: folder)
            }
        } catch {
            completion(error)
            return
        }

        if #available(macOS 14.0, *) {
            WKWebsiteDataStore.remove(forIdentifier: removed.dataStoreUUID) { error in
                completion(error)
            }
        } else {
            completion(nil)
        }
    }

    func recordVisit(_ url: URL, for profile: BrowserProfile) {
        guard url.scheme == "https" || url.scheme == "http" else { return }
        guard let index = profiles.firstIndex(where: { $0.id == profile.id }) else { return }
        let value = url.absoluteString
        profiles[index].lastURL = value
        profiles[index].history.removeAll { $0 == value }
        profiles[index].history.append(value)
        if profiles[index].history.count > 200 {
            profiles[index].history.removeFirst(profiles[index].history.count - 200)
        }
        profiles[index].updatedAt = Date()
        save()
    }

    // Drops every recorded visit under the domain, along with a lastURL
    // pointing at it — otherwise the next launch would resurrect a page whose
    // site data was just wiped.
    func removeHistory(forDomain domain: String, in profile: BrowserProfile) {
        guard let index = profiles.firstIndex(where: { $0.id == profile.id }) else { return }
        profiles[index].history.removeAll {
            URL(string: $0)?.host.flatMap { registrableDomain(for: $0) } == domain
        }
        if let host = profiles[index].lastURL.flatMap({ URL(string: $0)?.host }),
           registrableDomain(for: host) == domain {
            profiles[index].lastURL = nil
        }
        profiles[index].updatedAt = Date()
        save()
    }

    private func load() {
        do {
            try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            if FileManager.default.fileExists(atPath: fileURL.path) {
                let data = try Data(contentsOf: fileURL)
                let archive = try JSONDecoder().decode(ProfileArchive.self, from: data)
                profiles = archive.profiles
                defaultProfileID = archive.defaultProfileID ?? "default"
            }
            if profiles.isEmpty {
                let now = Date()
                profiles = [BrowserProfile(
                    id: "default",
                    name: "Default",
                    dataStoreID: Self.defaultDataStoreID,
                    lastURL: UserDefaults.standard.string(forKey: "LastURL"),
                    history: [],
                    createdAt: now,
                    updatedAt: now)]
            }
            normalizeProfiles()
            normalizeDefaultProfile()
            for profile in profiles { try ensureDirectory(for: profile) }
            save()
        } catch {
            fputs("chromeless: could not load profiles: \(error.localizedDescription)\n", stderr)
            let now = Date()
            profiles = [BrowserProfile(
                id: "default",
                name: "Default",
                dataStoreID: Self.defaultDataStoreID,
                lastURL: nil,
                history: [],
                createdAt: now,
                updatedAt: now)]
        }
    }

    private func save() {
        do {
            try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(ProfileArchive(
                defaultProfileID: defaultProfile.id,
                profiles: profiles))
            try data.write(to: fileURL, options: .atomic)
            // Each profile records the last page it was on. Owner-only.
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        } catch {
            fputs("chromeless: could not save profiles: \(error.localizedDescription)\n", stderr)
        }
    }

    private func normalizeProfiles() {
        for index in profiles.indices {
            if UUID(uuidString: profiles[index].dataStoreID) == nil ||
                profiles[index].dataStoreID == "00000000-0000-0000-0000-000000000001" {
                profiles[index].dataStoreID = profiles[index].id == "default"
                    ? Self.defaultDataStoreID
                    : UUID().uuidString
                profiles[index].updatedAt = Date()
            }
        }
    }

    private func normalizeDefaultProfile() {
        if !profiles.contains(where: { $0.id == defaultProfileID }) {
            defaultProfileID = profiles.first { $0.id == "default" }?.id ?? profiles[0].id
        }
    }

    private func ensureDirectory(for profile: BrowserProfile) throws {
        try FileManager.default.createDirectory(
            at: directoryURL.appendingPathComponent(profile.id, isDirectory: true),
            withIntermediateDirectories: true)
    }

    private func uniqueID(from name: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
        let folded = name.folding(options: [.diacriticInsensitive, .caseInsensitive], locale: .current)
        let base = folded.lowercased().unicodeScalars.map { allowed.contains($0) ? Character($0) : "-" }
        var id = String(base).split(separator: "-").joined(separator: "-")
        if id.isEmpty { id = "profile" }
        var candidate = id
        var suffix = 2
        while profiles.contains(where: { $0.id == candidate }) {
            candidate = "\(id)-\(suffix)"
            suffix += 1
        }
        return candidate
    }
}

let profileStore = ProfileStore()
if launchOptions.listProfiles {
    for profile in profileStore.profiles {
        let marker = profile.id == profileStore.defaultProfile.id ? "*" : " "
        print("\(marker) \(profile.id)\t\(profile.name)")
    }
    exit(0)
}

// MARK: - Start page

// The page is handed to WebKit as a bare string with no base URL, so it cannot
// pull in a stylesheet, a script, or an image file — everything it needs is
// inline, and the quick-access icons ride along as base64 data URIs.
private let startPageTemplate = #"""
<!doctype html>
<html><head><meta charset="utf-8"><title>chromeless</title>
<style>
  html, body { height: 100%; margin: 0; }
  body { background: #0a0a0e; color: #e8e8ee; font: 15px/1.6 -apple-system, system-ui;
         display: flex; justify-content: center; overflow-y: auto;
         -webkit-user-select: none; cursor: default; }
  /* `margin: auto` centres the same way `align-items: center` does, minus its
     one flaw: when the list is taller than the window, that property overflows
     equally in both directions and the top scrolls out of reach. */
  main { text-align: center; max-width: 680px; padding: 48px; margin: auto;
         animation: in .6s ease-out; }
  @keyframes in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; } }
  h1 { font-size: 46px; font-weight: 650; letter-spacing: -.02em; margin: 0 0 6px; color: #fff; }
  p.tag { color: #85858f; margin: 0 0 46px; font-size: 16px; }
  .keys { display: grid; grid-template-columns: auto auto; gap: 11px 22px;
          justify-content: center; text-align: left; font-size: 13.5px; color: #b9b9c4; }
  .k { text-align: right; }
  kbd { font: 600 12px ui-monospace, "SF Mono", monospace; background: #1b1b22;
        border: 1px solid #2c2c36; border-bottom-width: 2px; border-radius: 6px;
        padding: 2.5px 8px; color: #e8e8ee; white-space: nowrap; }
  footer { margin-top: 44px; color: #55555e; font-size: 12px; line-height: 2; }
  footer b { color: #8a8a97; font-weight: 600; }

  /* Quick access — a footnote under the keys, not a headline above them. */
  .qa { margin: 36px 0 0; }
  .qa-head { display: inline-flex; align-items: center; gap: 7px; padding: 3px 9px;
             border: 0; border-radius: 7px; background: none; cursor: pointer;
             font: 11.5px -apple-system, system-ui; letter-spacing: .04em; color: #55555e; }
  .qa-head:hover { background: #14141a; color: #8a8a97; }
  .chev { font-size: 9px; transform: rotate(90deg); transition: transform .15s; }
  .qa[data-collapsed] .chev { transform: rotate(0deg); }
  .qa[data-collapsed] .grid { display: none; }
  .count { color: #3b3b45; }
  .grid { display: grid; grid-template-columns: repeat(5, 76px); gap: 10px;
          justify-content: center; margin: 13px 0 0; }
  .slot { position: relative; height: 66px; border-radius: 11px; display: flex;
          flex-direction: column; align-items: center; justify-content: center; gap: 6px;
          background: #121218; border: 1px solid #1f1f28; cursor: pointer;
          transition: background .12s, border-color .12s, transform .12s; }
  .slot:hover { background: #181820; border-color: #31313c; transform: translateY(-1px); }
  .slot img, .mono { width: 24px; height: 24px; border-radius: 6px; }
  .mono { display: grid; place-items: center; background: #24242f; color: #cfcfdb;
          font: 600 12px -apple-system, system-ui; text-transform: uppercase; }
  .name { max-width: 62px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
          font-size: 10.5px; color: #9a9aa6; }
  .empty { background: none; border: 1px dashed #21212a; color: #313139; font-size: 16px;
           font-weight: 300; }
  .empty:hover { background: none; border-color: #3a3a47; color: #6c6c80; }
  .pen { position: absolute; top: 3px; right: 3px; width: 17px; height: 17px; border-radius: 6px;
         display: grid; place-items: center; font-size: 9px; color: #8a8a97; background: #24242e;
         opacity: 0; transition: opacity .12s; }
  .slot:hover .pen { opacity: 1; }
  .pen:hover { background: #353542; color: #fff; }

  /* Add / edit sheet */
  .sheet { position: fixed; inset: 0; background: #05050880; backdrop-filter: blur(6px);
           display: none; place-items: center; z-index: 10; }
  .sheet[data-open] { display: grid; }
  .card { width: 340px; text-align: left; background: #16161d; border: 1px solid #2c2c36;
          border-radius: 16px; padding: 22px; box-shadow: 0 24px 60px #00000080; }
  .card h2 { margin: 0 0 16px; font-size: 16px; font-weight: 600; color: #fff; }
  .card label { display: block; font-size: 11.5px; color: #7c7c88; margin: 0 0 4px;
                text-transform: uppercase; letter-spacing: .05em; }
  .card input { width: 100%; box-sizing: border-box; margin: 0 0 14px; padding: 9px 11px;
                background: #0e0e13; border: 1px solid #2c2c36; border-radius: 9px;
                color: #e8e8ee; font: 13.5px -apple-system, system-ui; outline: none;
                -webkit-user-select: text; cursor: text; }
  .card input:focus { border-color: #4a4a5c; }
  .err { min-height: 16px; margin: -8px 0 10px; font-size: 12px; color: #e2686f; }
  .row { display: flex; align-items: center; gap: 8px; }
  .row .spacer { flex: 1; }
  .card button { padding: 7px 14px; border-radius: 9px; border: 1px solid #2c2c36;
                 background: #1e1e26; color: #d8d8e2; font: 13px -apple-system, system-ui;
                 cursor: pointer; }
  .card button:hover { background: #26262f; }
  .card button.save { background: #3a6df0; border-color: #3a6df0; color: #fff; }
  .card button.save:hover { background: #4a7bf5; }
  .card button.drop { border-color: transparent; background: none; color: #98545a; }
  .card button.drop:hover { background: #2a1a1d; color: #e2686f; }
</style></head>
<body><main>
  <h1>chromeless</h1>
  <p class="tag">the browser that isn&rsquo;t there</p>
  <div class="keys">
    <div class="k"><kbd>&#8984; L</kbd></div>       <div>search or enter a url &mdash; it suggests as you type</div>
    <div class="k"><kbd>&#8984; T</kbd></div>       <div>new tab &mdash; the tab bar shows up from the second one</div>
    <div class="k"><kbd>&#8679;&#8984; T</kbd></div><div>reopen a closed tab &mdash; right-click a tab for more</div>
    <div class="k"><kbd>&#8963;&#8677;</kbd></div>  <div>next tab &mdash; <kbd>&#8984;1</kbd>&hellip;<kbd>&#8984;9</kbd> jump straight there</div>
    <div class="k"><kbd>&#8679;&#8984; N</kbd></div><div>private window &mdash; nothing is saved</div>
    <div class="k"><kbd>&#8984; F</kbd></div>       <div>find in page &mdash; <kbd>&#8984;G</kbd> <kbd>&#8679;&#8984;G</kbd> walk the matches</div>
    <div class="k"><kbd>&#8984; drag</kbd></div>    <div>move the window</div>
    <div class="k"><kbd>&#8984; click</kbd></div>   <div>open a link in a background tab &mdash; middle-click too, <kbd>&#8679;&#8984;</kbd> to jump there</div>
    <div class="k"><kbd>&#8963;&#8984; F</kbd></div><div>fullscreen</div>
    <div class="k"><kbd>&#8679;&#8984; S</kbd></div><div>snapshot the page &rarr; desktop</div>
    <div class="k"><kbd>&#8984; P</kbd></div>       <div>pin on top of every window</div>
    <div class="k"><kbd>&#8984; [</kbd> <kbd>&#8984; ]</kbd></div><div>back / forward</div>
    <div class="k"><kbd>&#8679;&#8984; H</kbd></div><div>home &mdash; back to this page</div>
    <div class="k"><kbd>&#8984; =</kbd> <kbd>&#8984; &minus;</kbd> <kbd>&#8984; 0</kbd></div><div>zoom</div>
    <div class="k"><kbd>&#8679;&#8984; C</kbd></div><div>copy current url</div>
    <div class="k"><kbd>&#8679;&#8984; A</kbd></div><div>ai sidebar &mdash; asks about the tab you are on, one chat per tab</div>
    <div class="k"><kbd>&#8679;&#8984; B</kbd></div><div>ads are blocked everywhere &mdash; this lets them through on one site</div>
    <div class="k"><kbd>&#8963;&#8679;&#8984; E</kbd></div><div>point at anything on the page and hide it for good</div>
    <div class="k"><kbd>F12</kbd></div>             <div>web inspector &mdash; <kbd>&#8997;&#8984; I</kbd> does it too</div>
  </div>
  <section class="qa" id="qa">
    <button type="button" class="qa-head" id="qa-head" aria-expanded="true">
      <span class="chev">&#9656;</span> quick access <span class="count" id="qa-count"></span>
    </button>
    <div class="grid" id="qa-grid"></div>
  </section>
  <footer>&#8984;N profile window &nbsp;&middot;&nbsp; &#8679;&#8984;J downloads &nbsp;&middot;&nbsp; &#8984;R reload &nbsp;&middot;&nbsp; &#8984;W close tab &nbsp;&middot;&nbsp; &#8679;&#8984;W close window
  <br>hover a link and its address shows bottom-left &nbsp;&middot;&nbsp; sites that ask for camera, mic, location, or notifications get a real prompt now
  <br>quick access: click a tile to go, &#8984;-click for a background tab, &#9998; to edit &mdash; icons fetch themselves
  <br>site tweaks and site zooms live in <b>&#8984;, Settings</b> &mdash; filter lists, your own rules, and the sites you allowed live in <b>View &rsaquo; Ad Blocking</b>
  <br>ai sidebar: add a provider &mdash; openrouter, chatgpt, gemini, claude, ollama&hellip; &mdash; and its models in <b>View &rsaquo; AI Settings</b>, then <kbd>&#8679;&#8984;A</kbd> asks about the page you are on
  <br>the sidebar header switches model per tab, from the ones you added
  <br><b>View &rsaquo; Show AI Button</b> parks a small &#10022; next to the profile chip for the same thing</footer>
</main>

<div class="sheet" id="sheet">
  <form class="card" id="form">
    <h2 id="heading">Add a shortcut</h2>
    <label for="url">Address</label>
    <input id="url" placeholder="example.com" spellcheck="false" autocapitalize="off">
    <label for="title">Name</label>
    <input id="title" maxlength="60" placeholder="Taken from the site if left blank">
    <p class="err" id="err"></p>
    <div class="row">
      <button type="button" class="drop" id="drop" hidden>Remove</button>
      <span class="spacer"></span>
      <button type="button" id="cancel">Cancel</button>
      <button type="submit" class="save">Save</button>
    </div>
  </form>
</div>
<script>
(function () {
  var state = __QUICK_ACCESS__;
  var section = document.getElementById("qa");
  var head = document.getElementById("qa-head");
  var count = document.getElementById("qa-count");
  var grid = document.getElementById("qa-grid");
  var sheet = document.getElementById("sheet");
  var form = document.getElementById("form");
  var heading = document.getElementById("heading");
  var urlField = document.getElementById("url");
  var titleField = document.getElementById("title");
  var errLine = document.getElementById("err");
  var dropButton = document.getElementById("drop");
  var editingID = null;

  // Every message carries the nonce this page was built with. A different page
  // can reach the same handler — they share the page world — but it cannot read
  // this document, so it cannot produce the nonce, and the app drops it.
  var NONCE = "__QUICK_ACCESS_NONCE__";
  function post(message) {
    message.nonce = NONCE;
    try { window.webkit.messageHandlers.chromelessQuickAccess.postMessage(message); } catch (e) {}
  }

  function initial(link) {
    var source = (link.title || link.url.replace(/^[a-z]+:\/\/(www\.)?/i, "")).trim();
    return source ? source.charAt(0) : "?";
  }

  // Built node by node rather than with innerHTML: a page title is arbitrary
  // text off the internet, and textContent is the one place it cannot bite.
  function tile(link) {
    var slot = document.createElement("div");
    slot.className = "slot";
    slot.title = link.url;

    var art;
    if (link.icon) {
      art = document.createElement("img");
      art.src = link.icon;
      art.alt = "";
    } else {
      art = document.createElement("div");
      art.className = "mono";
      art.textContent = initial(link);
    }
    slot.appendChild(art);

    var name = document.createElement("div");
    name.className = "name";
    name.textContent = link.title || link.url;
    slot.appendChild(name);

    var pen = document.createElement("div");
    pen.className = "pen";
    pen.textContent = "✎";
    pen.addEventListener("click", function (event) {
      event.stopPropagation();
      openSheet(link);
    });
    slot.appendChild(pen);

    slot.addEventListener("click", function (event) {
      post({ action: "open", id: link.id, background: event.metaKey === true, activate: event.shiftKey === true });
    });
    slot.addEventListener("auxclick", function (event) {
      if (event.button !== 1) return;
      event.preventDefault();
      post({ action: "open", id: link.id, background: true, activate: event.shiftKey === true });
    });
    return slot;
  }

  function blank() {
    var slot = document.createElement("div");
    slot.className = "slot empty";
    slot.textContent = "+";
    slot.addEventListener("click", function () { openSheet(null); });
    return slot;
  }

  function render(next) {
    if (next) state = next;
    grid.textContent = "";
    var links = state.links || [];
    for (var i = 0; i < links.length; i++) grid.appendChild(tile(links[i]));
    // One trailing "+" only — a wall of empty boxes is louder than the page
    // it is sitting on.
    if (links.length < state.slots) grid.appendChild(blank());
    // The count is what the section has left to say once it is folded shut.
    count.textContent = links.length ? String(links.length) : "";
    collapse(state.collapsed === true);
  }

  function collapse(shut) {
    if (shut) section.setAttribute("data-collapsed", "");
    else section.removeAttribute("data-collapsed");
    head.setAttribute("aria-expanded", shut ? "false" : "true");
  }

  head.addEventListener("click", function () {
    var shut = !section.hasAttribute("data-collapsed");
    collapse(shut);
    state.collapsed = shut;
    post({ action: "collapse", value: shut });
  });

  function openSheet(link) {
    editingID = link ? link.id : null;
    heading.textContent = link ? "Edit shortcut" : "Add a shortcut";
    urlField.value = link ? link.url : "";
    titleField.value = link ? link.title : "";
    errLine.textContent = "";
    dropButton.hidden = !link;
    sheet.setAttribute("data-open", "");
    // The ⌘L HUD owns the keyboard while the start page is up; ask for it back,
    // then take focus once its dismissal animation has finished.
    post({ action: "editing", value: true });
    urlField.focus();
    setTimeout(function () { urlField.focus(); urlField.select(); }, 240);
  }

  function closeSheet() {
    sheet.removeAttribute("data-open");
    editingID = null;
    post({ action: "editing", value: false });
  }

  // The sheet is left open here on purpose — the app has the last word on
  // whether the address is usable, and it answers with accept() or reject().
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var address = urlField.value.trim();
    if (!address) { errLine.textContent = "An address is required."; urlField.focus(); return; }
    errLine.textContent = "";
    post({ action: "save", id: editingID, url: address, title: titleField.value.trim() });
  });
  document.getElementById("cancel").addEventListener("click", closeSheet);
  dropButton.addEventListener("click", function () {
    if (editingID) post({ action: "remove", id: editingID });
    closeSheet();
  });
  sheet.addEventListener("click", function (event) { if (event.target === sheet) closeSheet(); });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && sheet.hasAttribute("data-open")) {
      event.preventDefault();
      closeSheet();
    }
  });

  window.chromelessQuickAccess = {
    render: render,
    // The app skips a refresh while the sheet is up, so an icon landing
    // mid-edit cannot wipe out what is being typed.
    isEditing: function () { return sheet.hasAttribute("data-open"); },
    // The shortcut is saved: shut the sheet, then ask for the repaint that was
    // skipped for exactly that reason a moment ago.
    accept: function () { closeSheet(); post({ action: "ready" }); },
    reject: function (text) { errLine.textContent = text; urlField.focus(); }
  };
  render(null);
})();
</script>
</body></html>
"""#

/// The start page, stamped with the nonce that its bridge has to quote back.
func startPageHTML(nonce: String) -> String {
    startPageTemplate
        .replacingOccurrences(of: "__QUICK_ACCESS__", with: quickAccessStore.payloadJSON)
        .replacingOccurrences(of: "__QUICK_ACCESS_NONCE__", with: nonce)
}

// MARK: - Views

final class BrowserWebView: WKWebView {
    // Set by the owning window controller. Fed by `AuxClickRouter` for a
    // middle-click, and by `openLinkInNewTab` for a ⌘-click.
    var onOpenLinkInNewTab: ((URL, _ background: Bool) -> Void)?
    // Fed by `AdBlockPickerRouter` once the element picker has a selector, or
    // nil when the element could not be named safely.
    var onPickedSelector: ((String?) -> Void)?
    // Fed by `QuickAccessRouter` when the start page opens, saves, or drops a
    // shortcut. Bare Esc deliberately does nothing here: it used to jump back
    // to the start page, which threw away whatever was typed into the page.
    var onQuickAccess: ((BrowserWebView, [String: Any]) -> Void)?
    // Fed by `LinkHoverRouter` as the pointer moves over anchors: the link's
    // href, or nil when the pointer is no longer on one.
    var onLinkHover: ((URL?) -> Void)?
    // Fed by `TranslateRouter` when ⇧ is pressed with an active selection, and
    // again when the page wants the bubble gone (scroll, click, collapse).
    var onTranslate: (([String: Any]) -> Void)?

    // ⌘ is overloaded: ⌘-drag moves the window, ⌘-click opens the link under
    // the cursor in a new tab. Which one it is is not knowable at mouse-down,
    // so the press is held until the pointer either moves or comes back up.
    // Mouse buttons 4/5 go back/forward.
    override func mouseDown(with event: NSEvent) {
        guard event.modifierFlags.contains(.command) else {
            super.mouseDown(with: event)
            return
        }
        let start = event.locationInWindow
        var dragged = false
        window?.trackEvents(matching: [.leftMouseDragged, .leftMouseUp],
                            timeout: .infinity, mode: .eventTracking) { moved, stop in
            guard let moved else { stop.pointee = true; return }
            if moved.type == .leftMouseDragged {
                let p = moved.locationInWindow
                // Same 4pt slop the tab drag uses, so a shaky hand still clicks.
                guard hypot(p.x - start.x, p.y - start.y) >= 4 else { return }
                dragged = true
            }
            stop.pointee = true
        }
        if dragged {
            window?.performDrag(with: event)
        } else {
            openLinkInNewTab(at: convert(start, from: nil),
                             background: !event.modifierFlags.contains(.shift))
        }
    }

    // The page never sees this click — it was swallowed above — so the link has
    // to be found by asking the document what sits at that point. Only the main
    // frame is searched; a ⌘-click inside an iframe finds nothing. Middle-click
    // has no such limit, since it is handled by a script injected into every
    // frame.
    private func openLinkInNewTab(at point: NSPoint, background: Bool) {
        // elementFromPoint wants CSS pixels down from the top-left of the
        // viewport. WKWebView is flipped, so the converted point already counts
        // downwards; only the zoom has to be divided out.
        let scale = pageZoom * magnification
        guard scale > 0, isFlipped else { return }
        let x = point.x / scale
        let y = point.y / scale
        evaluateJavaScript("""
        (function () {
          var n = document.elementFromPoint(\(x), \(y));
          while (n && n.nodeType === 1) {
            if (n.tagName === "A" && n.href) return n.href;
            n = n.parentNode;
          }
          return null;
        })();
        """) { [weak self] result, _ in
            guard let href = result as? String, let url = URL(string: href) else { return }
            self?.onOpenLinkInNewTab?(url, background)
        }
    }
    override func otherMouseUp(with event: NSEvent) {
        if event.buttonNumber == 3, canGoBack { goBack(); return }
        if event.buttonNumber == 4, canGoForward { goForward(); return }
        super.otherMouseUp(with: event)
    }
}

final class LayoutReportingView: NSView {
    var onLayout: (() -> Void)?
    override func layout() {
        super.layout()
        onLayout?()
    }
}

// The profile chip. It used to pass clicks through to the page; now it is a
// button that opens the profile picker, so it takes its own clicks.
final class ProfileChipView: NSVisualEffectView {
    var onClick: (() -> Void)?
    private var trackingAreaRef: NSTrackingArea?

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let t = trackingAreaRef { removeTrackingArea(t) }
        let t = NSTrackingArea(rect: bounds,
                               options: [.mouseEnteredAndExited, .activeInKeyWindow],
                               owner: self, userInfo: nil)
        addTrackingArea(t)
        trackingAreaRef = t
    }

    override func mouseEntered(with event: NSEvent) { animator().alphaValue = 1.0 }
    override func mouseExited(with event: NSEvent) { animator().alphaValue = 0.82 }
    override func mouseDown(with event: NSEvent) { onClick?() }
}

extension Notification.Name {
    static let profileChipPreferenceDidChange = Notification.Name("chromeless.profileChipDidChange")
}

/// Whether the profile chip shows — docked in the tab bar or floating in the
/// corner. On by default, since it is the main way into the profile picker,
/// and shared by every window, which is why it lives in defaults rather than
/// on a controller. Profiles stay reachable through ⌘N either way.
enum ProfileChipPreference {
    private static let key = "ChromelessShowProfileChip"

    static var isOn: Bool { UserDefaults.standard.object(forKey: key) as? Bool ?? true }

    static func set(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: key)
        NotificationCenter.default.post(name: .profileChipPreferenceDidChange, object: nil)
    }
}

/// The autosaved frame remembers which display the window was on, so a window
/// quit on a secondary monitor reopens there — fine until the monitor is gone
/// or unwelcome. On by default: new windows recenter on the primary display
/// instead. `NSScreen.screens.first` is the primary; `NSScreen.main` just
/// means "holds the key window".
enum PrimaryScreenPreference {
    private static let key = "ChromelessOpenOnPrimaryScreen"

    static var isOn: Bool { UserDefaults.standard.object(forKey: key) as? Bool ?? true }

    static func set(_ on: Bool) { UserDefaults.standard.set(on, forKey: key) }

    /// Recenters `window` on the primary display, keeping its size, when it
    /// ended up somewhere else. No-op when the setting is off, there is one
    /// screen, or the window is already on the primary.
    static func constrain(_ window: NSWindow) {
        guard isOn, let primary = NSScreen.screens.first,
              window.screen != primary else { return }
        let visible = primary.visibleFrame
        var frame = window.frame
        frame.origin = NSPoint(x: visible.midX - frame.width / 2,
                               y: visible.midY - frame.height / 2)
        window.setFrame(frame, display: false)
    }
}

// MARK: - Tabs

// WebKit does not treat a middle-click on a link as a request for a new window
// — it never calls `createWebViewWith` and just navigates the current frame,
// which is worse than doing nothing. So the page has to be taught: cancel the
// default action and hand the href back for a background tab.
private let auxClickScript = """
(function () {
  function anchor(node) {
    while (node && node.nodeType === 1) {
      if (node.tagName === "A" && node.href) return node;
      node = node.parentNode;
    }
    return null;
  }
  function swallow(e) {
    if (e.button === 1 && anchor(e.target)) e.preventDefault();
  }
  // The navigation is suppressed on the way down and the href reported on the
  // way up, so the gesture only counts once the button is actually released.
  document.addEventListener("mousedown", swallow, true);
  document.addEventListener("auxclick", function (e) {
    if (e.button !== 1) return;
    var a = anchor(e.target);
    if (!a) return;
    e.preventDefault();
    e.stopPropagation();
    window.webkit.messageHandlers.chromelessAuxClick.postMessage(a.href);
  }, true);
})();
"""

// With no status bar there is no way to see where a link goes before clicking
// it. The page reports the anchor under the pointer — or "" once there is none
// — and the app draws it in a corner bubble. One post per change, so dragging
// the pointer across the page does not stream messages.
private let linkHoverScript = """
(function () {
  var last = null;
  function hrefFor(e) {
    var n = e.target;
    while (n && n.nodeType === 1) {
      if (n.tagName === "A" && n.href) return n.href;
      n = n.parentNode;
    }
    return null;
  }
  document.addEventListener("mouseover", function (e) {
    var h = hrefFor(e);
    if (h === last) return;
    last = h;
    window.webkit.messageHandlers.chromelessLinkHover.postMessage(h || "");
  }, true);
  document.addEventListener("mouseleave", function () {
    if (last === null) return;
    last = null;
    window.webkit.messageHandlers.chromelessLinkHover.postMessage("");
  }, true);
})();
"""

// The ⌘F engine. Kept on the world's own `window` so it survives between calls
// on the same page; a navigation drops it with the rest of the page's globals.
// Hits are text-node ranges — matches that span elements are not found, and
// inputs/textareas are skipped on purpose. Selection is the highlight: moving
// to a hit selects it and scrolls it into view.
private let findEngineScript = """
window.__clf = window.__clf || (function () {
  var hits = [], idx = -1;
  function searchable(n) {
    for (var e = n.parentElement; e; e = e.parentElement) {
      var t = e.tagName;
      if (t === "SCRIPT" || t === "STYLE" || t === "NOSCRIPT" || t === "TEXTAREA") return false;
    }
    return true;
  }
  function paint() {
    var sel = window.getSelection();
    sel.removeAllRanges();
    if (idx < 0 || idx >= hits.length) return;
    try {
      var h = hits[idx], r = document.createRange();
      r.setStart(h[0], h[1]); r.setEnd(h[0], h[2]);
      sel.addRange(r);
      var rect = r.getBoundingClientRect();
      if (rect.bottom < 0 || rect.top > window.innerHeight ||
          rect.right < 0 || rect.left > window.innerWidth)
        r.startContainer.parentElement.scrollIntoView({ block: "center", inline: "nearest" });
    } catch (e) {}
  }
  return {
    scan: function (term) {
      hits = []; idx = -1;
      if (!term) { paint(); return 0; }
      var needle = term.toLowerCase();
      var w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
        acceptNode: function (n) {
          return n.nodeValue && n.nodeValue.toLowerCase().indexOf(needle) !== -1 && searchable(n)
            ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
        }
      });
      var node;
      while ((node = w.nextNode())) {
        var s = node.nodeValue.toLowerCase(), i = 0;
        while ((i = s.indexOf(needle, i)) !== -1) {
          hits.push([node, i, i + needle.length]);
          i += needle.length;
        }
      }
      return hits.length;
    },
    // Jump to the i-th hit, wrapping around. The caller rescans before every
    // jump, because the DOM may have moved since the last one.
    at: function (i) {
      if (!hits.length) { idx = -1; paint(); return -1; }
      idx = ((i % hits.length) + hits.length) % hits.length;
      paint();
      return idx;
    },
    clear: function () { hits = []; idx = -1; paint(); }
  };
})();
"""


// A recent desktop Chrome on macOS — generic enough to pass a UA check
// without promising a WebKit feature the site might then call.
private let chromeUserAgentString =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36"

/// Where the scripts this app injects live, and where their message handlers are
/// registered. A page cannot see `window.webkit.messageHandlers` entries from
/// another content world, so it cannot post to them — which matters because these
/// handlers open tabs and write filter rules, and any site could reach them while
/// they sat in the page's own world.
let chromelessWorld = WKContentWorld.world(name: "chromeless")

// One shared handler for every web view: it routes by the message's own web
// view, so it never needs to know which window or profile the page belongs to.
final class AuxClickRouter: NSObject, WKScriptMessageHandler {
    static let shared = AuxClickRouter()
    static let messageName = "chromelessAuxClick"

    func userContentController(_ controller: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard let webView = message.webView as? BrowserWebView,
              let href = message.body as? String,
              let url = URL(string: href),
              // Only a web link is a link. `file:` and `data:` reach this far only
              // if something is wrong, and a tab is not the place to find out.
              ["http", "https"].contains(url.scheme?.lowercased() ?? "") else { return }
        webView.onOpenLinkInNewTab?(url, true)
    }
}

// Routes the link-hover script's messages to the web view they came from.
final class LinkHoverRouter: NSObject, WKScriptMessageHandler {
    static let shared = LinkHoverRouter()
    static let messageName = "chromelessLinkHover"

    func userContentController(_ controller: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard let webView = message.webView as? BrowserWebView,
              let href = message.body as? String else { return }
        webView.onLinkHover?(href.isEmpty ? nil : URL(string: href))
    }
}

func makeWebConfiguration(for profile: BrowserProfile, isPrivate: Bool = false) -> WKWebViewConfiguration {
    let conf = WKWebViewConfiguration()
    conf.websiteDataStore = isPrivate
        ? .nonPersistent()
        : profileStore.websiteDataStore(for: profile)
    conf.preferences.isElementFullscreenEnabled = true
    // `isInspectable` only unlocks the context menu's Inspect Element. Driving
    // the inspector from code needs WebKit's developer extras as well — the bit
    // Safari's Develop menu flips — or `_inspector`'s `show` returns having done
    // nothing. Guarded, so a rename downgrades to no inspector, not a crash.
    if conf.preferences.responds(to: NSSelectorFromString("_setDeveloperExtrasEnabled:")) {
        conf.preferences.setValue(true, forKey: "developerExtrasEnabled")
    }
    conf.mediaTypesRequiringUserActionForPlayback = []
    conf.allowsAirPlayForMediaPlayback = true
    conf.applicationNameForUserAgent = "Version/26.0 Safari/605.1.15"
    // SSO sign-ins often reach window.open only after an async hop — fetch the
    // IdP URL, then open it — by which point WebKit no longer counts the click
    // as a gesture and silently drops the popup: createWebViewWith is never
    // called, window.open returns null, and the Sign in button looks dead.
    conf.preferences.javaScriptCanOpenWindowsAutomatically = true
    // These two are ours to call and no page's: registered in our own world, they
    // are invisible to page scripts.
    conf.userContentController.add(AuxClickRouter.shared, contentWorld: chromelessWorld,
                                   name: AuxClickRouter.messageName)
    conf.userContentController.add(AdBlockPickerRouter.shared, contentWorld: chromelessWorld,
                                   name: AdBlockPickerRouter.messageName)
    conf.userContentController.add(LinkHoverRouter.shared, contentWorld: chromelessWorld,
                                   name: LinkHoverRouter.messageName)
    conf.userContentController.add(TranslateRouter.shared, contentWorld: chromelessWorld,
                                   name: TranslateRouter.messageName)
    // The start page is a page, so its bridge has to be in the page world. What
    // keeps another site out is the nonce it carries — see `handleQuickAccess`.
    conf.userContentController.add(QuickAccessRouter.shared, name: QuickAccessRouter.messageName)
    conf.userContentController.addUserScript(WKUserScript(
        source: auxClickScript, injectionTime: .atDocumentStart, forMainFrameOnly: false,
        in: chromelessWorld))
    conf.userContentController.addUserScript(WKUserScript(
        source: linkHoverScript, injectionTime: .atDocumentStart, forMainFrameOnly: false,
        in: chromelessWorld))
    // Main frame only: the popover anchors to a rect the script reports, and
    // an iframe's coordinates can't be re-expressed in the window's space when
    // it is cross-origin — a wrong anchor is worse than no trigger.
    conf.userContentController.addUserScript(WKUserScript(
        source: translateTriggerScript, injectionTime: .atDocumentStart,
        forMainFrameOnly: true, in: chromelessWorld))
    if !hasPasskeyEntitlement {
        let hideWebAuthn = WKUserScript(
            source: """
            (function () {
              try {
                delete window.PublicKeyCredential;
                delete window.AuthenticatorResponse;
                delete window.AuthenticatorAttestationResponse;
                delete window.AuthenticatorAssertionResponse;
              } catch (e) {}
            })();
            """,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: false)
        conf.userContentController.addUserScript(hideWebAuthn)
    }
    return conf
}

// One tab: a web view plus the page state that used to live on the window
// controller back when a window held exactly one page.
final class Tab {
    let webView: BrowserWebView
    var onStartPage = false
    var lastProgress: CGFloat = 0
    var observations: [NSKeyValueObservation] = []
    // The AI conversation about this tab's page, and whether this tab is showing
    // the sidebar. Both are per tab on purpose: the sidebar is one view per
    // window, but it only exists for the tab that asked for it — switch to a tab
    // that never opened it and the window is just the page again.
    let aiSession = AIChatSession()
    var aiSidebarOpen = false
    /// What the start page in this tab must quote back for its bridge to be
    /// listened to. Nil for a tab showing a website, which is the point.
    var startPageNonce: String?
    /// The tab bar's icon and the host it belongs to. The host is tracked so
    /// same-site navigations do not refetch, and a different site clears it.
    var favicon: NSImage?
    var faviconHost: String?
    /// A tab the control socket opened. Remote commands only ever reach agent
    /// tabs — the user's own tabs refuse them — so this flag is the whole
    /// permission boundary. Marked orange: an "AI" pill in the tab bar, a
    /// border on the page, and a rail the probe draws at the top of it.
    var isAgent = false
    /// The agent's debugging feed — console, page errors, fetch/XHR — filled
    /// by the probe script only agent-tab configurations carry.
    let agentLog = AgentLog()

    init(webView: BrowserWebView) { self.webView = webView }

    var displayTitle: String {
        if onStartPage { return "chromeless" }
        let t = webView.title ?? ""
        if !t.isEmpty { return t }
        return webView.url?.host ?? "New Tab"
    }

    func teardown() {
        observations.removeAll()
        aiSession.cancel()
        webView.stopLoading()
        webView.navigationDelegate = nil
        webView.uiDelegate = nil
        webView.removeFromSuperview()
    }
}

final class TabItemView: NSView {
    // The callbacks hand back the view rather than an index, so TabBarView can
    // read `index` at call time. Baking the index into the closure only worked
    // while every item was thrown away and rebuilt after each change.
    var onSelect: ((TabItemView) -> Void)?
    var onClose: ((TabItemView) -> Void)?
    var onDragBegin: ((TabItemView, NSEvent) -> Void)?
    var onMenu: ((TabItemView) -> NSMenu?)?

    var index = 0

    private let iconView = NSImageView()
    private let label = NSTextField(labelWithString: "")
    private let closeButton = NSButton()
    private let agentBadge = NSTextField(labelWithString: "AI")
    private var hovering = false
    private var trackingAreaRef: NSTrackingArea?
    private var middleDownInside = false

    var isActive = false { didSet { applyStyle(); needsLayout = true } }
    // An agent tab wears its ownership on the item: the whole body goes
    // orange and a small "AI" pill sits where the icon would otherwise start.
    var isAgent = false { didSet { applyStyle(); needsLayout = true } }
    var title = "" {
        didSet {
            label.stringValue = title
            toolTip = title
            needsLayout = true
        }
    }
    var icon: NSImage? {
        didSet {
            iconView.image = icon
            iconView.isHidden = icon == nil
            needsLayout = true
        }
    }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        wantsLayer = true
        layer?.cornerRadius = 7
        layer?.cornerCurve = .continuous

        iconView.imageScaling = .scaleProportionallyUpOrDown
        iconView.isHidden = true
        iconView.wantsLayer = true
        iconView.layer?.cornerRadius = 3
        iconView.layer?.masksToBounds = true
        addSubview(iconView)

        label.font = .systemFont(ofSize: 12, weight: .medium)
        label.lineBreakMode = .byTruncatingTail
        label.cell?.truncatesLastVisibleLine = true
        addSubview(label)

        closeButton.isBordered = false
        closeButton.bezelStyle = .inline
        closeButton.title = "✕"
        closeButton.font = .systemFont(ofSize: 9, weight: .bold)
        closeButton.contentTintColor = .secondaryLabelColor
        closeButton.target = self
        closeButton.action = #selector(closeClicked)
        closeButton.isHidden = true
        addSubview(closeButton)

        agentBadge.font = .systemFont(ofSize: 8.5, weight: .bold)
        agentBadge.textColor = .white
        agentBadge.backgroundColor = .systemOrange
        agentBadge.drawsBackground = true
        agentBadge.isBezeled = false
        agentBadge.alignment = .center
        agentBadge.wantsLayer = true
        agentBadge.layer?.cornerRadius = 3
        agentBadge.isHidden = true
        addSubview(agentBadge)

        applyStyle()
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    @objc private func closeClicked() { onClose?(self) }

    private func applyStyle() {
        if isAgent {
            layer?.backgroundColor = NSColor.systemOrange.withAlphaComponent(
                isActive ? 0.35 : (hovering ? 0.22 : 0.14)).cgColor
        } else {
            layer?.backgroundColor = isActive
                ? NSColor.white.withAlphaComponent(0.14).cgColor
                : (hovering ? NSColor.white.withAlphaComponent(0.07).cgColor : NSColor.clear.cgColor)
        }
        label.textColor = isActive ? .labelColor : .secondaryLabelColor
        agentBadge.isHidden = !isAgent
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let t = trackingAreaRef { removeTrackingArea(t) }
        let t = NSTrackingArea(rect: bounds,
                               options: [.mouseEnteredAndExited, .activeInKeyWindow],
                               owner: self, userInfo: nil)
        addTrackingArea(t)
        trackingAreaRef = t
    }

    override func mouseEntered(with event: NSEvent) {
        hovering = true
        closeButton.isHidden = false
        applyStyle()
        needsLayout = true
    }

    override func mouseExited(with event: NSEvent) {
        hovering = false
        closeButton.isHidden = true
        applyStyle()
        needsLayout = true
    }

    // Claim the press before it reaches the title label, so the middle-click
    // bounds check below is against the tab's own geometry. The close button is
    // the one exception, since it needs its own tracking.
    override func hitTest(_ point: NSPoint) -> NSView? {
        let local = convert(point, from: superview)
        guard bounds.contains(local) else { return nil }
        if !closeButton.isHidden, closeButton.frame.contains(local) { return closeButton }
        return self
    }

    // Selecting on press is what every browser does, so it happens before the
    // drag is even considered; the bar decides afterwards whether the gesture
    // turns into a reorder. A double press is the titlebar double-click — the
    // whole strip reads as the titlebar, so tabs zoom the window too.
    override func mouseDown(with event: NSEvent) {
        onSelect?(self)
        if event.clickCount == 2 {
            performTitlebarDoubleClick(on: window)
            return
        }
        onDragBegin?(self, event)
    }

    // Right-click selects too, then asks the bar for the context menu — a menu
    // that acts on a tab it is not attached to reads like a bug.
    override func menu(for event: NSEvent) -> NSMenu? {
        onSelect?(self)
        return onMenu?(self)
    }

    // Middle-click closes, but only on release and only if the cursor never
    // left the tab — sliding off before letting go cancels, the way it does for
    // every other destructive click on macOS.
    override func otherMouseDown(with event: NSEvent) {
        guard event.buttonNumber == 2 else { return super.otherMouseDown(with: event) }
        middleDownInside = true
    }

    override func otherMouseUp(with event: NSEvent) {
        guard event.buttonNumber == 2, middleDownInside else {
            return super.otherMouseUp(with: event)
        }
        middleDownInside = false
        if bounds.contains(convert(event.locationInWindow, from: nil)) { onClose?(self) }
    }

    override func layout() {
        super.layout()
        let b = bounds
        closeButton.frame = NSRect(x: b.width - 20, y: (b.height - 16) / 2, width: 16, height: 16)
        iconView.frame = NSRect(x: 8, y: (b.height - 14) / 2, width: 14, height: 14)
        agentBadge.frame = NSRect(x: iconView.isHidden ? 8 : 27,
                                  y: (b.height - 13) / 2, width: 17, height: 13)
        let labelX: CGFloat = isAgent ? agentBadge.frame.maxX + 5 : (iconView.isHidden ? 9 : 27)
        let labelRight: CGFloat = closeButton.isHidden ? 8 : 22
        label.frame = NSRect(x: labelX, y: (b.height - 15) / 2,
                             width: max(0, b.width - labelX - labelRight), height: 15)
    }
}

// Our fake titlebar strips are plain views once `isMovable` is off, so the
// system's titlebar double-click does not reach them. Mirror the global
// "double-click a window's title bar" preference: Zoom by default, Minimize
// or nothing when the user set it so.
func performTitlebarDoubleClick(on window: NSWindow?) {
    guard let window else { return }
    switch UserDefaults.standard.string(forKey: "AppleActionOnDoubleClick") {
    case "Minimize": window.miniaturize(nil)
    case "None": break
    default: window.zoom(nil)
    }
}

final class TabBarView: NSVisualEffectView {
    static let height: CGFloat = 34
    // The traffic lights are hidden but appear on hover over the top-left
    // corner. Without this inset they would draw on top of the first tab.
    static let trafficLightInset: CGFloat = 78

    var onSelect: ((Int) -> Void)?
    var onClose: ((Int) -> Void)?
    var onNewTab: (() -> Void)?
    var onReorder: ((Int, Int) -> Void)?
    var onContextMenu: ((Int) -> NSMenu?)?

    private var items: [TabItemView] = []
    private let addButton = NSButton()
    private var chipWidth: CGFloat = 0
    // Set only while a drag is live. `layout()` leaves this item alone; without
    // that, any layout pass mid-gesture snaps it back to its slot.
    private var dragItem: TabItemView?
    private var dragToken = 0

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        material = .hudWindow
        blendingMode = .withinWindow
        state = .active
        wantsLayer = true

        addButton.isBordered = false
        addButton.bezelStyle = .inline
        addButton.title = "+"
        addButton.font = .systemFont(ofSize: 16, weight: .medium)
        addButton.contentTintColor = .secondaryLabelColor
        addButton.toolTip = "New Tab (⌘T)"
        addButton.target = self
        addButton.action = #selector(addClicked)
        addSubview(addButton)
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    @objc private func addClicked() { onNewTab?() }

    // With the tab bar up, the window is `isMovable = false` (see `refreshTabs`),
    // so the empty part of the strip has to move the window by hand — and handle
    // the titlebar double-click too, since the system no longer sees it. Presses
    // on a tab never reach here — items are subviews and take their own events.
    override func mouseDown(with event: NSEvent) {
        if event.clickCount == 2 {
            performTitlebarDoubleClick(on: window)
            return
        }
        window?.performDrag(with: event)
    }

    // Middle-clicking the strip itself opens a tab. Items are subviews, so a
    // middle-click that lands on a tab is hit-tested there and never gets here.
    override func otherMouseUp(with event: NSEvent) {
        guard event.buttonNumber == 2 else { return super.otherMouseUp(with: event) }
        onNewTab?()
    }

    // Items are reused across rebuilds rather than recreated. A drag holds on
    // to the view it is moving, and selecting a tab rebuilds the bar, so tearing
    // the views down would kill the gesture on its first frame.
    func rebuild(titles: [String], activeIndex: Int, agents: [Bool] = []) {
        while items.count > titles.count {
            let gone = items.removeLast()
            if gone === dragItem { dragItem = nil }
            gone.removeFromSuperview()
        }
        while items.count < titles.count {
            let item = TabItemView(frame: .zero)
            item.onSelect = { [weak self] in self?.onSelect?($0.index) }
            item.onClose = { [weak self] in self?.onClose?($0.index) }
            item.onDragBegin = { [weak self] in self?.beginDrag($0, with: $1) }
            item.onMenu = { [weak self] in self?.onContextMenu?($0.index) }
            addSubview(item, positioned: .below, relativeTo: addButton)
            items.append(item)
        }
        for (index, item) in items.enumerated() {
            item.index = index
            item.title = titles[index]
            item.isActive = index == activeIndex
            item.isAgent = index < agents.count && agents[index]
        }
        needsLayout = true
    }

    func update(titleAt index: Int?, to title: String) {
        guard let index, items.indices.contains(index) else { return }
        items[index].title = title
    }

    func update(iconAt index: Int?, to icon: NSImage?) {
        guard let index, items.indices.contains(index) else { return }
        items[index].icon = icon
    }

    func setChipWidth(_ width: CGFloat) {
        guard width != chipWidth else { return }
        chipWidth = width
        needsLayout = true
    }

    // Slot geometry, shared by `layout()` and the drag loop so a dragged tab
    // lands on exactly the position layout would have given it.
    private var tabPitch: CGFloat {
        let addW: CGFloat = 26
        let available = max(0, bounds.width - Self.trafficLightInset - (chipWidth + 18) - addW - 8)
        return min(190, max(90, available / CGFloat(max(1, items.count))))
    }

    private func slotFrame(_ index: Int) -> NSRect {
        NSRect(x: Self.trafficLightInset + tabPitch * CGFloat(index), y: 3,
               width: max(40, tabPitch - 3), height: bounds.height - 6)
    }

    override func layout() {
        super.layout()
        for (index, item) in items.enumerated() where item !== dragItem {
            item.frame = slotFrame(index)
        }
        let addW: CGFloat = 26
        let rightReserve = chipWidth + 18
        let x = Self.trafficLightInset + tabPitch * CGFloat(items.count)
        addButton.frame = NSRect(
            x: min(x + 2, max(Self.trafficLightInset, bounds.width - rightReserve - addW)),
            y: (bounds.height - 22) / 2, width: addW, height: 22)
    }

    // MARK: Drag to reorder

    private func settle(_ index: Int, of item: TabItemView) {
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = 0.12
            item.animator().frame = slotFrame(index)
        }
    }

    private func beginDrag(_ item: TabItemView, with event: NSEvent) {
        guard let window, items.count > 1 else { return }
        dragToken += 1
        let token = dragToken
        let start = convert(event.locationInWindow, from: nil)
        let grabOffset = start.x - item.frame.origin.x
        let startIndex = items.firstIndex(of: item) ?? item.index
        let originalOrder = items
        var currentIndex = startIndex
        var live = false
        var cancelled = false

        window.trackEvents(matching: [.leftMouseDragged, .leftMouseUp, .keyDown],
                           timeout: .infinity, mode: .eventTracking) { event, stop in
            guard let event else { stop.pointee = true; return }
            switch event.type {
            case .keyDown:
                guard event.keyCode == 53 else { return } // Esc
                cancelled = true
                self.items = originalOrder
                stop.pointee = true

            case .leftMouseDragged:
                let p = self.convert(event.locationInWindow, from: nil)
                if !live {
                    // Below this the gesture is still a click, not a drag.
                    guard abs(p.x - start.x) >= 4 else { return }
                    live = true
                    self.dragItem = item
                    self.addSubview(item, positioned: .below, relativeTo: self.addButton)
                }
                let pitch = self.tabPitch
                let maxX = Self.trafficLightInset + pitch * CGFloat(self.items.count - 1)
                item.frame.origin.x = min(max(p.x - grabOffset, Self.trafficLightInset), maxX)

                let raw = Int(((item.frame.origin.x - Self.trafficLightInset) / pitch).rounded())
                let target = min(max(raw, 0), self.items.count - 1)
                guard target != currentIndex else { return }
                self.items.remove(at: currentIndex)
                self.items.insert(item, at: target)
                currentIndex = target
                for (index, other) in self.items.enumerated() where other !== item {
                    self.settle(index, of: other)
                }

            case .leftMouseUp:
                stop.pointee = true

            default:
                break
            }
        }

        guard live else { return }
        let finalIndex = cancelled ? startIndex : currentIndex
        // `dragItem` stays set until the settle animation finishes, so the
        // relayout that `onReorder` triggers does not yank the tab into place
        // and cut the animation short.
        settle(finalIndex, of: item)
        // Keyed on the drag, not the view: starting a second drag on the same tab
        // inside the settle window would otherwise clear `dragItem` underneath it.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.12) { [weak self] in
            guard let self, self.dragToken == token else { return }
            self.dragItem = nil
            self.needsLayout = true
        }
        if cancelled {
            for (index, other) in items.enumerated() where other !== item {
                settle(index, of: other)
            }
        } else if finalIndex != startIndex {
            onReorder?(startIndex, finalIndex)
        }
    }
}

// MARK: - Browser window

final class BrowserWindowController: NSWindowController, NSWindowDelegate,
    WKNavigationDelegate, WKUIDelegate, NSTextFieldDelegate, NSMenuItemValidation,
    NSTableViewDataSource, NSTableViewDelegate {

    private(set) var tabs: [Tab] = []
    private(set) var activeIndex = 0
    private let profile: BrowserProfile
    /// A private window runs on a non-persistent data store and records nothing:
    /// no history, no last page. Downloads still land on disk — they are files
    /// the user asked for, not browsing data.
    let isPrivate: Bool
    private let tabBar = TabBarView()
    private let progressBar = NSView()
    private let hud = NSVisualEffectView()
    private let hudField = NSTextField()
    private let suggestPanel = NSVisualEffectView()
    private let suggestTable = NSTableView()
    private var suggestions: [(title: String?, url: String, icon: NSImage?)] = []
    private var suggestIconCache: [String: NSImage] = [:]
    private let findBar = NSVisualEffectView()
    private let findField = NSTextField()
    private let findCountLabel = NSTextField(labelWithString: "")
    private var findButtons: [NSButton] = []
    private var findIndex = -1
    private var findDebounce: DispatchWorkItem?
    private let linkHoverView = NSVisualEffectView()
    private let linkHoverLabel = NSTextField(labelWithString: "")
    private let translatePopover = TranslatePopover()
    private let systemTranslate = SystemTranslationOverlay()
    private let translator = Translator()
    private var closedTabs: [URL] = []
    private var faviconCache: [String: NSImage] = [:]
    private var keepAwakeActivity: NSObjectProtocol?
    private var permissionChoices: [String: Bool] = [:]
    private var permissionQueue: [() -> Void] = []
    private var permissionPromptUp = false
    private let toastView = NSVisualEffectView()
    private let toastLabel = NSTextField(labelWithString: "")
    private let profileBadge = ProfileChipView()
    private let profileLabel = NSTextField(labelWithString: "")
    private var mouseMonitor: Any?
    private var keyMonitor: Any?
    private var snapJob: SnapJob?
    private var toastHide: DispatchWorkItem?
    private let downloadsPanel = DownloadsPanelView()
    private var downloadsPanelPinned = false
    private var downloadsHide: DispatchWorkItem?
    private var downloadsObservers: [NSObjectProtocol] = []
    private var quickAccessObserver: NSObjectProtocol?
    private let aiSidebar = AISidebarView()
    private let aiChip = ProfileChipView()
    private let aiChipLabel = NSTextField(labelWithString: "✦")
    private var aiSidebarWidth = AISidebarView.defaultWidth
    private var aiSettingsObserver: NSObjectProtocol?
    private var aiButtonObserver: NSObjectProtocol?
    private var profileChipObserver: NSObjectProtocol?
    // Tokens arrive faster than a transcript needs repainting, so renders are
    // coalesced onto the next tick instead of one per delta.
    private var aiRenderPending = false
    // ⌥ is read when the navigation is still an action, because a response
    // download arrives a round trip later, by which time the key is released.
    private var pendingDownloadWantsPanel = false
    private var isConfirmingExternalOpen = false
    var profileID: String { profile.id }
    var onClose: (() -> Void)?

    // Every existing menu action, HUD commit, snapshot, and download path
    // reaches the page through `webView`, so pointing it at the active tab
    // keeps all of them working untouched.
    var activeTab: Tab { tabs[activeIndex] }
    var webView: BrowserWebView { tabs[activeIndex].webView }
    private var tabBarVisible: Bool { tabs.count > 1 }
    private var tabBarHeight: CGFloat { tabBarVisible ? TabBarView.height : 0 }
    /// The sidebar belongs to the front tab, so this is a question about that tab
    /// and not about the window.
    private var aiSidebarShown: Bool { activeTab.aiSidebarOpen }
    /// How much of the window's width the page keeps once the sidebar has its cut.
    private var aiSidebarSpan: CGFloat { aiSidebarShown ? aiSidebarWidth : 0 }
    private var aiChipWidth: CGFloat { AIButtonPreference.isOn ? 32 : 0 }

    init(profile: BrowserProfile, url: URL?, size: NSSize?, snap: SnapJob?,
         isPrimary: Bool, isPrivate: Bool = false, firstTabAgent: Bool = false) {
        self.profile = profile
        self.isPrivate = isPrivate
        // A window the control socket opens is born with its one agent tab —
        // the remote `open` that caused it — rather than a start page that
        // would only sit beside the tab it was asked for.
        let firstConf = firstTabAgent
            ? makeAgentConfiguration(for: profile, isPrivate: isPrivate)
            : makeWebConfiguration(for: profile, isPrivate: isPrivate)
        tabs = [Tab(webView: BrowserWebView(frame: .zero, configuration: firstConf))]
        // Set before configure() so the orange border lands on the first paint.
        tabs[0].isAgent = firstTabAgent
        snapJob = snap

        let contentSize = size ?? NSSize(width: 1160, height: 760)
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: contentSize),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered, defer: false)
        super.init(window: window)

        window.title = "Chromeless - \(isPrivate ? "Private" : profile.name)"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        window.isReleasedWhenClosed = false
        window.tabbingMode = .disallowed
        window.minSize = NSSize(width: 320, height: 220)
        window.backgroundColor = NSColor(calibratedWhite: 0.04, alpha: 1)
        window.appearance = NSAppearance(named: .darkAqua)
        window.collectionBehavior.insert(.fullScreenPrimary)
        window.acceptsMouseMovedEvents = true
        window.delegate = self
        setTrafficLights(visible: false)

        let container = LayoutReportingView(frame: NSRect(origin: .zero, size: contentSize))
        container.onLayout = { [weak self] in self?.layoutOverlays() }
        window.contentView = container

        configure(tabs[0])
        tabs[0].webView.frame = container.bounds
        container.addSubview(tabs[0].webView)

        buildOverlays(in: container)

        window.center()
        if isPrimary && snap == nil {
            // macOS 15+ appends the tiling state to the autosaved frame; the
            // WindowServer then replays the tile at order time — wrong display,
            // wrong size. Only the plain rect is ours to restore, so the tail
            // JSON is stripped before the frame goes back in.
            let frameKey = "NSWindow Frame ChromelessMain-\(profile.id)"
            if let saved = UserDefaults.standard.string(forKey: frameKey),
               let brace = saved.firstIndex(of: "{") {
                UserDefaults.standard.set(String(saved[..<brace]), forKey: frameKey)
            }
            window.setFrameUsingName("ChromelessMain-\(profile.id)")
            window.setFrameAutosaveName("ChromelessMain-\(profile.id)")
        } else if let key = NSApp.keyWindow {
            window.setFrameTopLeftPoint(NSPoint(x: key.frame.minX + 30, y: key.frame.maxY - 30))
        }
        if let size { window.setContentSize(size) }
        // After the saved/cascaded frame is final: the setting pulls windows
        // back onto the primary display — the whole point of it.
        if snap == nil { PrimaryScreenPreference.constrain(window) }

        installMouseMonitor()
        installKeyMonitor()

        if let url { navigate(to: url) } else { loadStartPage() }
        preconnectFrequentHosts()
        if snap == nil && !profileStore.usesPersistentProfileStores {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) { [weak self] in
                self?.showToast("Profiles are private on macOS 13; persistent profiles need macOS 14")
            }
        }
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    // MARK: Tabs

    private func configure(_ tab: Tab) {
        let wv = tab.webView
        wv.autoresizingMask = [.width, .height]
        // The page rail marks an agent tab inside the page; this marks the
        // edge of its view, so the border is still visible while the rail is
        // scrolled past or the page simply hasn't painted yet.
        if tab.isAgent {
            wv.wantsLayer = true
            wv.layer?.borderWidth = 2
            wv.layer?.borderColor = NSColor.systemOrange.cgColor
        }
        wv.onQuickAccess = { [weak self] source, body in self?.handleQuickAccess(body, from: source) }
        wv.onOpenLinkInNewTab = { [weak self] url, background in
            _ = self?.addTab(url: url, activate: !background)
        }
        // Only the front tab's hover is drawn — a background tab's pointer is
        // not moving anyway, and drawing its link over this page would lie.
        wv.onLinkHover = { [weak self, weak wv] url in
            guard let self, let wv, self.tab(for: wv) === self.activeTab else { return }
            self.setLinkHover(url)
        }
        wv.onTranslate = { [weak self, weak wv] body in
            guard let self, let wv, self.tab(for: wv) === self.activeTab else { return }
            self.handleTranslateMessage(body, from: wv)
        }
        wv.onPickedSelector = { [weak self, weak wv] selector in
            guard let self else { return }
            guard let selector else {
                self.showToast("That element can’t be targeted safely")
                // The picker hid the element when Hide was clicked; with no
                // rule saved, put it back.
                wv?.evaluateJavaScript(
                    "window.__chromelessPickDone && window.__chromelessPickDone(true);",
                    in: nil, in: chromelessWorld, completionHandler: nil)
                return
            }
            // No reload: the picker hid the element when Hide was clicked and
            // the compiled rule covers the next load. Reloading would only
            // cost the page's scroll position and whatever was typed into it.
            self.showToast("\(selector) stays hidden")
            wv?.evaluateJavaScript(
                "window.__chromelessPickDone && window.__chromelessPickDone(false);",
                in: nil, in: chromelessWorld, completionHandler: nil)
        }
        adBlockManager.register(wv)
        wv.navigationDelegate = self
        wv.uiDelegate = self
        wv.allowsBackForwardNavigationGestures = true
        wv.allowsMagnification = true
        wv.underPageBackgroundColor = NSColor(calibratedWhite: 0.04, alpha: 1)
        if #available(macOS 13.3, *) { wv.isInspectable = true }
        observe(tab)
    }

    // `configuration` is non-nil only when WebKit hands us one for window.open
    // or target=_blank; in that case WebKit drives the load itself.
    @discardableResult
    func addTab(url: URL?, configuration: WKWebViewConfiguration? = nil,
                activate: Bool = true, agent: Bool = false) -> Tab {
        let conf = configuration ?? makeWebConfiguration(for: profile, isPrivate: isPrivate)
        let tab = Tab(webView: BrowserWebView(frame: .zero, configuration: conf))
        // Set before configure+refreshTabs so the badge and border are right
        // from the first paint.
        tab.isAgent = agent
        configure(tab)
        tabs.append(tab)
        if activate { activeIndex = tabs.count - 1 }
        refreshTabs()
        if configuration == nil {
            if let url { load(url, in: tab) } else { loadStartPage(in: tab) }
        }
        return tab
    }

    /// The tab a remote `open` makes: agent-owned from birth, always in the
    /// background so nothing remote takes the user's foreground, and built on
    /// the instrumented configuration that feeds `logs`.
    func addAgentTab(url: URL) -> Tab {
        let conf = makeAgentConfiguration(for: profile, isPrivate: isPrivate)
        let tab = addTab(url: nil, configuration: conf, activate: false, agent: true)
        load(url, in: tab)
        return tab
    }

    func selectTab(at index: Int) {
        guard tabs.indices.contains(index), index != activeIndex else { return }
        // Clears the find highlight on the tab being left, before it goes.
        hideFindBar()
        activeIndex = index
        refreshTabs()
    }

    func closeTab(at index: Int, recordClosed: Bool = true) {
        guard tabs.indices.contains(index) else { return }
        // Closing the only tab closes the window, so ⌘W keeps its old meaning
        // — and windowShouldClose is what asks about the session inside it.
        if tabs.count == 1 { window?.performClose(nil); return }
        guard confirmLeavingSessions(in: [tabs[index]], verb: "Close") else { return }
        if index == activeIndex { hideFindBar() }
        let tab = tabs.remove(at: index)
        // The URL is all a reopen gets back — the page's own back-forward list
        // dies with the web view.
        if recordClosed { recordClosedTab(tab) }
        tab.teardown()
        if activeIndex >= tabs.count {
            activeIndex = tabs.count - 1
        } else if index < activeIndex {
            activeIndex -= 1
        }
        refreshTabs()
    }

    // Reordering only permutes the array; no web view is created, destroyed, or
    // reparented, so the page being viewed never notices.
    func moveTab(from: Int, to: Int) {
        guard tabs.indices.contains(from), tabs.indices.contains(to), from != to else { return }
        tabs.insert(tabs.remove(at: from), at: to)
        // Keep whichever tab was active active, wherever it ended up.
        if activeIndex == from {
            activeIndex = to
        } else if from < activeIndex, activeIndex <= to {
            activeIndex -= 1
        } else if to <= activeIndex, activeIndex < from {
            activeIndex += 1
        }
        refreshTabs()
    }

    private func refreshTabs() {
        guard let container = window?.contentView else { return }
        for tab in tabs where tab !== activeTab {
            if tab.isAgent {
                // Background agent tabs stay attached, parked under the
                // user's page — hidden or detached web views stop rendering,
                // and `snap` is how a remote agent sees the pages it drives.
                // Re-adding one that was just active parks it back at the
                // bottom of the stack. The frame is set by hand: autoresizing
                // only stretches a view when the container resizes, and a
                // parked view may be attached after that resize happened.
                tab.webView.frame = container.bounds
                container.addSubview(tab.webView, positioned: .below, relativeTo: nil)
            } else if tab.webView.superview != nil {
                tab.webView.removeFromSuperview()
            }
        }
        if activeTab.webView.superview == nil || activeTab.isAgent {
            // Re-adding a parked agent view lifts it back above the others.
            activeTab.webView.frame = container.bounds
            container.addSubview(activeTab.webView, positioned: .below,
                                 relativeTo: tabBar)
        }
        activeTab.webView.isHidden = false
        tabBar.rebuild(titles: tabs.map(\.displayTitle), activeIndex: activeIndex,
                       agents: tabs.map(\.isAgent))
        for (index, tab) in tabs.enumerated() {
            tabBar.update(iconAt: index, to: tab.favicon)
        }
        tabBar.isHidden = !tabBarVisible
        // The bubble belongs to the page it hovered over, not the window.
        setLinkHover(nil)
        dismissTranslate()
        refreshKeepAwake()
        // The tab bar sits in the titlebar strip, which the WindowServer claims
        // as a window-drag region from outside this process. No view-level
        // property gets it back — `mouseDownCanMoveWindow` is simply ignored
        // there — so a press on a tab slides the window instead of the tab.
        // Clearing `isMovable` is the one thing that stops it. `performDrag` is
        // unaffected by the flag, so ⌘-drag and the empty strip still move the
        // window; with a single tab there is no bar and the strip behaves as it
        // always has. The AI sidebar reaches into the same strip, so it needs the
        // flag cleared for exactly the same reason.
        window?.isMovable = !(tabBarVisible || aiSidebarShown)
        // Lay out now rather than next frame, so a switch never paints one
        // frame of tabs still sitting at their old positions.
        tabBar.layoutSubtreeIfNeeded()
        syncWindowTitle()
        let p = activeTab.lastProgress
        progressBar.alphaValue = (p > 0 && p < 1) ? 1 : 0
        layoutOverlays()
        // The HUD is the address bar for the page you are on, so it must not
        // survive a tab switch carrying the previous tab's URL.
        if hud.isHidden {
            window?.makeFirstResponder(activeTab.webView)
        } else {
            hideHUD()
        }
        // The sidebar follows the front tab: a tab that never opened it shows no
        // sidebar at all, and the tab that did keeps its own conversation.
        syncAISidebar()
    }

    private func tab(for webView: WKWebView) -> Tab? {
        tabs.first { $0.webView === webView }
    }

    private func syncWindowTitle() {
        let t = activeTab.webView.title ?? ""
        let suffix = isPrivate ? "Private" : profile.name
        window?.title = "\(t.isEmpty ? "Chromeless" : t) - \(suffix)"
    }

    // MARK: Chrome (what little there is)

    private func setTrafficLights(visible: Bool) {
        for kind: NSWindow.ButtonType in [.closeButton, .miniaturizeButton, .zoomButton] {
            window?.standardWindowButton(kind)?.isHidden = !visible
        }
    }

    private var isFullScreen: Bool { window?.styleMask.contains(.fullScreen) ?? false }

    private func installMouseMonitor() {
        mouseMonitor = NSEvent.addLocalMonitorForEvents(matching: [.mouseMoved, .leftMouseDown]) { [weak self] event in
            guard let self, event.window === self.window else { return event }
            if event.type == .mouseMoved {
                // Reveal the traffic lights only when hovering the top-left corner.
                guard let contentView = self.window?.contentView else { return event }
                let p = event.locationInWindow
                let nearCorner = p.y > contentView.bounds.height - 44 && p.x < 96
                self.setTrafficLights(visible: self.isFullScreen || nearCorner)
            } else if !self.hud.isHidden {
                let p = self.window!.contentView!.convert(event.locationInWindow, from: nil)
                // The suggestion panel is part of the address-bar interaction —
                // clicking a row must not close the HUD before the click lands.
                if !self.hud.frame.contains(p) && !self.suggestPanel.frame.contains(p) {
                    self.hideHUD()
                }
            }
            return event
        }
    }

    // ⌃Tab cannot be a menu key equivalent on macOS, so it is caught here — and
    // F12 is caught here too, ahead of the menu equivalent that advertises it,
    // because on keyboards where F12 is wired to volume the key only arrives
    // fn-modified. ⌥⌘I still works for the Safari reflex, without a second row
    // in the menu.
    private func installKeyMonitor() {
        keyMonitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown]) { [weak self] event in
            guard let self, event.window === self.window else { return event }
            // A live session owns every key the page can see — ⌃Tab and F12
            // reach the terminal instead of switching tabs or popping the
            // inspector.
            if isSessionHost(self.activeTab.webView.url) { return event }
            let mods = event.modifierFlags
                .intersection(.deviceIndependentFlagsMask)
                .subtracting([.function, .numericPad, .capsLock])
            if event.keyCode == 111, mods.isEmpty {
                self.toggleWebInspector(nil)
                return nil
            }
            if mods == [.command, .option], event.charactersIgnoringModifiers?.lowercased() == "i" {
                self.toggleWebInspector(nil)
                return nil
            }
            guard event.modifierFlags.contains(.control), event.keyCode == 48 else { return event }
            if event.modifierFlags.contains(.shift) {
                self.showPreviousTab(nil)
            } else {
                self.showNextTab(nil)
            }
            return nil
        }
    }

    private func buildOverlays(in container: NSView) {
        tabBar.onSelect = { [weak self] i in self?.selectTab(at: i) }
        tabBar.onClose = { [weak self] i in self?.closeTab(at: i) }
        tabBar.onNewTab = { [weak self] in self?.addTab(url: nil) }
        tabBar.onReorder = { [weak self] from, to in self?.moveTab(from: from, to: to) }
        tabBar.onContextMenu = { [weak self] i in self?.buildTabContextMenu(for: i) }
        tabBar.isHidden = true
        container.addSubview(tabBar)

        progressBar.wantsLayer = true
        progressBar.layer?.backgroundColor = NSColor.controlAccentColor.cgColor
        progressBar.alphaValue = 0
        container.addSubview(progressBar)

        hud.material = .hudWindow
        hud.blendingMode = .withinWindow
        hud.state = .active
        hud.wantsLayer = true
        hud.layer?.cornerRadius = 26
        hud.layer?.cornerCurve = .continuous
        hud.layer?.masksToBounds = true
        hud.layer?.borderWidth = 1
        hud.layer?.borderColor = NSColor.white.withAlphaComponent(0.12).cgColor
        hud.isHidden = true
        hud.alphaValue = 0
        hudField.isBezeled = false
        hudField.isBordered = false
        hudField.drawsBackground = false
        hudField.focusRingType = .none
        hudField.font = .systemFont(ofSize: 16)
        hudField.textColor = .labelColor
        hudField.placeholderString = "Search or enter address"
        hudField.usesSingleLineMode = true
        hudField.cell?.isScrollable = true
        hudField.cell?.wraps = false
        hudField.delegate = self
        hud.addSubview(hudField)
        container.addSubview(hud)

        // The suggestion panel rides under the HUD like the suggestions ride
        // under a normal address bar: same width, same left edge.
        suggestPanel.material = .hudWindow
        suggestPanel.blendingMode = .withinWindow
        suggestPanel.state = .active
        suggestPanel.wantsLayer = true
        suggestPanel.layer?.cornerRadius = 12
        suggestPanel.layer?.cornerCurve = .continuous
        suggestPanel.layer?.masksToBounds = true
        suggestPanel.layer?.borderWidth = 1
        suggestPanel.layer?.borderColor = NSColor.white.withAlphaComponent(0.12).cgColor
        suggestPanel.isHidden = true
        suggestPanel.alphaValue = 0
        suggestTable.headerView = nil
        suggestTable.rowHeight = 28
        suggestTable.intercellSpacing = NSSize(width: 0, height: 2)
        suggestTable.backgroundColor = .clear
        suggestTable.selectionHighlightStyle = .regular
        suggestTable.dataSource = self
        suggestTable.delegate = self
        suggestTable.target = self
        suggestTable.action = #selector(openSelectedSuggestion(_:))
        suggestTable.addTableColumn(NSTableColumn(identifier: NSUserInterfaceItemIdentifier("s")))
        suggestPanel.addSubview(suggestTable)
        container.addSubview(suggestPanel)

        // ⌘F. A smaller HUD: field, n/m counter, prev/next/close.
        findBar.material = .hudWindow
        findBar.blendingMode = .withinWindow
        findBar.state = .active
        findBar.wantsLayer = true
        findBar.layer?.cornerRadius = 17
        findBar.layer?.cornerCurve = .continuous
        findBar.layer?.masksToBounds = true
        findBar.layer?.borderWidth = 1
        findBar.layer?.borderColor = NSColor.white.withAlphaComponent(0.12).cgColor
        findBar.isHidden = true
        findBar.alphaValue = 0
        findField.isBezeled = false
        findField.isBordered = false
        findField.drawsBackground = false
        findField.focusRingType = .none
        findField.font = .systemFont(ofSize: 13)
        findField.textColor = .labelColor
        findField.placeholderString = "Find in page"
        findField.usesSingleLineMode = true
        findField.cell?.isScrollable = true
        findField.cell?.wraps = false
        findField.delegate = self
        findBar.addSubview(findField)
        findCountLabel.font = .systemFont(ofSize: 11)
        findCountLabel.textColor = .secondaryLabelColor
        findCountLabel.alignment = .right
        findBar.addSubview(findCountLabel)
        for (title, tip, action) in [
            ("‹", "Previous (⇧↩)", #selector(findPreviousAction(_:))),
            ("›", "Next (↩)", #selector(findNextAction(_:))),
            ("✕", "Close (esc)", #selector(hideFindBarAction(_:))),
        ] {
            let b = NSButton()
            b.isBordered = false
            b.bezelStyle = .inline
            b.title = title
            b.font = .systemFont(ofSize: 13, weight: .medium)
            b.contentTintColor = .secondaryLabelColor
            b.toolTip = tip
            b.target = self
            b.action = action
            findBar.addSubview(b)
            findButtons.append(b)
        }
        container.addSubview(findBar)

        linkHoverView.material = .hudWindow
        linkHoverView.blendingMode = .withinWindow
        linkHoverView.state = .active
        linkHoverView.wantsLayer = true
        // Flush against the bottom-left corner like a real status bar — only
        // the top-right edge rounds off.
        linkHoverView.layer?.cornerRadius = 8
        linkHoverView.layer?.cornerCurve = .continuous
        linkHoverView.layer?.maskedCorners = [.layerMaxXMaxYCorner]
        linkHoverView.layer?.masksToBounds = true
        linkHoverView.isHidden = true
        linkHoverView.alphaValue = 0
        linkHoverLabel.font = .systemFont(ofSize: 11)
        linkHoverLabel.textColor = .secondaryLabelColor
        linkHoverLabel.lineBreakMode = .byTruncatingMiddle
        linkHoverView.addSubview(linkHoverLabel)
        container.addSubview(linkHoverView)

        toastView.material = .hudWindow
        toastView.blendingMode = .withinWindow
        toastView.state = .active
        toastView.wantsLayer = true
        toastView.layer?.cornerRadius = 17
        toastView.layer?.cornerCurve = .continuous
        toastView.layer?.masksToBounds = true
        toastView.isHidden = true
        toastView.alphaValue = 0
        toastLabel.font = .systemFont(ofSize: 13, weight: .medium)
        toastLabel.textColor = .labelColor
        toastView.addSubview(toastLabel)
        container.addSubview(toastView)

        profileBadge.material = .hudWindow
        profileBadge.blendingMode = .withinWindow
        profileBadge.state = .active
        profileBadge.wantsLayer = true
        profileBadge.layer?.cornerRadius = 12
        profileBadge.layer?.cornerCurve = .continuous
        profileBadge.layer?.masksToBounds = true
        profileBadge.alphaValue = 0.82
        profileLabel.stringValue = isPrivate ? "Private" : profile.name
        profileLabel.font = .systemFont(ofSize: 11, weight: .semibold)
        profileLabel.textColor = .labelColor
        profileLabel.lineBreakMode = .byTruncatingTail
        profileBadge.toolTip = isPrivate
            ? "Private window — nothing is saved"
            : "Profile — click to switch"
        profileBadge.onClick = { [weak self] in
            guard let self else { return }
            (NSApp.delegate as? AppDelegate)?.presentProfilePicker(from: self)
        }
        profileBadge.addSubview(profileLabel)
        container.addSubview(profileBadge)

        profileChipObserver = NotificationCenter.default.addObserver(
            forName: .profileChipPreferenceDidChange, object: nil, queue: .main) { [weak self] _ in
                guard let self else { return }
                self.layoutOverlays()
            }

        downloadsPanel.onClose = { [weak self] in self?.hideDownloadsPanel() }
        container.addSubview(downloadsPanel)
        buildAISidebar(in: container)
        observeDownloads()
        observeQuickAccess()
    }

    // MARK: AI sidebar

    private func buildAISidebar(in container: NSView) {
        if let saved = UserDefaults.standard.object(forKey: "ChromelessAISidebarWidth") as? Double,
           saved >= Double(AISidebarView.minWidth) {
            aiSidebarWidth = CGFloat(saved)
        }
        aiSidebar.isHidden = true
        aiSidebar.onSend = { [weak self] text in self?.askAI(text) }
        aiSidebar.onStop = { [weak self] in
            guard let self else { return }
            self.activeTab.aiSession.cancel()
            self.renderAISidebar()
        }
        aiSidebar.onClose = { [weak self] in self?.setAISidebar(visible: false) }
        aiSidebar.onNewChat = { [weak self] in
            guard let self else { return }
            self.activeTab.aiSession.reset()
            self.renderAISidebar()
            self.aiSidebar.focusComposer()
        }
        aiSidebar.onOpenSettings = { AISettingsWindowController.shared.present() }
        aiSidebar.onToggleContext = { [weak self] on in
            guard let self else { return }
            self.activeTab.aiSession.includePage = on
            if on { self.captureAIPageContext() }
            self.renderAISidebar()
        }
        aiSidebar.onDraftChange = { [weak self] text in self?.activeTab.aiSession.draft = text }
        aiSidebar.onOpenLink = { [weak self] url in
            // A link in an answer opens where the reader is looking: a new
            // background tab, not on top of the page being asked about.
            self?.addTab(url: url, activate: false)
        }
        aiSidebar.onResize = { [weak self] width in self?.resizeAISidebar(to: width) }
        aiSidebar.onPickModel = { [weak self] ref in
            guard let self else { return }
            // The choice belongs to this tab, and becomes what the next new tab
            // starts on — picking a model twice for the same work is a chore.
            self.activeTab.aiSession.model = ref
            aiSettingsStore.update { $0.defaultModel = ref }
            self.renderAISidebar()
        }
        container.addSubview(aiSidebar)

        // The optional round button, parked next to the profile chip. Same view
        // class as that chip, so hover, blur, and clicks behave identically.
        aiChip.material = .hudWindow
        aiChip.blendingMode = .withinWindow
        aiChip.state = .active
        aiChip.wantsLayer = true
        aiChip.layer?.cornerRadius = 12
        aiChip.layer?.masksToBounds = true
        aiChip.alphaValue = 0.82
        aiChip.toolTip = "AI sidebar for this tab (⇧⌘A)"
        aiChip.isHidden = !AIButtonPreference.isOn
        aiChip.onClick = { [weak self] in self?.toggleAISidebar(nil) }
        aiChipLabel.font = .systemFont(ofSize: 12, weight: .semibold)
        aiChipLabel.textColor = .labelColor
        aiChipLabel.alignment = .center
        aiChip.addSubview(aiChipLabel)
        container.addSubview(aiChip)

        aiSettingsObserver = NotificationCenter.default.addObserver(
            forName: .aiSettingsDidChange, object: nil, queue: .main) { [weak self] _ in
                guard let self, self.aiSidebarShown else { return }
                self.renderAISidebar()
            }
        aiButtonObserver = NotificationCenter.default.addObserver(
            forName: .aiButtonPreferenceDidChange, object: nil, queue: .main) { [weak self] _ in
                guard let self else { return }
                self.aiChip.isHidden = !AIButtonPreference.isOn
                self.layoutOverlays()
            }
    }

    @objc func toggleAISidebar(_ sender: Any?) {
        setAISidebar(visible: !aiSidebarShown)
    }

    @objc func showAISettings(_ sender: Any?) {
        AISettingsWindowController.shared.present()
    }

    @objc func toggleAIButton(_ sender: Any?) {
        AIButtonPreference.set(!AIButtonPreference.isOn)
    }

    @objc func toggleTranslateOnShift(_ sender: Any?) {
        TranslatePreference.set(!TranslatePreference.isOn)
        if !TranslatePreference.isOn { dismissTranslate() }
    }

    @objc func toggleProfileChip(_ sender: Any?) {
        ProfileChipPreference.set(!ProfileChipPreference.isOn)
    }

    @objc func showRemoteSettings(_ sender: Any?) {
        RemoteSettingsWindowController.shared.present()
    }

    private func setAISidebar(visible: Bool) {
        guard activeTab.aiSidebarOpen != visible else { return }
        activeTab.aiSidebarOpen = visible
        syncAISidebar()
        if visible {
            aiSidebar.focusComposer()
        } else {
            window?.makeFirstResponder(webView)
        }
    }

    /// Brings the sidebar in line with the front tab: shown or gone, painted with
    /// that tab's conversation, and looking at that tab's page.
    private func syncAISidebar() {
        aiSidebar.isHidden = !aiSidebarShown
        // Same reason the tab bar clears it: the sidebar's header sits in the
        // strip the WindowServer treats as a drag handle.
        window?.isMovable = !(tabBarVisible || aiSidebarShown)
        layoutOverlays()
        guard aiSidebarShown else { return }
        renderAISidebar()
        captureAIPageContext()
    }

    private func resizeAISidebar(to width: CGFloat) {
        guard let contentWidth = window?.contentView?.bounds.width else { return }
        let maximum = min(AISidebarView.maxWidth, max(AISidebarView.minWidth, contentWidth - 260))
        aiSidebarWidth = min(max(width, AISidebarView.minWidth), maximum)
        UserDefaults.standard.set(Double(aiSidebarWidth), forKey: "ChromelessAISidebarWidth")
        layoutOverlays()
    }

    private func renderAISidebar() {
        guard aiSidebarShown else { return }
        aiSidebar.render(session: activeTab.aiSession, settings: aiSettingsStore.settings)
    }

    /// Reads the page so the sidebar can say what it is about to send. The
    /// capture used for an actual question is taken again at send time.
    private func captureAIPageContext() {
        guard aiSidebarShown, activeTab.aiSession.includePage else { return }
        let tab = activeTab
        AIPageCapture.capture(from: tab.webView,
                             limit: aiSettingsStore.settings.maxContextCharacters) { [weak self] page in
            guard let self, let page else { return }
            tab.aiSession.pageContext = page
            guard tab === self.activeTab else { return }
            self.renderAISidebar()
        }
    }

    private func askAI(_ text: String) {
        let tab = activeTab
        let session = tab.aiSession
        guard !session.streaming else { return }
        guard aiSettingsStore.settings.resolve(session.model) != nil else {
            AISettingsWindowController.shared.present()
            return
        }
        // The page is read again right before the question goes out, so an answer
        // is about what is on screen now — not what was there when the sidebar
        // was opened.
        guard session.includePage else {
            startAI(text, in: tab, page: nil)
            return
        }
        AIPageCapture.capture(from: tab.webView,
                             limit: aiSettingsStore.settings.maxContextCharacters) { [weak self] page in
            self?.startAI(text, in: tab, page: page)
        }
    }

    private func startAI(_ text: String, in tab: Tab, page: AIPageContext?) {
        tab.aiSession.send(text, page: page) { [weak self, weak tab] in
            guard let self, let tab, tab === self.activeTab else { return }
            self.scheduleAIRender()
        }
    }

    private func scheduleAIRender() {
        guard aiSidebarShown, !aiRenderPending else { return }
        aiRenderPending = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { [weak self] in
            guard let self else { return }
            self.aiRenderPending = false
            self.renderAISidebar()
        }
    }

    // MARK: Downloads panel

    private func observeDownloads() {
        let center = NotificationCenter.default
        downloadsObservers = [
            center.addObserver(forName: .downloadsDidChange, object: nil, queue: .main) {
                [weak self] _ in self?.downloadsChanged()
            },
            center.addObserver(forName: .downloadsMessage, object: nil, queue: .main) {
                [weak self] note in
                guard let self, self.window?.isKeyWindow == true,
                      let text = note.userInfo?["text"] as? String else { return }
                self.showToast(text)
            },
        ]
    }

    private func downloadsChanged() {
        downloadsPanel.refresh()
        layoutOverlays()
        if downloadManager.hasActiveDownloads {
            downloadsHide?.cancel()
            downloadsHide = nil
        } else if !downloadsPanel.isHidden && !downloadsPanelPinned {
            scheduleDownloadsHide()
        }
    }

    private func showDownloadsPanel(pinned: Bool) {
        if pinned { downloadsPanelPinned = true }
        downloadsHide?.cancel()
        downloadsHide = nil
        downloadsPanel.refresh()
        layoutOverlays()
        guard downloadsPanel.isHidden || downloadsPanel.alphaValue < 1 else { return }
        downloadsPanel.isHidden = false
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = 0.15
            downloadsPanel.animator().alphaValue = 1
        }
    }

    private func hideDownloadsPanel() {
        downloadsPanelPinned = false
        downloadsHide?.cancel()
        downloadsHide = nil
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = 0.15
            self.downloadsPanel.animator().alphaValue = 0
        } completionHandler: { [weak self] in
            guard let self, self.downloadsPanel.alphaValue == 0 else { return }
            self.downloadsPanel.isHidden = true
        }
    }

    // Linger for a moment after the last transfer lands, and keep lingering
    // while the pointer is still in the panel reaching for Reveal.
    private func scheduleDownloadsHide() {
        downloadsHide?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self, !self.downloadsPanelPinned,
                  !downloadManager.hasActiveDownloads else { return }
            if self.downloadsPanel.pointerInside {
                self.scheduleDownloadsHide()
                return
            }
            self.hideDownloadsPanel()
        }
        downloadsHide = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 4, execute: work)
    }

    @objc func toggleDownloadsPanel(_ sender: Any?) {
        if downloadsPanel.isHidden || downloadsPanel.alphaValue < 1 {
            showDownloadsPanel(pinned: true)
        } else {
            hideDownloadsPanel()
        }
    }

    private func layoutOverlays() {
        guard let contentView = window?.contentView else { return }
        let b = contentView.bounds

        // The sidebar takes its slice off the right edge and everything else —
        // page, tab bar, HUD, toast, badge, downloads — lays out inside what is
        // left. A window narrow enough that the sidebar would swallow the page
        // clamps it back down first.
        if aiSidebarShown {
            let maximum = min(AISidebarView.maxWidth, max(AISidebarView.minWidth, b.width - 260))
            aiSidebarWidth = min(max(aiSidebarWidth, AISidebarView.minWidth), max(maximum, 200))
        }
        let sidebar = aiSidebarSpan
        let pageWidth = max(120, b.width - sidebar)
        aiSidebar.isHidden = !aiSidebarShown
        if aiSidebarShown {
            aiSidebar.frame = NSRect(x: pageWidth, y: 0, width: b.width - pageWidth, height: b.height)
        }

        let barH = tabBarHeight
        tabBar.isHidden = !tabBarVisible
        tabBar.frame = NSRect(x: 0, y: b.height - barH, width: pageWidth, height: barH)
        activeTab.webView.frame = NSRect(x: 0, y: 0, width: pageWidth, height: b.height - barH)

        let hudW = min(620, max(280, pageWidth - 48))
        let hudH: CGFloat = 52
        hud.frame = NSRect(x: (pageWidth - hudW) / 2, y: b.height - barH - hudH - 84,
                           width: hudW, height: hudH)
        hudField.frame = NSRect(x: 20, y: (hudH - 22) / 2, width: hudW - 40, height: 22)

        // Suggestions hang off the HUD's bottom edge, as tall as the list —
        // never scrolled, since the cap is eight rows.
        let sgH = suggestions.isEmpty ? 0 : CGFloat(suggestions.count) * suggestTable.rowHeight + 8
        suggestPanel.frame = NSRect(x: hud.frame.minX,
                                    y: hud.frame.minY - 6 - sgH,
                                    width: hudW, height: sgH)
        suggestTable.frame = NSRect(x: 4, y: 4, width: max(0, hudW - 8), height: max(0, sgH - 8))

        // ⌘F docks top-right under the tab bar — where browsers put it.
        let fbW = min(320, max(240, pageWidth * 0.42))
        let fbH: CGFloat = 34
        findBar.frame = NSRect(x: pageWidth - fbW - 14,
                               y: b.height - barH - fbH - 8,
                               width: fbW, height: fbH)
        var fbRight = fbW - 8
        for button in findButtons.reversed() {
            fbRight -= 24
            button.frame = NSRect(x: fbRight, y: (fbH - 20) / 2, width: 24, height: 20)
        }
        findCountLabel.sizeToFit()
        let countW = min(72, findCountLabel.frame.width)
        findCountLabel.frame = NSRect(x: fbRight - countW - 4, y: (fbH - 14) / 2,
                                      width: countW, height: 14)
        findField.frame = NSRect(x: 14, y: (fbH - 20) / 2,
                                 width: max(60, findCountLabel.frame.minX - 20), height: 20)

        // The link-hover bubble hugs the bottom-left corner, like a status bar.
        linkHoverLabel.sizeToFit()
        let lhW = min(max(140, linkHoverLabel.frame.width + 24), max(140, pageWidth * 0.62))
        linkHoverView.frame = NSRect(x: 0, y: 0, width: lhW, height: 24)
        linkHoverLabel.frame = NSRect(x: 12, y: 5, width: lhW - 24, height: 14)

        toastLabel.sizeToFit()
        let ts = toastLabel.frame.size
        let tw = ts.width + 32
        let th: CGFloat = 34
        toastView.frame = NSRect(x: (pageWidth - tw) / 2, y: 28, width: tw, height: th)
        toastLabel.frame = NSRect(x: 16, y: (th - ts.height) / 2, width: ts.width, height: ts.height)

        // Bottom-right of the page area, and never taller than the window leaves
        // room for.
        let dlW = min(DownloadsPanelView.width, max(240, pageWidth - 40))
        let dlH = min(downloadsPanel.preferredHeight, max(120, b.height - barH - 40))
        downloadsPanel.frame = NSRect(x: pageWidth - dlW - 20, y: 20, width: dlW, height: dlH)

        let profileShown = ProfileChipPreference.isOn
        let profileMaxW = min(180, max(90, pageWidth * 0.34))
        let profileTextW = min(profileMaxW - 22, profileLabel.intrinsicContentSize.width)
        let profileW: CGFloat = profileShown ? max(72, profileTextW + 22) : 0
        let profileH: CGFloat = 24
        profileBadge.isHidden = !profileShown

        // One chip, two homes: docked in the tab bar when it is up, floating in
        // the corner when it is not. The AI button, when it is on, rides along
        // just to its left and moves house with it — and takes over the corner
        // spot entirely when the profile chip is off.
        let aiSide: CGFloat = 24
        if tabBarVisible {
            if profileBadge.superview !== tabBar {
                profileBadge.removeFromSuperview()
                tabBar.addSubview(profileBadge)
            }
            if aiChip.superview !== tabBar {
                aiChip.removeFromSuperview()
                tabBar.addSubview(aiChip)
            }
            tabBar.setChipWidth(profileW + aiChipWidth)
            profileBadge.frame = NSRect(
                x: pageWidth - profileW - 12,
                y: (barH - profileH) / 2,
                width: profileW,
                height: profileH)
            aiChip.frame = NSRect(
                x: profileBadge.frame.minX - aiSide - (profileShown ? 8 : 0),
                y: (barH - aiSide) / 2,
                width: aiSide,
                height: aiSide)
        } else {
            if profileBadge.superview !== contentView {
                profileBadge.removeFromSuperview()
                contentView.addSubview(profileBadge)
            }
            if aiChip.superview !== contentView {
                aiChip.removeFromSuperview()
                contentView.addSubview(aiChip)
            }
            let topInset: CGFloat = isFullScreen ? 18 : 12
            profileBadge.frame = NSRect(
                x: pageWidth - profileW - 14,
                y: b.height - profileH - topInset,
                width: profileW,
                height: profileH)
            aiChip.frame = NSRect(
                x: profileBadge.frame.minX - aiSide - (profileShown ? 8 : 0),
                y: b.height - aiSide - topInset,
                width: aiSide,
                height: aiSide)
        }
        aiChipLabel.frame = NSRect(x: 0, y: (aiSide - 15) / 2, width: aiSide, height: 15)
        profileLabel.frame = NSRect(
            x: 11,
            y: (profileH - 14) / 2,
            width: max(0, profileW - 22),
            height: 14)

        progressBar.frame = NSRect(x: 0, y: b.height - barH - 2,
                                   width: pageWidth * activeTab.lastProgress, height: 2)
    }

    private func observe(_ tab: Tab) {
        tab.observations = [
            tab.webView.observe(\.estimatedProgress, options: [.new]) { [weak self, weak tab] wv, _ in
                guard let self, let tab else { return }
                tab.lastProgress = CGFloat(wv.estimatedProgress)
                if tab === self.activeTab { self.progressChanged(wv.estimatedProgress) }
            },
            tab.webView.observe(\.title) { [weak self, weak tab] _, _ in
                guard let self, let tab else { return }
                self.tabBar.update(titleAt: self.tabs.firstIndex { $0 === tab }, to: tab.displayTitle)
                if tab === self.activeTab { self.syncWindowTitle() }
            },
            tab.webView.observe(\.url) { [weak self, weak tab] wv, _ in
                guard let self, let tab else { return }
                if !self.isPrivate, let u = wv.url, u.scheme == "https" || u.scheme == "http" {
                    profileStore.recordVisit(u, for: self.profile)
                }
                self.updateFavicon(for: tab, url: wv.url)
            },
        ]
    }

    private func progressChanged(_ progress: Double) {
        activeTab.lastProgress = CGFloat(progress)
        if let width = window?.contentView?.bounds.width {
            progressBar.frame.size.width = (width - aiSidebarSpan) * activeTab.lastProgress
        }
        if progress >= 1.0 {
            NSAnimationContext.runAnimationGroup({ ctx in
                ctx.duration = 0.35
                progressBar.animator().alphaValue = 0
            }, completionHandler: { [weak self] in
                self?.activeTab.lastProgress = 0
                self?.layoutOverlays()
            })
        } else {
            progressBar.alphaValue = 1
        }
    }

    // MARK: Navigation

    func load(_ url: URL, in tab: Tab) {
        tab.onStartPage = false
        if url.isFileURL {
            tab.webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        } else {
            tab.webView.load(URLRequest(url: url))
        }
    }

    func loadStartPage(in tab: Tab) {
        tab.onStartPage = true
        // New nonce per load: a stale one from a page that has been navigated away
        // from is worth nothing.
        let nonce = UUID().uuidString
        tab.startPageNonce = nonce
        tab.webView.loadHTMLString(startPageHTML(nonce: nonce), baseURL: nil)
        tabBar.update(titleAt: tabs.firstIndex { $0 === tab }, to: tab.displayTitle)
    }

    func navigate(to url: URL) { load(url, in: activeTab) }

    func loadStartPage() {
        loadStartPage(in: activeTab)
        if let job = snapJob {
            snapJob = nil
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
                self?.runSnapJob(job)
            }
        }
    }

    // MARK: Quick access

    private func observeQuickAccess() {
        quickAccessObserver = NotificationCenter.default.addObserver(
            forName: .quickAccessDidChange, object: nil, queue: .main) { [weak self] _ in
                self?.refreshQuickAccess()
            }
    }

    // Every start page in the window is repainted, not just the front one, and
    // every other window does the same off the notification — a shortcut saved
    // here has to exist everywhere it is on screen. The sheet being open is the
    // one exception: an icon arriving mid-edit must not blow away the typing.
    private func refreshQuickAccess() {
        for tab in tabs where tab.onStartPage { render(into: tab.webView) }
    }

    private func render(into webView: BrowserWebView) {
        webView.evaluateJavaScript("""
        (function () {
          var qa = window.chromelessQuickAccess;
          if (qa && !qa.isEditing()) qa.render(\(quickAccessStore.payloadJSON));
        })();
        """)
    }

    /// Calls one method on the start page's bridge, and does nothing at all if
    /// the page in that view has since been navigated away from.
    private func reply(to webView: BrowserWebView, _ call: String) {
        webView.evaluateJavaScript(
            "window.chromelessQuickAccess && window.chromelessQuickAccess.\(call);")
    }

    /// The start page asking for something. Anything else that reaches this — a
    /// site the user happens to be on, posting to the same handler — cannot know
    /// the nonce, and is dropped before it can rewrite a shortcut.
    private func handleQuickAccess(_ body: [String: Any], from webView: BrowserWebView) {
        guard let tab = tab(for: webView), tab.onStartPage,
              let nonce = tab.startPageNonce,
              let claimed = body["nonce"] as? String, claimed == nonce else {
            // Worth a line: this is either a page trying its luck, or a bug in the
            // start page. Both are things someone would want to see.
            fputs("chromeless: dropped a quick-access message that did not come "
                + "from the start page (\(body["action"] as? String ?? "no action"))\n", stderr)
            return
        }
        switch body["action"] as? String {
        case "open":
            guard let id = body["id"] as? String,
                  let link = quickAccessStore.link(id: id),
                  let url = URL(string: link.url) else { return }
            if body["background"] as? Bool == true {
                addTab(url: url, activate: body["activate"] as? Bool == true)
            } else {
                load(url, in: tab)
            }

        // The sheet stays open until this comes back, so a rejected address can
        // be corrected instead of being silently swallowed.
        case "save":
            let raw = (body["url"] as? String) ?? ""
            guard let url = smartURL(raw), !url.isFileURL else {
                reply(to: webView, "reject('That address doesn\\'t look right.')")
                return
            }
            let id = body["id"] as? String
            guard quickAccessStore.save(id: id, title: (body["title"] as? String) ?? "", url: url) != nil else {
                reply(to: webView, "reject('All \(QuickAccessStore.slotCount) slots are taken.')")
                return
            }
            reply(to: webView, "accept()")

        case "remove":
            guard let id = body["id"] as? String else { return }
            quickAccessStore.remove(id: id)

        // Folded or unfolded is remembered, since the start page is rebuilt
        // from scratch every time it is opened.
        case "collapse":
            quickAccessStore.setCollapsed(body["value"] as? Bool == true)

        case "editing":
            // The HUD floats over the page and holds first responder, so it has
            // to get out of the way before the sheet can be typed into.
            if body["value"] as? Bool == true { hideHUD() }

        // Sent by the page once its sheet is shut. `refreshQuickAccess` skipped
        // this tab while the sheet was open, so this is the repaint it missed.
        case "ready":
            render(into: webView)

        default:
            break
        }
    }

    // MARK: HUD (the ⌘L address bar)

    func showHUD() {
        if let u = webView.url, !activeTab.onStartPage, u.absoluteString != "about:blank" {
            hudField.stringValue = u.absoluteString
        } else {
            hudField.stringValue = ""
        }
        hud.isHidden = false
        layoutOverlays()
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = 0.15
            hud.animator().alphaValue = 1
        }
        hudField.selectText(nil)
        rebuildSuggestions()
    }

    func hideHUD() {
        suggestions = []
        suggestPanel.isHidden = true
        suggestPanel.alphaValue = 0
        suggestTable.deselectAll(nil)
        NSAnimationContext.runAnimationGroup({ ctx in
            ctx.duration = 0.15
            self.hud.animator().alphaValue = 0
        }, completionHandler: { [weak self] in
            guard let self else { return }
            self.hud.isHidden = true
            // Hand the page its focus back — unless another overlay's field
            // claimed it while the fade ran (⌘F opens the find bar mid-fade).
            if !(self.window?.firstResponder is NSTextView) {
                self.window?.makeFirstResponder(self.webView)
            }
        })
    }

    private func commitHUD() {
        // A picked suggestion wins over whatever is typed — that is what the
        // arrows are for.
        if let url = pickedSuggestionURL() {
            hideHUD()
            navigate(to: url)
            return
        }
        let text = hudField.stringValue
        hideHUD()
        if let url = smartURL(text) { navigate(to: url) }
    }

    func control(_ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
        if control === findField {
            if commandSelector == #selector(NSResponder.cancelOperation(_:)) { hideFindBar(); return true }
            if commandSelector == #selector(NSResponder.insertNewline(_:)) {
                // The same field, the same two directions as every browser.
                stepFind(NSApp.currentEvent?.modifierFlags.contains(.shift) == true ? -1 : 1)
                return true
            }
            return false
        }
        guard control === hudField else { return false }
        if commandSelector == #selector(NSResponder.cancelOperation(_:)) { hideHUD(); return true }
        if commandSelector == #selector(NSResponder.insertNewline(_:)) { commitHUD(); return true }
        if commandSelector == #selector(NSResponder.moveDown(_:)) { moveSuggestion(1); return true }
        if commandSelector == #selector(NSResponder.moveUp(_:)) { moveSuggestion(-1); return true }
        return false
    }

    func controlTextDidChange(_ obj: Notification) {
        guard let control = obj.object as? NSControl else { return }
        if control === hudField {
            rebuildSuggestions()
        } else if control === findField {
            // Rescanning on every keystroke is cheap for normal pages; the
            // short debounce keeps pathological ones from stalling the field.
            findDebounce?.cancel()
            let work = DispatchWorkItem { [weak self] in
                self?.performFind(target: 0)
            }
            findDebounce = work
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.15, execute: work)
        }
    }

    // MARK: HUD suggestions

    /// Quick-access tiles first — they are the sites the user chose — then the
    /// profile's recorded history, newest visit first. An empty field lists
    /// the tiles alone, so ⌘L ↓ ↩ is a jump to any of them.
    private func rebuildSuggestions() {
        let q = hudField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        var out: [(title: String?, url: String, icon: NSImage?)] = []
        var seen = Set<String>()
        func add(_ title: String?, _ url: String, _ icon: NSImage?) {
            if out.count < 8, seen.insert(url).inserted { out.append((title, url, icon)) }
        }
        for link in quickAccessStore.links
        where q.isEmpty || link.title.lowercased().contains(q) || link.url.lowercased().contains(q) {
            add(link.title, link.url, suggestionIcon(for: link))
        }
        if !q.isEmpty {
            for u in profile.history.reversed() where u.lowercased().contains(q) {
                add(nil, u, nil)
            }
        }
        suggestions = out
        suggestTable.reloadData()
        suggestTable.deselectAll(nil)
        layoutOverlays()
        let show = !hud.isHidden && !suggestions.isEmpty
        suggestPanel.isHidden = !show
        suggestPanel.alphaValue = show ? 1 : 0
    }

    private func suggestionIcon(for link: QuickLink) -> NSImage? {
        if let cached = suggestIconCache[link.id] { return cached }
        guard let image = imageFromDataURI(link.icon) else { return nil }
        suggestIconCache[link.id] = image
        return image
    }

    private func imageFromDataURI(_ s: String?) -> NSImage? {
        guard let s, let comma = s.firstIndex(of: ","),
              s[..<comma].contains("base64"),
              let data = Data(base64Encoded: String(s[s.index(after: comma)...])),
              let image = NSImage(data: data) else { return nil }
        return image
    }

    /// ↓/↑ inside the HUD walk the list; the walk stops at the ends rather
    /// than wrapping, matching the address bars everyone is used to.
    private func moveSuggestion(_ delta: Int) {
        guard !suggestions.isEmpty else { return }
        let row = suggestTable.selectedRow
        let next = row < 0
            ? (delta > 0 ? 0 : suggestions.count - 1)
            : min(max(row + delta, 0), suggestions.count - 1)
        guard next != row else { return }
        suggestTable.selectRowIndexes(IndexSet(integer: next), byExtendingSelection: false)
        suggestTable.scrollRowToVisible(next)
    }

    private func pickedSuggestionURL() -> URL? {
        let row = suggestTable.selectedRow
        guard !suggestPanel.isHidden, suggestions.indices.contains(row),
              let url = URL(string: suggestions[row].url) else { return nil }
        return url
    }

    @objc func openSelectedSuggestion(_ sender: Any?) {
        let row = suggestTable.clickedRow >= 0 ? suggestTable.clickedRow : suggestTable.selectedRow
        openSuggestion(at: row)
    }

    private func openSuggestion(at row: Int) {
        guard suggestions.indices.contains(row),
              let url = URL(string: suggestions[row].url) else { return }
        hideHUD()
        navigate(to: url)
    }

    func numberOfRows(in tableView: NSTableView) -> Int { suggestions.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard suggestions.indices.contains(row) else { return nil }
        let s = suggestions[row]
        let cell = NSTableCellView(frame: NSRect(x: 0, y: 0, width: tableView.frame.width, height: 28))

        let iconView = NSImageView(frame: NSRect(x: 10, y: 6, width: 16, height: 16))
        iconView.imageScaling = .scaleProportionallyUpOrDown
        iconView.wantsLayer = true
        iconView.layer?.cornerRadius = 3
        iconView.layer?.masksToBounds = true
        if let icon = s.icon {
            iconView.image = icon
        } else {
            // History entries carry no artwork; the generic mark keeps the
            // row's left edge aligned with the tiles that do.
            iconView.image = NSImage(systemSymbolName: "globe", accessibilityDescription: nil)
            iconView.contentTintColor = .secondaryLabelColor
        }
        cell.addSubview(iconView)

        // Title in the foreground, address dimmed after it — and for history,
        // which has no title, the address is all there is.
        let attr = NSMutableAttributedString()
        if let title = s.title, !title.isEmpty {
            attr.append(NSAttributedString(string: title, attributes: [
                .font: NSFont.systemFont(ofSize: 12.5, weight: .medium),
                .foregroundColor: NSColor.labelColor]))
            attr.append(NSAttributedString(string: "  —  ", attributes: [
                .font: NSFont.systemFont(ofSize: 12.5),
                .foregroundColor: NSColor.tertiaryLabelColor]))
        }
        attr.append(NSAttributedString(string: s.url, attributes: [
            .font: NSFont.systemFont(ofSize: 12.5),
            .foregroundColor: (s.title?.isEmpty == false) ? NSColor.secondaryLabelColor : NSColor.labelColor]))
        let text = NSTextField(labelWithString: "")
        text.attributedStringValue = attr
        text.lineBreakMode = .byTruncatingTail
        text.frame = NSRect(x: 34, y: 5, width: max(60, tableView.frame.width - 44), height: 18)
        text.autoresizingMask = [.width]
        cell.addSubview(text)
        cell.textField = text
        return cell
    }

    // MARK: Find in page (⌘F)

    @objc func findInPageAction(_ sender: Any?) {
        if !findBar.isHidden {
            window?.makeFirstResponder(findField)
            findField.selectText(nil)
            return
        }
        // The field opens with the page's current selection, the way every
        // other find bar does.
        webView.evaluateJavaScript("window.getSelection().toString()", in: nil,
                                   in: chromelessWorld) { [weak self] result in
            guard let self else { return }
            if case .success(let value) = result, let text = value as? String, !text.isEmpty {
                self.findField.stringValue = String(text.prefix(200))
            }
            self.presentFindBar()
        }
    }

    private func presentFindBar() {
        // Two floating fields at once is one too many.
        hideHUD()
        findBar.isHidden = false
        layoutOverlays()
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = 0.15
            findBar.animator().alphaValue = 1
        }
        window?.makeFirstResponder(findField)
        findField.selectText(nil)
        if !findField.stringValue.isEmpty { performFind(target: 0) }
    }

    func hideFindBar() {
        guard !findBar.isHidden else { return }
        clearFindInPage()
        findIndex = -1
        findCountLabel.stringValue = ""
        NSAnimationContext.runAnimationGroup({ ctx in
            ctx.duration = 0.15
            self.findBar.animator().alphaValue = 0
        }, completionHandler: { [weak self] in
            self?.findBar.isHidden = true
        })
        window?.makeFirstResponder(webView)
    }

    @objc func hideFindBarAction(_ sender: Any?) { hideFindBar() }

    @objc func findNextAction(_ sender: Any?) { stepFind(1) }
    @objc func findPreviousAction(_ sender: Any?) { stepFind(-1) }

    private func stepFind(_ delta: Int) {
        guard !findField.stringValue.isEmpty else { return }
        if findBar.isHidden { presentFindBar() }
        performFind(target: findIndex + delta)
    }

    /// Rescans the term and jumps to `target`. Every call rescans because the
    /// DOM may have shifted since the last one — a stale node range is worse
    /// than a wasted walk.
    private func performFind(target: Int) {
        let term = findField.stringValue
        guard !term.isEmpty else {
            clearFindInPage()
            updateFindLabel(index: -1, count: 0)
            return
        }
        let js = findEngineScript
            + "\n;(function(){var c=window.__clf,n=c.scan(\(jsStringLiteral(term)));"
            + "var i=c.at(\(target));return i+'/'+n;})()"
        webView.evaluateJavaScript(js, in: nil, in: chromelessWorld) { [weak self] result in
            var index = -1, count = 0
            if case .success(let value) = result, let s = value as? String {
                let parts = s.split(separator: "/").compactMap { Int($0) }
                if parts.count == 2 { index = parts[0]; count = parts[1] }
            }
            self?.updateFindLabel(index: index, count: count)
        }
    }

    private func clearFindInPage() {
        webView.evaluateJavaScript(findEngineScript + "\n;window.__clf.clear();",
                                   in: nil, in: chromelessWorld, completionHandler: nil)
    }

    private func updateFindLabel(index: Int, count: Int) {
        findIndex = index
        findCountLabel.stringValue = findField.stringValue.isEmpty ? ""
            : count == 0 ? "No results"
            : "\(index + 1)/\(count)"
        layoutOverlays()
    }

    /// A JS string literal for `term`, escaping handled by the JSON encoder.
    private func jsStringLiteral(_ s: String) -> String {
        guard let data = try? JSONEncoder().encode(s) else { return "\"\"" }
        return String(decoding: data, as: UTF8.self)
    }

    // MARK: Link hover bubble

    private func setLinkHover(_ url: URL?) {
        if let url {
            linkHoverLabel.stringValue = url.absoluteString
            layoutOverlays()
            linkHoverView.isHidden = false
            linkHoverView.animator().alphaValue = 1
        } else {
            NSAnimationContext.runAnimationGroup({ ctx in
                ctx.duration = 0.12
                self.linkHoverView.animator().alphaValue = 0
            }, completionHandler: { [weak self] in
                guard let self, self.linkHoverView.alphaValue == 0 else { return }
                self.linkHoverView.isHidden = true
            })
        }
    }

    // MARK: Selection translate

    private func handleTranslateMessage(_ body: [String: Any], from wv: BrowserWebView) {
        if body["dismiss"] as? Bool == true {
            dismissTranslate()
            return
        }
        guard TranslatePreference.isOn,
              let raw = body["text"] as? String,
              !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        func num(_ key: String) -> CGFloat {
            CGFloat((body[key] as? NSNumber)?.doubleValue ?? 0)
        }
        // The rect arrives in CSS pixels; the same zoom the link-hit test
        // divides out is multiplied back in here. The web view is flipped, so
        // CSS's top-down Y is already the view's Y.
        let scale = wv.pageZoom * wv.magnification
        guard scale > 0 else { return }
        var rect = NSRect(x: num("x") * scale, y: num("y") * scale,
                          width: max(num("w") * scale, 2), height: max(num("h") * scale, 2))
        rect = rect.intersection(wv.bounds)
        guard !rect.isNull, !rect.isEmpty else { return }
        // The system overlay WebKit's context-menu Translate uses is the
        // primary path; the AI stream only runs when that service is missing.
        if systemTranslate.show(text: raw, relativeTo: rect, of: wv) { return }
        translatePopover.show(relativeTo: rect, of: wv)
        translator.translate(
            raw,
            onUpdate: { [weak self] text, note in
                self?.translatePopover.update(text, note: note)
            },
            onFinish: { [weak self] error in
                guard let error else { return }
                self?.translatePopover.fail(error.localizedDescription)
            })
    }

    private func dismissTranslate() {
        translator.cancel()
        systemTranslate.close()
        translatePopover.close()
    }

    // MARK: Closed tabs and tab operations

    private func recordClosedTab(_ tab: Tab) {
        guard let u = tab.webView.url, u.scheme == "http" || u.scheme == "https" else { return }
        closedTabs.append(u)
        if closedTabs.count > 10 { closedTabs.removeFirst(closedTabs.count - 10) }
    }

    @objc func reopenClosedTabAction(_ sender: Any?) {
        guard let url = closedTabs.popLast() else { return }
        addTab(url: url)
    }

    private func duplicateTab(at index: Int) {
        // A start-page tab has no URL to copy — its twin is just a fresh one.
        addTab(url: tabs[index].webView.url)
    }

    private func moveTabToNewWindow(at index: Int) {
        let url = tabs[index].webView.url
        (NSApp.delegate as? AppDelegate)?.openWindow(
            profile: profile, url: url, isPrivate: isPrivate)
        // The tab moved rather than closed — it does not go on the reopen stack.
        closeTab(at: index, recordClosed: false)
    }

    private func closeOtherTabs(than index: Int) {
        guard confirmLeavingSessions(
            in: tabs.enumerated().filter { $0.offset != index }.map(\.element),
            verb: "Close") else { return }
        let keep = tabs[index]
        for (i, tab) in tabs.enumerated() where i != index {
            recordClosedTab(tab)
            tab.teardown()
        }
        tabs = [keep]
        activeIndex = 0
        refreshTabs()
    }

    private func closeTabsToRight(of index: Int) {
        guard index + 1 < tabs.count else { return }
        guard confirmLeavingSessions(
            in: Array(tabs[(index + 1)...]), verb: "Close") else { return }
        for tab in tabs[(index + 1)...] {
            recordClosedTab(tab)
            tab.teardown()
        }
        tabs.removeSubrange((index + 1)...)
        if activeIndex > index { activeIndex = index }
        refreshTabs()
    }

    private func buildTabContextMenu(for index: Int) -> NSMenu? {
        guard tabs.indices.contains(index) else { return nil }
        let menu = NSMenu()
        func add(_ title: String, _ op: Int, enabled: Bool = true) {
            let item = NSMenuItem(title: title, action: #selector(tabMenuAction(_:)),
                                  keyEquivalent: "")
            item.target = self
            item.tag = op
            item.representedObject = index
            item.isEnabled = enabled
            menu.addItem(item)
        }
        add("Duplicate Tab", 0)
        add("Move Tab to New Window", 1)
        menu.addItem(.separator())
        add("Close Tab", 2)
        add("Close Other Tabs", 3, enabled: tabs.count > 1)
        add("Close Tabs to the Right", 4, enabled: index < tabs.count - 1)
        return menu
    }

    @objc private func tabMenuAction(_ sender: NSMenuItem) {
        guard let index = sender.representedObject as? Int, tabs.indices.contains(index) else { return }
        switch sender.tag {
        case 0: duplicateTab(at: index)
        case 1: moveTabToNewWindow(at: index)
        case 2: closeTab(at: index)
        case 3: closeOtherTabs(than: index)
        case 4: closeTabsToRight(of: index)
        default: break
        }
    }

    // MARK: Favicons

    /// Refetches the tab's icon when the host changes. Icons are cached per
    /// host for the life of the window, so walking around one site costs one
    /// fetch, not one per page.
    private func updateFavicon(for tab: Tab, url: URL?) {
        let web = url?.scheme == "http" || url?.scheme == "https"
        let host = web ? url?.host?.lowercased() : nil
        guard tab.faviconHost != host else { return }
        tab.faviconHost = host
        let index = tabs.firstIndex { $0 === tab }
        guard let host, let url else {
            tab.favicon = nil
            tabBar.update(iconAt: index, to: nil)
            return
        }
        if let cached = faviconCache[host] {
            tab.favicon = cached
            tabBar.update(iconAt: index, to: cached)
            return
        }
        tab.favicon = nil
        tabBar.update(iconAt: index, to: nil)
        QuickAccessIconFetcher.fetch(for: url) { [weak self, weak tab] dataURI, _ in
            guard let self, let image = self.imageFromDataURI(dataURI) else { return }
            self.faviconCache[host] = image
            // The tab may have moved on while the fetch was out — the cache
            // entry is still right, the icon on that tab would not be.
            guard tab?.faviconHost == host else { return }
            tab?.favicon = image
            self.tabBar.update(iconAt: self.tabs.firstIndex { $0 === tab }, to: image)
        }
    }

    // MARK: Site tweaks

    /// Grants the current page whatever its host's `siteTweaks` entry allows.
    /// Both switches are WebKit internals — guarded the same way the rest of
    /// this file's private calls are: if the selector is not there, the site
    /// just gets stock behavior.
    private func applySiteTweaks(to tab: Tab) {
        let host = tab.webView.url?.host?.lowercased() ?? ""
        let tweaks = tweaksForHost(host)
        let stayLive = tweaks?.backgroundWork == true
        let wv = tab.webView
        // Occlusion off: a covered or minimized window no longer suspends
        // rendering, so a remote session keeps painting unseen.
        if wv.responds(to: Selector(("_setWindowOcclusionDetectionEnabled:"))) {
            wv.setValue(!stayLive, forKey: "windowOcclusionDetectionEnabled")
        }
        // Timer throttling off: a non-front tab keeps its event loop at full
        // speed instead of once-per-second.
        let prefs = wv.configuration.preferences
        if prefs.responds(to: Selector(("_setHiddenPageDOMTimerThrottlingEnabled:"))) {
            prefs.setValue(!stayLive, forKey: "hiddenPageDOMTimerThrottlingEnabled")
        }
        // A two-finger swipe back lands wherever the session's auth redirect
        // came from — a dead page. On session hosts the gesture is off.
        wv.allowsBackForwardNavigationGestures = tweaks?.appMode != true
        refreshKeepAwake()
    }

    /// Live sessions die with their page, so anything that unloads one asks
    /// first. `verb` fills both the sentence and the confirm button.
    private func confirmLeavingSessions(in doomedTabs: [Tab], verb: String) -> Bool {
        let hosts = doomedTabs
            .filter { isSessionHost($0.webView.url) }
            .compactMap { $0.webView.url?.host }
        guard !hosts.isEmpty else { return true }
        let alert = NSAlert()
        alert.messageText = "\(verb) disconnects the session on \(hosts.joined(separator: ", "))."
        alert.addButton(withTitle: verb)
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }

    /// While a keep-awake site is the active tab of a visible window, hold an
    /// activity that blocks App Nap, idle system sleep, and display sleep —
    /// the three things that otherwise freeze a session left running. It is
    /// released the moment the tab, the page, or the window no longer asks.
    private func refreshKeepAwake() {
        let host = activeTab.webView.url?.host?.lowercased() ?? ""
        let wants = tweaksForHost(host)?.keepAwake == true && window?.isVisible == true
        if wants && keepAwakeActivity == nil {
            keepAwakeActivity = ProcessInfo.processInfo.beginActivity(
                options: [.userInitiated, .idleDisplaySleepDisabled],
                reason: "Active remote session")
        } else if !wants, let activity = keepAwakeActivity {
            ProcessInfo.processInfo.endActivity(activity)
            keepAwakeActivity = nil
        }
    }

    // MARK: Site zoom

    /// `pageZoom` is a property of the web view, not the page — left alone, a
    /// zoom picked on one site follows the tab to every site after it. This
    /// map makes zoom per site the way other browsers do: keyed by host (port
    /// included, so `localhost:3000` and `:8080` are different sites), kept in
    /// UserDefaults so every window shares it, applied on each committed
    /// navigation, and an absent key meaning 100%.

    private func siteZoomKey(for url: URL?) -> String? {
        guard let url else { return nil }
        // Local documents have no host; they share one zoom like one origin.
        if url.isFileURL { return "file" }
        guard let host = url.host?.lowercased(), !host.isEmpty else { return nil }
        if let port = url.port { return "\(host):\(port)" }
        return host
    }

    private func applySavedZoom(to wv: WKWebView) {
        var zoom = CGFloat(1)
        if let key = siteZoomKey(for: wv.url),
           let saved = UserDefaults.standard.dictionary(forKey: siteZoomDefaultsKey)?[key] as? Double {
            zoom = CGFloat(saved)
        }
        if wv.pageZoom != zoom { wv.pageZoom = zoom }
    }

    private func saveZoom(for wv: WKWebView) {
        // A private window reads the shared map but never adds to it — an
        // entry is a record that the site was visited.
        guard !isPrivate, let key = siteZoomKey(for: wv.url) else { return }
        var zooms = UserDefaults.standard.dictionary(forKey: siteZoomDefaultsKey) as? [String: Double] ?? [:]
        if abs(wv.pageZoom - 1.0) < 0.001 {
            zooms.removeValue(forKey: key)
        } else {
            zooms[key] = Double(wv.pageZoom)
        }
        UserDefaults.standard.set(zooms, forKey: siteZoomDefaultsKey)
    }

    /// Warms DNS + TCP + TLS inside WebKit's own networking process for the
    /// sites opened most often, so the first navigation skips the handshake.
    /// A URLSession warm-up would not do this — WebKit keeps its own
    /// connection pool in a separate process.
    private func preconnectFrequentHosts() {
        let sel = Selector(("_preconnectToServer:"))
        guard webView.responds(to: sel) else { return }
        var origins = Set<String>()
        for link in quickAccessStore.links {
            guard let u = URL(string: link.url), u.scheme == "https", let host = u.host
            else { continue }
            origins.insert("https://\(host)")
        }
        // Patterns and comment keys can't be preconnected — only literal
        // hosts warm a socket.
        for key in Array(siteTweaks.keys) + Array(userSiteTweaks().keys)
        where !key.contains("*") && !key.hasPrefix("_") {
            origins.insert("https://\(key)")
        }
        for origin in origins {
            if let u = URL(string: origin) { _ = webView.perform(sel, with: u) }
        }
    }

    // MARK: Permission prompts

    /// One sheet at a time, one answer per site per window. WebKit asks the
    /// delegate for camera, microphone, location, and notification access; with
    /// no delegate method the request is refused outright, which is why some
    /// sites simply look broken.
    private func askPermission(_ kind: String, host: String, note: String? = nil,
                               answer: @escaping (Bool) -> Void) {
        if launchOptions.snap != nil { answer(false); return }
        let key = kind + "|" + host
        if let remembered = permissionChoices[key] {
            answer(remembered)
            return
        }
        let task = { [weak self] in
            guard let self, let window = self.window else { answer(false); return }
            self.permissionPromptUp = true
            let alert = NSAlert()
            alert.messageText = "Allow “\(host)” to use your \(kind)?"
            alert.informativeText = note
                ?? "The choice is remembered for this window, not between launches."
            alert.addButton(withTitle: "Allow")
            alert.addButton(withTitle: "Don’t Allow")
            // The floating HUD would sit under the sheet.
            self.hideHUD()
            alert.beginSheetModal(for: window) { response in
                let allowed = response == .alertFirstButtonReturn
                self.permissionChoices[key] = allowed
                self.permissionPromptUp = false
                answer(allowed)
                self.pumpPermissionQueue()
            }
        }
        if permissionPromptUp {
            permissionQueue.append(task)
        } else {
            task()
        }
    }

    private func pumpPermissionQueue() {
        guard !permissionPromptUp, !permissionQueue.isEmpty else { return }
        permissionQueue.removeFirst()()
    }

    private func permissionHost(_ webView: WKWebView, origin: WKSecurityOrigin) -> String {
        origin.host.isEmpty ? (webView.url?.host ?? "this page") : origin.host
    }

    // Camera and microphone — public API since macOS 12.
    func webView(_ webView: WKWebView, requestMediaCapturePermissionFor origin: WKSecurityOrigin,
                 initiatedByFrame frame: WKFrameInfo, type: WKMediaCaptureType,
                 decisionHandler: @escaping (WKPermissionDecision) -> Void) {
        let kind = type == .camera ? "camera"
            : type == .microphone ? "microphone"
            : "camera and microphone"
        askPermission(kind, host: permissionHost(webView, origin: origin)) {
            decisionHandler($0 ? .grant : .deny)
        }
    }

    // Geolocation — public since macOS 27. The two underscore spellings below
    // are the same request on older systems, where it is still SPI; whichever
    // one WebKit calls lands in the same prompt.
    @available(macOS 27.0, *)
    func webView(_ webView: WKWebView, requestGeolocationPermissionFor origin: WKSecurityOrigin,
                 initiatedByFrame frame: WKFrameInfo,
                 decisionHandler: @escaping (WKPermissionDecision) -> Void) {
        askPermission("location", host: permissionHost(webView, origin: origin)) {
            decisionHandler($0 ? .grant : .deny)
        }
    }

    func _webView(_ webView: WKWebView, requestGeolocationPermissionForOrigin origin: WKSecurityOrigin,
                  initiatedByFrame frame: WKFrameInfo,
                  decisionHandler: @escaping (WKPermissionDecision) -> Void) {
        askPermission("location", host: permissionHost(webView, origin: origin)) {
            decisionHandler($0 ? .grant : .deny)
        }
    }

    func _webView(_ webView: WKWebView, requestGeolocationPermissionForFrame frame: WKFrameInfo,
                  decisionHandler: @escaping (Bool) -> Void) {
        askPermission("location", host: webView.url?.host ?? "this page", answer: decisionHandler)
    }

    // Notifications — still SPI. Allowing tells the site it may send; where the
    // notifications would go is a question Chromeless does not answer yet, and
    // the prompt says so instead of faking delivery.
    func _webView(_ webView: WKWebView, requestNotificationPermissionForSecurityOrigin origin: WKSecurityOrigin,
                  decisionHandler: @escaping (Bool) -> Void) {
        askPermission("notifications", host: permissionHost(webView, origin: origin),
                      note: "Chromeless can’t display notifications yet — Allow only tells the site it may send them.",
                      answer: decisionHandler)
    }

    // beforeunload — the "leave site?" confirm a page raises on its way out.
    // Unhandled, the navigation just vanishes with whatever was being typed.
    func _webView(_ webView: WKWebView, runBeforeUnloadConfirmPanelWithMessage message: String,
                  initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        if launchOptions.snap != nil { completionHandler(true); return }
        let alert = NSAlert()
        alert.messageText = "Leave this page?"
        alert.informativeText = message.isEmpty
            ? "Changes you made may not be saved."
            : message
        alert.addButton(withTitle: "Leave")
        alert.addButton(withTitle: "Stay")
        hideHUD()
        if let window {
            alert.beginSheetModal(for: window) {
                completionHandler($0 == .alertFirstButtonReturn)
            }
        } else {
            completionHandler(alert.runModal() == .alertFirstButtonReturn)
        }
    }

    // MARK: Toast

    func showToast(_ text: String) {
        toastLabel.stringValue = text
        layoutOverlays()
        toastHide?.cancel()
        toastView.isHidden = false
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = 0.15
            toastView.animator().alphaValue = 1
        }
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            NSAnimationContext.runAnimationGroup({ ctx in
                ctx.duration = 0.4
                self.toastView.animator().alphaValue = 0
            }, completionHandler: { self.toastView.isHidden = true })
        }
        toastHide = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.7, execute: work)
    }

    // MARK: Snapshots

    private func writePNG(from image: NSImage, to path: String) -> (Int, Int)? {
        guard let cg = image.cgImage(forProposedRect: nil, context: nil, hints: nil),
              let data = NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:])
        else { return nil }
        do {
            try data.write(to: URL(fileURLWithPath: path))
            return (cg.width, cg.height)
        } catch {
            return nil
        }
    }

    private func runSnapJob(_ job: SnapJob) {
        DispatchQueue.main.asyncAfter(deadline: .now() + job.wait) { [weak self] in
            guard let self else { exit(3) }
            self.webView.takeSnapshot(with: nil) { image, error in
                guard let image, let dims = self.writePNG(from: image, to: job.path) else {
                    fputs("chromeless: snapshot failed: \(error?.localizedDescription ?? "could not write PNG")\n", stderr)
                    exit(3)
                }
                print("saved \(job.path) (\(dims.0)x\(dims.1) px)")
                exit(0)
            }
        }
    }

    // MARK: Menu actions

    @objc func openLocation(_ sender: Any?) { showHUD() }

    @objc func reloadPage(_ sender: Any?) {
        if activeTab.onStartPage { loadStartPage(); return }
        guard confirmLeavingSessions(in: [activeTab], verb: "Reload") else { return }
        webView.reload()
    }

    @objc func hardReloadPage(_ sender: Any?) {
        if activeTab.onStartPage { loadStartPage(); return }
        guard confirmLeavingSessions(in: [activeTab], verb: "Reload") else { return }
        webView.reloadFromOrigin()
    }

    // WebKit exposes no public way to open the inspector — `isInspectable`
    // only unlocks it for Safari's Develop menu and the context menu. The
    // private `_inspector` handle is what Safari itself drives; every hop is
    // guarded so a rename in a future macOS degrades to a toast, not a crash.
    @objc func toggleWebInspector(_ sender: Any?) {
        guard let inspector = webInspector else {
            showToast("Web Inspector unavailable")
            return
        }
        let action = NSSelectorFromString(isWebInspectorVisible ? "hide" : "show")
        guard inspector.responds(to: action) else {
            showToast("Web Inspector unavailable")
            return
        }
        _ = inspector.perform(action)
    }

    private var webInspector: NSObject? {
        let sel = NSSelectorFromString("_inspector")
        guard webView.responds(to: sel) else { return nil }
        return webView.perform(sel)?.takeUnretainedValue() as? NSObject
    }

    private var isWebInspectorVisible: Bool {
        let sel = NSSelectorFromString("isVisible")
        guard let inspector = webInspector, inspector.responds(to: sel) else { return false }
        return (inspector.value(forKey: "isVisible") as? Bool) ?? false
    }

    @objc func goBackAction(_ sender: Any?) {
        guard !isSessionHost(webView.url) else { return }
        webView.goBack()
    }
    @objc func goForwardAction(_ sender: Any?) {
        guard !isSessionHost(webView.url) else { return }
        webView.goForward()
    }

    @objc func zoomInPage(_ sender: Any?) {
        webView.pageZoom = min(webView.pageZoom * 1.1, 5.0)
        saveZoom(for: webView)
    }

    @objc func zoomOutPage(_ sender: Any?) {
        webView.pageZoom = max(webView.pageZoom / 1.1, 0.25)
        saveZoom(for: webView)
    }

    @objc func resetZoom(_ sender: Any?) {
        webView.pageZoom = 1.0
        saveZoom(for: webView)
    }

    @objc func saveSnapshot(_ sender: Any?) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd 'at' HH.mm.ss"
        let name = "chromeless \(formatter.string(from: Date())).png"
        let desktop = FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask)[0]
        let path = desktop.appendingPathComponent(name).path
        webView.takeSnapshot(with: nil) { [weak self] image, _ in
            guard let self else { return }
            if let image, self.writePNG(from: image, to: path) != nil {
                self.showToast("Saved “\(name)” to Desktop")
            } else {
                self.showToast("Snapshot failed")
            }
        }
    }

    @objc func copyPageURL(_ sender: Any?) {
        guard let u = webView.url, u.absoluteString != "about:blank" else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(u.absoluteString, forType: .string)
        showToast("URL copied")
    }

    @objc func togglePin(_ sender: Any?) {
        guard let window else { return }
        let pinned = window.level == .floating
        window.level = pinned ? .normal : .floating
        showToast(pinned ? "Unpinned" : "Pinned on top")
    }

    @objc func showHelpPage(_ sender: Any?) {
        guard confirmLeavingSessions(in: [activeTab], verb: "Leave") else { return }
        loadStartPage()
    }

    @objc func goHome(_ sender: Any?) {
        guard confirmLeavingSessions(in: [activeTab], verb: "Leave") else { return }
        loadStartPage()
    }

    // MARK: Ad blocking

    @objc func toggleSiteBlocking(_ sender: Any?) {
        guard let url = webView.url, let domain = AdBlockManager.domain(for: url) else {
            showToast("Nothing to allow or block here")
            return
        }
        let blocking = adBlockManager.isBlocking(url)
        showToast(blocking ? "Ads allowed on \(domain)" : "Blocking ads on \(domain)")
        adBlockManager.setBlocking(!blocking, for: url) { [weak self] in
            self?.reloadPage(nil)
        }
    }

    @objc func pickElementToBlock(_ sender: Any?) {
        guard !activeTab.onStartPage, webView.url != nil else {
            showToast("Open a page first")
            return
        }
        // The script's own return value is undefined, which WebKit reports as an
        // error; a trailing literal keeps the completion honest about failures
        // that actually matter.
        // Injected into our own content world, the same one its message handler is
        // registered in: the picker talks to the app, and the page cannot join in.
        webView.evaluateJavaScript(adBlockPickerScript + "\ntrue;", in: nil,
                                   in: chromelessWorld) { [weak self] result in
            guard case .failure(let error) = result else { return }
            self?.showToast("Picker failed — \(error.localizedDescription)")
        }
    }

    @objc func showAdBlockSettings(_ sender: Any?) {
        AdBlockSettingsWindowController.shared.present()
    }

    // Wipes one domain out of this window's data store — cookies, cache, local
    // storage, everything WebKit keeps — plus the history the profile recorded
    // for it. The field opens prefilled with the current page's domain, since
    // "clear this site" is the common case; typing any domain works too.
    @objc func clearSiteData(_ sender: Any?) {
        let alert = NSAlert()
        alert.messageText = "Clear Site Data"
        alert.informativeText = isPrivate
            ? "Deletes cookies, cache, and site storage for one domain. Private windows record no history."
            : "Deletes cookies, cache, site storage, and history for one domain in the “\(profile.name)” profile."
        alert.addButton(withTitle: "Clear")
        alert.addButton(withTitle: "Cancel")
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        field.placeholderString = "example.com"
        field.stringValue = AdBlockManager.domain(for: webView.url) ?? ""
        alert.accessoryView = field
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard let domain = siteDomain(from: field.stringValue) else {
            let typed = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if !typed.isEmpty { showToast("“\(typed)” is not a domain") }
            return
        }
        let profile = self.profile
        let isPrivate = self.isPrivate
        let dataStore = webView.configuration.websiteDataStore
        let types = WKWebsiteDataStore.allWebsiteDataTypes()
        dataStore.fetchDataRecords(ofTypes: types) { [weak self] records in
            // A record's displayName is a host; reducing both sides to the
            // registrable domain covers every subdomain at once.
            let matches = records.filter { registrableDomain(for: $0.displayName) == domain }
            dataStore.removeData(ofTypes: types, for: matches) { [weak self] in
                DispatchQueue.main.async { [weak self] in
                    if !isPrivate {
                        profileStore.removeHistory(forDomain: domain, in: profile)
                    }
                    guard let self else { return }
                    self.faviconCache = self.faviconCache.filter {
                        registrableDomain(for: $0.key) != domain
                    }
                    self.permissionChoices = self.permissionChoices.filter {
                        $0.key.split(separator: "|").last
                            .flatMap { registrableDomain(for: String($0)) } != domain
                    }
                    // Reloading a page on the wiped domain is the visible half
                    // of the feedback — a logged-out page says more than a toast.
                    if AdBlockManager.domain(for: self.webView.url) == domain {
                        self.reloadPage(nil)
                    }
                    self.showToast(matches.isEmpty
                        ? "No stored data for \(domain)"
                        : "Cleared data for \(domain)")
                }
            }
        }
    }

    @objc func newTabAction(_ sender: Any?) { addTab(url: nil) }

    @objc func closeTabAction(_ sender: Any?) { closeTab(at: activeIndex) }

    @objc func showNextTab(_ sender: Any?) {
        guard tabs.count > 1 else { return }
        selectTab(at: (activeIndex + 1) % tabs.count)
    }

    @objc func showPreviousTab(_ sender: Any?) {
        guard tabs.count > 1 else { return }
        selectTab(at: (activeIndex - 1 + tabs.count) % tabs.count)
    }

    // Tag 1…8 jump to that tab; tag 9 jumps to the last one, as browsers do.
    @objc func selectTabByNumber(_ sender: NSMenuItem) {
        selectTab(at: sender.tag == 9 ? tabs.count - 1 : sender.tag - 1)
    }

    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        switch menuItem.action {
        case #selector(goBackAction(_:)):
            return webView.canGoBack && !isSessionHost(webView.url)
        case #selector(goForwardAction(_:)):
            return webView.canGoForward && !isSessionHost(webView.url)
        case #selector(showNextTab(_:)), #selector(showPreviousTab(_:)):
            return tabs.count > 1
        case #selector(selectTabByNumber(_:)):
            return menuItem.tag == 9 ? tabs.count > 1 : menuItem.tag <= tabs.count
        case #selector(closeTabAction(_:)):
            menuItem.title = tabs.count > 1 ? "Close Tab" : "Close Window"
            return true
        case #selector(reopenClosedTabAction(_:)):
            return !closedTabs.isEmpty
        case #selector(findNextAction(_:)), #selector(findPreviousAction(_:)):
            return !findField.stringValue.isEmpty
        case #selector(copyPageURL(_:)):
            return webView.url != nil && webView.url?.absoluteString != "about:blank"
        case #selector(togglePin(_:)):
            menuItem.state = window?.level == .floating ? .on : .off
            return true
        case #selector(toggleSiteBlocking(_:)):
            menuItem.state = adBlockManager.isBlocking(webView.url) ? .on : .off
            return adBlockManager.settings.enabled && AdBlockManager.domain(for: webView.url) != nil
        case #selector(pickElementToBlock(_:)):
            return !activeTab.onStartPage && webView.url != nil
        case #selector(toggleWebInspector(_:)):
            menuItem.title = isWebInspectorVisible ? "Hide Web Inspector" : "Show Web Inspector"
            // Disabled items match no key equivalent — on a session host F12
            // falls through the menu into the page, where it belongs.
            return webInspector != nil && !isSessionHost(webView.url)
        case #selector(toggleAISidebar(_:)):
            menuItem.state = aiSidebarShown ? .on : .off
            return true
        case #selector(toggleAIButton(_:)):
            menuItem.state = AIButtonPreference.isOn ? .on : .off
            return true
        case #selector(toggleTranslateOnShift(_:)):
            menuItem.state = TranslatePreference.isOn ? .on : .off
            return true
        case #selector(toggleProfileChip(_:)):
            menuItem.state = ProfileChipPreference.isOn ? .on : .off
            return true
        default: return true
        }
    }

    // MARK: NSWindowDelegate

    func windowDidEnterFullScreen(_ notification: Notification) { setTrafficLights(visible: true) }
    func windowDidExitFullScreen(_ notification: Notification) { setTrafficLights(visible: false) }

    // Minimizing or hiding the app flips isVisible — a keep-awake session only
    // holds the display while the window can actually be seen.
    func windowDidChangeOcclusionState(_ notification: Notification) { refreshKeepAwake() }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        // Quit already asked once for every window — asking again per window
        // would double-prompt on the way out.
        if (NSApp.delegate as? AppDelegate)?.sessionCloseApproved == true { return true }
        return confirmLeavingSessions(in: tabs, verb: "Close")
    }

    func windowWillClose(_ notification: Notification) {
        if let activity = keepAwakeActivity {
            ProcessInfo.processInfo.endActivity(activity)
            keepAwakeActivity = nil
        }
        if let monitor = mouseMonitor { NSEvent.removeMonitor(monitor) }
        if let monitor = keyMonitor { NSEvent.removeMonitor(monitor) }
        mouseMonitor = nil
        keyMonitor = nil
        dismissTranslate()
        downloadsHide?.cancel()
        downloadsHide = nil
        for observer in downloadsObservers { NotificationCenter.default.removeObserver(observer) }
        downloadsObservers.removeAll()
        if let observer = quickAccessObserver { NotificationCenter.default.removeObserver(observer) }
        quickAccessObserver = nil
        if let observer = aiSettingsObserver { NotificationCenter.default.removeObserver(observer) }
        aiSettingsObserver = nil
        if let observer = aiButtonObserver { NotificationCenter.default.removeObserver(observer) }
        aiButtonObserver = nil
        if let observer = profileChipObserver { NotificationCenter.default.removeObserver(observer) }
        profileChipObserver = nil
        // Downloads outlive their window on purpose: the manager holds the
        // delegate, so tearing down these tabs does not stop a transfer.
        for tab in tabs { tab.teardown() }
        onClose?()
    }

    // MARK: WKNavigationDelegate

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
        let u = webView.url?.absoluteString
        if u != nil && u != "about:blank" { tab(for: webView)?.onStartPage = false }
        if let t = tab(for: webView) { applySiteTweaks(to: t) }
        applySavedZoom(to: webView)
        // Whatever the pointer was over is gone with the old page.
        if tab(for: webView) === activeTab { setLinkHover(nil) }
        // The selection — and the rect it was measured in — is gone too.
        if tab(for: webView) === activeTab { dismissTranslate() }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard let finished = tab(for: webView) else { return }
        tabBar.update(titleAt: tabs.firstIndex { $0 === finished }, to: finished.displayTitle)
        guard finished === activeTab else { return }
        // A new page means new context for the question being typed about it.
        if aiSidebarShown { captureAIPageContext() }
        // The find term survives a navigation; the matches do not. Rescan on
        // the new page, like every other find bar.
        if !findBar.isHidden && !findField.stringValue.isEmpty {
            performFind(target: 0)
        }
        if let job = snapJob {
            snapJob = nil
            runSnapJob(job)
        } else if finished.onStartPage {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
                guard let self, self.activeTab.onStartPage,
                      self.window?.isKeyWindow == true else { return }
                self.showHUD()
            }
        }
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        handleLoadError(error, in: webView)
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        handleLoadError(error, in: webView)
    }

    private func handleLoadError(_ error: Error, in webView: WKWebView) {
        let e = error as NSError
        // Ignore cancelled loads and "frame load interrupted" (downloads, redirects).
        if e.code == NSURLErrorCancelled || e.code == 102 { return }
        if launchOptions.snap != nil {
            fputs("chromeless: load failed: \(e.localizedDescription)\n", stderr)
            exit(1)
        }
        // The toast reports on the page you are looking at, so a background
        // tab failing quietly keeps its error state until you switch to it.
        guard tab(for: webView) === activeTab else { return }
        showToast("Couldn’t load — \(e.localizedDescription)")
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        // A crashed content process leaves a dead white tab; reload brings it back.
        webView.reload()
    }

    // Password-style challenges — Basic, Digest, and NTLM, the last being what
    // "Windows login" on intranet sites and on-prem Exchange/ADFS actually is —
    // need credentials only the user can supply; WebKit's default handling just
    // answers with a 401. Negotiate, client certificates, and server trust stay
    // with the system.
    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge,
                 completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodHTTPBasic,
             NSURLAuthenticationMethodHTTPDigest,
             NSURLAuthenticationMethodNTLM where launchOptions.snap == nil:
            promptForCredentials(webView: webView, challenge: challenge,
                                 completionHandler: completionHandler)
        default:
            completionHandler(.performDefaultHandling, nil)
        }
    }

    private func promptForCredentials(webView: WKWebView, challenge: URLAuthenticationChallenge,
                                      completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // A rejected password re-arms the same challenge; after a few refusals
        // let the server render its own 401 page rather than loop the sheet.
        guard challenge.previousFailureCount < 3 else {
            completionHandler(.rejectProtectionSpace, nil)
            return
        }
        let space = challenge.protectionSpace
        let alert = NSAlert()
        alert.messageText = "Sign in to \(space.host)"
        alert.informativeText = space.realm.map { "Realm: \($0)" }
            ?? "This site requires a username and password."
        let userField = NSTextField(frame: NSRect(x: 0, y: 30, width: 240, height: 22))
        let passField = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 240, height: 22))
        userField.placeholderString = "Username"
        passField.placeholderString = "Password"
        if let proposed = challenge.proposedCredential, let name = proposed.user {
            userField.stringValue = name
        }
        let fields = NSView(frame: NSRect(x: 0, y: 0, width: 240, height: 52))
        fields.addSubview(userField)
        fields.addSubview(passField)
        alert.accessoryView = fields
        alert.addButton(withTitle: "Sign In")
        alert.addButton(withTitle: "Cancel")
        // The floating HUD would sit under the sheet.
        hideHUD()
        let finish: (NSApplication.ModalResponse) -> Void = { response in
            guard response == .alertFirstButtonReturn, !userField.stringValue.isEmpty else {
                // Rejecting the space stops WebKit from re-asking and lets the
                // server's 401 page through.
                completionHandler(.rejectProtectionSpace, nil)
                return
            }
            let credential = URLCredential(user: userField.stringValue,
                                           password: passField.stringValue,
                                           persistence: .forSession)
            completionHandler(.useCredential, credential)
        }
        if let window = webView.window ?? self.window {
            alert.beginSheetModal(for: window, completionHandler: finish)
        } else {
            finish(alert.runModal())
        }
    }

    private func exitForSnapDownload() -> Never {
        fputs("chromeless: page attempted to download a file during --snap\n", stderr)
        exit(1)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        // The user agent is a property of the next load, not of this one —
        // crossing into or out of a spoofed host means canceling the first
        // attempt and starting it again under the right agent.
        if navigationAction.targetFrame?.isMainFrame != false,
           let url = navigationAction.request.url,
           let host = url.host?.lowercased(),
           ["http", "https"].contains(url.scheme ?? "") {
            let wantUA = tweaksForHost(host)?.chromeUserAgent == true ? chromeUserAgentString : nil
            // The getter reports "" for "no override" on newer WebKit, not nil —
            // comparing raw would restart every navigation forever.
            let haveUA = webView.customUserAgent?.isEmpty == false ? webView.customUserAgent : nil
            if haveUA != wantUA {
                webView.customUserAgent = wantUA
                decisionHandler(.cancel)
                webView.load(navigationAction.request)
                return
            }
        }
        // Hand non-web schemes (mailto:, facetime:, app links…) to the system — but
        // only when a click asked for it. Script-driven navigation to a scheme is
        // how a page launches another app behind the user's back, so that one gets
        // asked about instead.
        if let url = navigationAction.request.url, let scheme = url.scheme?.lowercased(),
           !["http", "https", "file", "about", "data", "blob", "javascript"].contains(scheme) {
            if navigationAction.navigationType == .linkActivated
                || navigationAction.navigationType == .formSubmitted {
                NSWorkspace.shared.open(url)
            } else {
                confirmExternalOpen(url)
            }
            decisionHandler(.cancel)
            return
        }
        if navigationAction.shouldPerformDownload {
            if launchOptions.snap != nil { exitForSnapDownload() }
            pendingDownloadWantsPanel = navigationAction.modifierFlags.contains(.option)
            decisionHandler(.download)
            return
        }
        // Remember the modifier even for links that only turn out to be
        // downloads once the response headers arrive.
        pendingDownloadWantsPanel = navigationAction.modifierFlags.contains(.option)
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        let disposition = ((navigationResponse.response as? HTTPURLResponse)?
            .value(forHTTPHeaderField: "Content-Disposition") ?? "").lowercased()
        if !navigationResponse.canShowMIMEType || disposition.contains("attachment") {
            if launchOptions.snap != nil { exitForSnapDownload() }
            decisionHandler(.download)
            return
        }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
        beginDownload(download, from: webView)
    }

    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
        beginDownload(download, from: webView)
    }

    /// Asks before letting a page hand a URL to another app. One at a time: a page
    /// that fires a hundred of these gets one sheet, not a hundred.
    private func confirmExternalOpen(_ url: URL) {
        guard let window, !isConfirmingExternalOpen else { return }
        isConfirmingExternalOpen = true
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Open this in another app?"
        alert.informativeText = "This page asked macOS to open:\n\n\(url.absoluteString)\n\n"
            + "Nothing was clicked, so the page asked for this on its own."
        alert.addButton(withTitle: "Open")
        alert.addButton(withTitle: "Cancel")
        alert.beginSheetModal(for: window) { [weak self] response in
            self?.isConfirmingExternalOpen = false
            guard response == .alertFirstButtonReturn else { return }
            NSWorkspace.shared.open(url)
        }
    }

    private func beginDownload(_ download: WKDownload, from webView: WKWebView) {
        if launchOptions.snap != nil { exitForSnapDownload() }
        let wantsPanel = pendingDownloadWantsPanel
        pendingDownloadWantsPanel = false
        downloadManager.attach(download, from: webView, wantsSavePanel: wantsPanel)
        if !wantsPanel { showDownloadsPanel(pinned: false) }
    }

    // MARK: WKUIDelegate

    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        // --snap is a one-shot screenshot: never fan out into tabs.
        if launchOptions.snap != nil {
            if let url = navigationAction.request.url { webView.load(URLRequest(url: url)) }
            return nil
        }
        // Background opening is not decided here. A middle-click never reaches
        // this method — the page script cancels it and reports the href instead
        // — and ⌘-click never reaches the page at all, because `BrowserWebView`
        // claims ⌘ for dragging the window.
        // The configuration WebKit hands over shares the opener's session and
        // process but not this preference — reset it or a sign-in popup could
        // not chain a second popup (an MFA prompt, an account picker) of its own.
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = true
        // Handing back a live web view lets WebKit drive the load itself, so
        // window.open + document.write popups work, not just plain links.
        // A popup born of an AI tab is still the agent's page doing the
        // asking, so it keeps agent ownership — and gets the instrumentation
        // and the orange marking its parent had. It also stays in the
        // background like every other agent birth; activating it would take
        // the user's foreground. The configuration WebKit hands over carries
        // the opener's user content controller, so the handler is already on
        // it — adding one by the same name crashes, hence remove-first (a
        // no-op when absent) and membership checks for the scripts.
        let agentPopup = tab(for: webView)?.isAgent == true
        if agentPopup {
            let ucc = configuration.userContentController
            ucc.removeScriptMessageHandler(forName: AgentLogRouter.messageName)
            ucc.add(AgentLogRouter.shared, name: AgentLogRouter.messageName)
            let existing = ucc.userScripts.map(\.source)
            if !existing.contains(agentProbeScript) {
                ucc.addUserScript(WKUserScript(
                    source: agentProbeScript, injectionTime: .atDocumentStart,
                    forMainFrameOnly: false))
            }
            if !existing.contains(agentRailScript) {
                ucc.addUserScript(WKUserScript(
                    source: agentRailScript, injectionTime: .atDocumentStart,
                    forMainFrameOnly: true))
            }
        }
        return addTab(url: nil, configuration: configuration,
                      activate: !agentPopup, agent: agentPopup).webView
    }

    func webViewDidClose(_ webView: WKWebView) {
        // WebKit forwards window.close() only for pages a script itself opened —
        // which is to say, sign-in popups finishing their handshake. Close the
        // tab and hand the window back to the opener, which by now is usually
        // already signed in. When the popup outlived its opener and is the last
        // tab, closeTab performs the window close itself. A popup finishing its
        // job is not a tab the user closed — it stays off the reopen stack.
        guard let index = tabs.firstIndex(where: { $0.webView === webView }) else { return }
        closeTab(at: index, recordClosed: false)
    }

    // SPI from WKUIDelegatePrivate: WebKit offers the context menu it built
    // and shows whatever comes back — nil shows nothing at all. On a live
    // session the right-click belongs to the page; the browser's items are
    // noise, and half of them (Back, Reload) would kill the session anyway.
    @objc(_webView:getContextMenuFromProposedMenu:forElement:userInfo:completionHandler:)
    func webView(_ webView: WKWebView, getContextMenuFromProposedMenu menu: NSMenu,
                 forElement elementInfo: Any, userInfo: Any?,
                 completionHandler: @escaping (NSMenu?) -> Void) {
        completionHandler(isSessionHost(webView.url) ? nil : menu)
    }

    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let alert = NSAlert()
        alert.messageText = message
        alert.addButton(withTitle: "OK")
        alert.runModal()
        completionHandler()
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let alert = NSAlert()
        alert.messageText = message
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        completionHandler(alert.runModal() == .alertFirstButtonReturn)
    }

    func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String,
                 defaultText: String?, initiatedByFrame frame: WKFrameInfo,
                 completionHandler: @escaping (String?) -> Void) {
        let alert = NSAlert()
        alert.messageText = prompt
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        field.stringValue = defaultText ?? ""
        alert.accessoryView = field
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        completionHandler(alert.runModal() == .alertFirstButtonReturn ? field.stringValue : nil)
    }

    // WebKit owns no file chooser of its own: without this method a click on
    // <input type="file"> does nothing at all — no panel, no error, no console
    // message. The completion handler must run exactly once, or the input stays
    // wedged for the rest of the page's life and never asks again.
    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters,
                 initiatedByFrame frame: WKFrameInfo,
                 completionHandler: @escaping ([URL]?) -> Void) {
        var answered = false
        let reply: ([URL]?) -> Void = { urls in
            guard !answered else { return }
            answered = true
            completionHandler(urls)
        }

        // --snap is a one-shot screenshot; stopping for a panel would hang it.
        guard launchOptions.snap == nil else {
            reply(nil)
            return
        }

        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = parameters.allowsMultipleSelection
        // `webkitdirectory` asks for a folder, and WebKit walks it itself. The
        // two modes are exclusive: offering both lets the page get a kind of
        // path it never asked for.
        panel.canChooseDirectories = parameters.allowsDirectories
        panel.canChooseFiles = !parameters.allowsDirectories
        panel.canCreateDirectories = false
        panel.resolvesAliases = true
        panel.treatsFilePackagesAsDirectories = false
        panel.prompt = parameters.allowsDirectories ? "Choose Folder" : "Choose"
        // No type filter: `accept` is not exposed on WKOpenPanelParameters, and
        // guessing it from the page would only make valid files unselectable.
        if let host = frame.request.url?.host ?? webView.url?.host {
            panel.message = "Choose \(parameters.allowsDirectories ? "a folder" : "files") to upload to \(host)"
        }

        // The ⌘L HUD floats inside the window and would sit under the sheet.
        hideHUD()

        let finish: (NSApplication.ModalResponse) -> Void = { result in
            reply(result == .OK && !panel.urls.isEmpty ? panel.urls : nil)
        }
        if let window = webView.window ?? self.window {
            panel.beginSheetModal(for: window, completionHandler: finish)
        } else {
            panel.begin(completionHandler: finish)
        }
    }
}

// MARK: - App delegate

final class AppDelegate: NSObject, NSApplicationDelegate, NSTableViewDataSource, NSTableViewDelegate {
    var controllers: [BrowserWindowController] = []
    /// Set once the quit prompt over live sessions is answered yes — the
    /// per-window close check reads it and stops asking.
    var sessionCloseApproved = false
    private var profilePickerProfiles: [BrowserProfile] = []
    private var profilePickerSelectedID: String?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        buildMenu()
        seedSiteTweaksFile()

        // Compiling takes a moment, and the first page can load before the list
        // is ready. Reloading it out from under the user to catch a handful of
        // early requests would be worse than missing them.
        adBlockManager.rebuild()
        if launchOptions.snap == nil {
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                adBlockManager.updateAll(force: false)
            }
            // A shortcut saved while the machine was offline still has no icon.
            quickAccessStore.refreshMissingIcons()
        }

        guard let profile = profileStore.profile(matching: launchOptions.profile) else {
            fputs("chromeless: profile not found: \(launchOptions.profile ?? "")\n", stderr)
            exit(1)
        }
        let url: URL? = {
            if let u = launchOptions.url { return u }
            if launchOptions.snap != nil { return nil }
            // A private window does not resurrect a page it never recorded.
            if launchOptions.restoreLastPage, !launchOptions.privateWindow,
               let s = profile.lastURL { return URL(string: s) }
            return nil
        }()
        // A URL opened from another app (`open -a Chromeless <url>`, a link
        // clicked somewhere else) arrives through application(_:open:), which
        // AppKit calls *before* this method, so a window is already up. Opening
        // the start page as well used to bury it: the link looked like it had
        // been swallowed, when it was loading one window behind.
        if url == nil && launchOptions.snap == nil && !controllers.isEmpty {
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        openWindow(profile: profile, url: url, size: launchOptions.size,
                   snap: launchOptions.snap, isPrimary: true,
                   isPrivate: launchOptions.privateWindow)
        NSApp.activate(ignoringOtherApps: true)

        if launchOptions.snap != nil {
            DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
                fputs("chromeless: --snap timed out\n", stderr)
                exit(2)
            }
        } else {
            remoteControl.startIfEnabled()
        }
    }

    @discardableResult
    func openWindow(profile: BrowserProfile, url: URL?, size: NSSize? = nil,
                    snap: SnapJob? = nil, isPrimary: Bool = false, isPrivate: Bool = false,
                    foreground: Bool = true, firstTabAgent: Bool = false) -> BrowserWindowController {
        let controller = BrowserWindowController(
            profile: profile, url: url, size: size, snap: snap,
            isPrimary: isPrimary, isPrivate: isPrivate, firstTabAgent: firstTabAgent)
        controller.onClose = { [weak self, weak controller] in
            self?.controllers.removeAll { $0 === controller }
        }
        controllers.append(controller)
        if foreground {
            controller.showWindow(nil)
            controller.window?.makeKeyAndOrderFront(nil)
        } else {
            // Ordered front but never key: the window appears so the user can
            // see what the agent got, without taking the focus it was using.
            controller.window?.orderFront(nil)
        }
        // Placement is only final once the window is ordered: the
        // WindowServer may still re-place a restored frame between init and
        // here (tiling state, space bookkeeping), so where it actually landed
        // is what counts. The second pass catches stragglers that move after
        // the first ordering settles.
        if snap == nil, let window = controller.window {
            DispatchQueue.main.async { PrimaryScreenPreference.constrain(window) }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) {
                PrimaryScreenPreference.constrain(window)
            }
        }
        return controller
    }

    @objc func newWindow(_ sender: Any?) { presentProfilePicker(from: nil) }

    @objc func newPrivateWindow(_ sender: Any?) {
        openWindow(profile: profileStore.defaultProfile, url: nil, isPrivate: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    // Closing the last window quits the app, so without this a download that is
    // 90% done dies silently when you close the window it started from.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard launchOptions.snap == nil else { return .terminateNow }
        // A live session dies with its window — one quit prompt for all of
        // them, then windowShouldClose stands down via sessionCloseApproved.
        if !sessionCloseApproved {
            let hosts = controllers.flatMap(\.tabs)
                .filter { isSessionHost($0.webView.url) }
                .compactMap { $0.webView.url?.host }
            if !hosts.isEmpty {
                let alert = NSAlert()
                alert.messageText = "Quitting disconnects the session on \(hosts.joined(separator: ", "))."
                alert.addButton(withTitle: "Quit")
                alert.addButton(withTitle: "Cancel")
                if alert.runModal() != .alertFirstButtonReturn { return .terminateCancel }
                sessionCloseApproved = true
            }
        }
        guard downloadManager.hasActiveDownloads else { return .terminateNow }
        let alert = NSAlert()
        alert.messageText = "A download is still in progress."
        alert.informativeText = "Quitting now cancels it."
        alert.addButton(withTitle: "Quit Anyway")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            downloadManager.cancelAll()
            return .terminateNow
        }
        // Staying alive after all — the next quit asks about sessions again.
        sessionCloseApproved = false
        return .terminateCancel
    }
    @objc func showSettings(_ sender: Any?) {
        SettingsWindowController.shared.present()
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool { true }

    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls { openWindow(profile: profileStore.defaultProfile, url: url) }
    }

    func presentProfilePicker(from controller: BrowserWindowController?) {
        profilePickerProfiles = profileStore.profiles
        let preferredID = controller?.profileID
            ?? NSApp.keyWindow
                .flatMap { window in controllers.first { $0.window === window }?.profileID }
            ?? profileStore.defaultProfile.id
        profilePickerSelectedID = profilePickerProfiles.first { $0.id == preferredID }?.id
            ?? profilePickerProfiles.first?.id

        let alert = NSAlert()
        alert.messageText = "Choose Profile"
        alert.informativeText = "Open the new window with separate cookies, cache, and session data."
        alert.addButton(withTitle: "Open")
        alert.addButton(withTitle: "Make Default")
        alert.addButton(withTitle: "New Profile...")
        alert.addButton(withTitle: "Delete Profile")
        alert.addButton(withTitle: "Cancel")

        let table = NSTableView(frame: NSRect(x: 0, y: 0, width: 430, height: 1))
        table.headerView = nil
        table.rowHeight = 54
        table.intercellSpacing = NSSize(width: 0, height: 4)
        table.selectionHighlightStyle = .regular
        table.dataSource = self
        table.delegate = self
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("Profile"))
        column.width = 430
        table.addTableColumn(column)

        let scrollHeight = min(280, max(64, profilePickerProfiles.count * 58))
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 430, height: scrollHeight))
        scroll.hasVerticalScroller = profilePickerProfiles.count > 5
        scroll.borderType = .bezelBorder
        scroll.documentView = table
        alert.accessoryView = scroll

        table.reloadData()
        if let id = profilePickerSelectedID,
           let row = profilePickerProfiles.firstIndex(where: { $0.id == id }) {
            table.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        }

        switch alert.runModal() {
        case .alertFirstButtonReturn:
            if let profile = selectedPickerProfile() {
                openWindow(profile: profile, url: nil)
            }
        case .alertSecondButtonReturn:
            if let profile = selectedPickerProfile() {
                profileStore.setDefaultProfile(profile)
                presentProfilePicker(from: nil)
            }
        case .alertThirdButtonReturn:
            createProfileThenOpenWindow()
        case NSApplication.ModalResponse(rawValue: NSApplication.ModalResponse.alertThirdButtonReturn.rawValue + 1):
            if let profile = selectedPickerProfile() {
                confirmDeleteProfile(profile)
            } else {
                presentProfilePicker(from: nil)
            }
        default:
            break
        }
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        profilePickerProfiles.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard profilePickerProfiles.indices.contains(row) else { return nil }
        let profile = profilePickerProfiles[row]
        let cell = NSTableCellView(frame: NSRect(x: 0, y: 0, width: 430, height: 54))

        let isDefault = profile.id == profileStore.defaultProfile.id
        let title = NSTextField(labelWithString: isDefault ? "\(profile.name) (Default)" : profile.name)
        title.font = .systemFont(ofSize: 14, weight: .semibold)
        title.textColor = .labelColor
        title.lineBreakMode = .byTruncatingTail
        title.frame = NSRect(x: 12, y: 28, width: 390, height: 18)
        title.autoresizingMask = [.width]

        let detailText = profile.lastURL ?? (isDefault ? "Default profile" : "No saved page yet")
        let detail = NSTextField(labelWithString: detailText)
        detail.font = .systemFont(ofSize: 11)
        detail.textColor = .secondaryLabelColor
        detail.lineBreakMode = .byTruncatingMiddle
        detail.frame = NSRect(x: 12, y: 9, width: 390, height: 15)
        detail.autoresizingMask = [.width]

        cell.addSubview(title)
        cell.addSubview(detail)
        cell.textField = title
        return cell
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        guard let table = notification.object as? NSTableView else { return }
        if profilePickerProfiles.indices.contains(table.selectedRow) {
            profilePickerSelectedID = profilePickerProfiles[table.selectedRow].id
        }
    }

    private func selectedPickerProfile() -> BrowserProfile? {
        guard let id = profilePickerSelectedID else { return profilePickerProfiles.first }
        return profilePickerProfiles.first { $0.id == id } ?? profilePickerProfiles.first
    }

    private func createProfileThenOpenWindow() {
        let alert = NSAlert()
        alert.messageText = "New Profile"
        alert.informativeText = "Create a separate browser identity for another account."
        alert.addButton(withTitle: "Create")
        alert.addButton(withTitle: "Cancel")

        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        field.placeholderString = "Work, Personal, Client..."
        alert.accessoryView = field

        guard alert.runModal() == .alertFirstButtonReturn else { return }
        do {
            let profile = try profileStore.createProfile(named: field.stringValue)
            openWindow(profile: profile, url: nil)
        } catch {
            let errorAlert = NSAlert(error: error)
            errorAlert.messageText = "Couldn’t Create Profile"
            errorAlert.runModal()
        }
    }

    private func confirmDeleteProfile(_ profile: BrowserProfile) {
        if controllers.contains(where: { $0.profileID == profile.id }) {
            let alert = NSAlert()
            alert.messageText = "Close Profile Windows First"
            alert.informativeText = "Close all windows using “\(profile.name)” before deleting that profile."
            alert.addButton(withTitle: "OK")
            alert.runModal()
            presentProfilePicker(from: nil)
            return
        }

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Delete “\(profile.name)”?"
        alert.informativeText = "This removes the profile metadata and its website data, including cookies, cache, local storage, history, and login sessions."
        alert.addButton(withTitle: "Delete")
        alert.addButton(withTitle: "Cancel")

        guard alert.runModal() == .alertFirstButtonReturn else {
            presentProfilePicker(from: nil)
            return
        }

        profileStore.deleteProfile(profile) { [weak self] error in
            DispatchQueue.main.async {
                if let error {
                    let errorAlert = NSAlert(error: error)
                    errorAlert.messageText = "Couldn’t Delete Profile"
                    errorAlert.runModal()
                }
                self?.presentProfilePicker(from: nil)
            }
        }
    }

    // MARK: Menu

    private func buildMenu() {
        let main = NSMenu()

        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "About Chromeless",
                        action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Settings…", action: #selector(showSettings(_:)), keyEquivalent: ",")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide Chromeless", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        let hideOthers = appMenu.addItem(withTitle: "Hide Others",
                                         action: #selector(NSApplication.hideOtherApplications(_:)), keyEquivalent: "h")
        hideOthers.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(withTitle: "Show All", action: #selector(NSApplication.unhideAllApplications(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Quit Chromeless", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        main.addItem(withTitle: "Chromeless", action: nil, keyEquivalent: "").submenu = appMenu

        let fileMenu = NSMenu(title: "File")
        let newWin = fileMenu.addItem(withTitle: "New Window", action: #selector(newWindow(_:)), keyEquivalent: "n")
        newWin.target = self
        let newPriv = fileMenu.addItem(withTitle: "New Private Window",
                                       action: #selector(newPrivateWindow(_:)), keyEquivalent: "n")
        newPriv.keyEquivalentModifierMask = [.command, .shift]
        newPriv.target = self
        fileMenu.addItem(withTitle: "New Tab",
                         action: #selector(BrowserWindowController.newTabAction(_:)), keyEquivalent: "t")
        let reopen = fileMenu.addItem(withTitle: "Reopen Closed Tab",
                                      action: #selector(BrowserWindowController.reopenClosedTabAction(_:)),
                                      keyEquivalent: "t")
        reopen.keyEquivalentModifierMask = [.command, .shift]
        fileMenu.addItem(withTitle: "Open Location…",
                         action: #selector(BrowserWindowController.openLocation(_:)), keyEquivalent: "l")
        fileMenu.addItem(.separator())
        let snap = fileMenu.addItem(withTitle: "Save Snapshot to Desktop",
                                    action: #selector(BrowserWindowController.saveSnapshot(_:)), keyEquivalent: "s")
        snap.keyEquivalentModifierMask = [.command, .shift]
        fileMenu.addItem(.separator())
        // ⌘W closes the tab, and closes the window when it is the last one, so
        // the old muscle memory still lands where it used to.
        fileMenu.addItem(withTitle: "Close Tab",
                         action: #selector(BrowserWindowController.closeTabAction(_:)), keyEquivalent: "w")
        let closeWin = fileMenu.addItem(withTitle: "Close Window",
                                        action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        closeWin.keyEquivalentModifierMask = [.command, .shift]
        main.addItem(withTitle: "File", action: nil, keyEquivalent: "").submenu = fileMenu

        let editMenu = NSMenu(title: "Edit")
        editMenu.addItem(withTitle: "Undo", action: NSSelectorFromString("undo:"), keyEquivalent: "z")
        editMenu.addItem(withTitle: "Redo", action: NSSelectorFromString("redo:"), keyEquivalent: "Z")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "Find…",
                         action: #selector(BrowserWindowController.findInPageAction(_:)), keyEquivalent: "f")
        editMenu.addItem(withTitle: "Find Next",
                         action: #selector(BrowserWindowController.findNextAction(_:)), keyEquivalent: "g")
        let findPrev = editMenu.addItem(withTitle: "Find Previous",
                                        action: #selector(BrowserWindowController.findPreviousAction(_:)),
                                        keyEquivalent: "g")
        findPrev.keyEquivalentModifierMask = [.command, .shift]
        editMenu.addItem(.separator())
        let copyURL = editMenu.addItem(withTitle: "Copy Current URL",
                                       action: #selector(BrowserWindowController.copyPageURL(_:)), keyEquivalent: "c")
        copyURL.keyEquivalentModifierMask = [.command, .shift]
        main.addItem(withTitle: "Edit", action: nil, keyEquivalent: "").submenu = editMenu

        let viewMenu = NSMenu(title: "View")
        viewMenu.addItem(withTitle: "Reload Page",
                         action: #selector(BrowserWindowController.reloadPage(_:)), keyEquivalent: "r")
        let hardReload = viewMenu.addItem(withTitle: "Reload Ignoring Cache",
                                          action: #selector(BrowserWindowController.hardReloadPage(_:)), keyEquivalent: "r")
        hardReload.keyEquivalentModifierMask = [.command, .shift]
        viewMenu.addItem(.separator())
        viewMenu.addItem(withTitle: "Zoom In",
                         action: #selector(BrowserWindowController.zoomInPage(_:)), keyEquivalent: "=")
        viewMenu.addItem(withTitle: "Zoom Out",
                         action: #selector(BrowserWindowController.zoomOutPage(_:)), keyEquivalent: "-")
        viewMenu.addItem(withTitle: "Actual Size",
                         action: #selector(BrowserWindowController.resetZoom(_:)), keyEquivalent: "0")
        viewMenu.addItem(.separator())
        let home = viewMenu.addItem(withTitle: "Home",
                                    action: #selector(BrowserWindowController.goHome(_:)), keyEquivalent: "h")
        home.keyEquivalentModifierMask = [.command, .shift]
        viewMenu.addItem(.separator())
        let downloads = viewMenu.addItem(
            withTitle: "Show Downloads",
            action: #selector(BrowserWindowController.toggleDownloadsPanel(_:)), keyEquivalent: "j")
        downloads.keyEquivalentModifierMask = [.command, .shift]
        viewMenu.addItem(withTitle: "Show Profile Button",
                         action: #selector(BrowserWindowController.toggleProfileChip(_:)), keyEquivalent: "")
        viewMenu.addItem(.separator())
        let aiSidebar = viewMenu.addItem(
            withTitle: "AI Sidebar",
            action: #selector(BrowserWindowController.toggleAISidebar(_:)), keyEquivalent: "a")
        aiSidebar.keyEquivalentModifierMask = [.command, .shift]
        viewMenu.addItem(withTitle: "Show AI Button",
                         action: #selector(BrowserWindowController.toggleAIButton(_:)), keyEquivalent: "")
        viewMenu.addItem(withTitle: "AI Settings…",
                         action: #selector(BrowserWindowController.showAISettings(_:)), keyEquivalent: "")
        viewMenu.addItem(withTitle: "Translate Selection on ⇧",
                         action: #selector(BrowserWindowController.toggleTranslateOnShift(_:)), keyEquivalent: "")
        viewMenu.addItem(withTitle: "Remote Control…",
                         action: #selector(BrowserWindowController.showRemoteSettings(_:)), keyEquivalent: "")
        viewMenu.addItem(.separator())
        let siteBlocking = viewMenu.addItem(
            withTitle: "Block Ads on This Site",
            action: #selector(BrowserWindowController.toggleSiteBlocking(_:)), keyEquivalent: "b")
        siteBlocking.keyEquivalentModifierMask = [.command, .shift]
        let picker = viewMenu.addItem(
            withTitle: "Pick Element to Hide…",
            action: #selector(BrowserWindowController.pickElementToBlock(_:)), keyEquivalent: "e")
        picker.keyEquivalentModifierMask = [.command, .shift, .control]
        viewMenu.addItem(withTitle: "Ad Blocking…",
                         action: #selector(BrowserWindowController.showAdBlockSettings(_:)), keyEquivalent: "")
        viewMenu.addItem(.separator())
        // ⌫ is Chrome's Clear Browsing Data shortcut, so the muscle memory
        // already knows where this lives.
        let clearSite = viewMenu.addItem(
            withTitle: "Clear Site Data…",
            action: #selector(BrowserWindowController.clearSiteData(_:)),
            keyEquivalent: "\u{8}")
        clearSite.keyEquivalentModifierMask = [.command, .shift]
        viewMenu.addItem(.separator())
        let inspector = viewMenu.addItem(
            withTitle: "Show Web Inspector",
            action: #selector(BrowserWindowController.toggleWebInspector(_:)),
            keyEquivalent: String(UnicodeScalar(UInt32(NSF12FunctionKey))!))
        inspector.keyEquivalentModifierMask = []
        viewMenu.addItem(.separator())
        let fullScreen = viewMenu.addItem(withTitle: "Enter Full Screen",
                                          action: #selector(NSWindow.toggleFullScreen(_:)), keyEquivalent: "f")
        fullScreen.keyEquivalentModifierMask = [.command, .control]
        main.addItem(withTitle: "View", action: nil, keyEquivalent: "").submenu = viewMenu

        let historyMenu = NSMenu(title: "History")
        historyMenu.addItem(withTitle: "Back",
                            action: #selector(BrowserWindowController.goBackAction(_:)), keyEquivalent: "[")
        historyMenu.addItem(withTitle: "Forward",
                            action: #selector(BrowserWindowController.goForwardAction(_:)), keyEquivalent: "]")
        main.addItem(withTitle: "History", action: nil, keyEquivalent: "").submenu = historyMenu

        let windowMenu = NSMenu(title: "Window")
        windowMenu.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowMenu.addItem(withTitle: "Zoom", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        windowMenu.addItem(.separator())
        let nextTab = windowMenu.addItem(withTitle: "Show Next Tab",
                                         action: #selector(BrowserWindowController.showNextTab(_:)),
                                         keyEquivalent: "]")
        nextTab.keyEquivalentModifierMask = [.command, .shift]
        let prevTab = windowMenu.addItem(withTitle: "Show Previous Tab",
                                         action: #selector(BrowserWindowController.showPreviousTab(_:)),
                                         keyEquivalent: "[")
        prevTab.keyEquivalentModifierMask = [.command, .shift]
        for n in 1...9 {
            let item = windowMenu.addItem(
                withTitle: n == 9 ? "Show Last Tab" : "Show Tab \(n)",
                action: #selector(BrowserWindowController.selectTabByNumber(_:)),
                keyEquivalent: "\(n)")
            item.tag = n
        }
        windowMenu.addItem(.separator())
        windowMenu.addItem(withTitle: "Pin on Top",
                           action: #selector(BrowserWindowController.togglePin(_:)), keyEquivalent: "p")
        main.addItem(withTitle: "Window", action: nil, keyEquivalent: "").submenu = windowMenu
        NSApp.windowsMenu = windowMenu

        let helpMenu = NSMenu(title: "Help")
        helpMenu.addItem(withTitle: "Chromeless Help",
                         action: #selector(BrowserWindowController.showHelpPage(_:)), keyEquivalent: "?")
        main.addItem(withTitle: "Help", action: nil, keyEquivalent: "").submenu = helpMenu
        NSApp.helpMenu = helpMenu

        NSApp.mainMenu = main
    }
}

// MARK: - Boot

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
