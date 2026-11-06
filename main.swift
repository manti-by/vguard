import Cocoa
import Darwin
import notify
import SystemConfiguration

// MARK: - Config

let supportDir = "/Library/Application Support/VGuard"
let configPath = supportDir + "/config.json"
let pausePath = supportDir + "/pause"
let statusPath = supportDir + "/status.json"
let tokenPath = "/var/run/vguard.pftoken"
let daemonLabel = "com.vguard.daemon"
let daemonBinary = "/Library/PrivilegedHelperTools/com.vguard.daemon"
let daemonPlist = "/Library/LaunchDaemons/com.vguard.daemon.plist"
let pfctl = "/sbin/pfctl"
let pfAnchor = "com.apple/vguard" // evaluated by the stock `anchor "com.apple/*"` in /etc/pf.conf
let gpSettingsPlist = "/Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist"

// notify(3) names — work across user sessions and root daemons
let notifyStatus = "com.vguard.status" // daemon → tray: status changed
let notifyReload = "com.vguard.reload" // tray → daemon: re-read config/pause
let notifyResume = "com.vguard.resume" // tray → daemon: cancel pause (only makes things stricter, so unprivileged)

let tunnelPrefixes = ["utun", "ipsec", "gpd", "ppp", "wg"]
let lanV4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255"]
let lanV6 = ["fe80::/10", "fc00::/7", "ff00::/8"]

func log(_ s: String) {
    let ts = ISO8601DateFormatter().string(from: Date())
    FileHandle.standardError.write(Data("[\(ts)] \(s)\n".utf8))
}

struct Config {
    var allowLAN = true
    var allowDNS = true
    var autoDiscover = true
    // "*.domain" entries match the whole DNS wildcard zone (e.g. GlobalProtect cloud)
    var extraHosts: [String] = ["*.gpcloudservice.com"]

    static func load() -> Config {
        var c = Config()
        guard let data = FileManager.default.contents(atPath: configPath),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return c }
        c.allowLAN = obj["allowLAN"] as? Bool ?? c.allowLAN
        c.allowDNS = obj["allowDNS"] as? Bool ?? c.allowDNS
        c.autoDiscover = obj["autoDiscover"] as? Bool ?? c.autoDiscover
        c.extraHosts = (obj["extraHosts"] as? [String] ?? []).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        return c
    }

    func data() -> Data {
        let obj: [String: Any] = ["allowLAN": allowLAN, "allowDNS": allowDNS, "autoDiscover": autoDiscover, "extraHosts": extraHosts]
        return (try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys])) ?? Data()
    }
}

// MARK: - Shell

@discardableResult
/// `stderr: false` discards stderr — pfctl prints ALTQ notices there that would pollute query output.
func run(_ path: String, _ args: [String], stdin: String? = nil, stderr: Bool = true) -> (code: Int32, out: String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let out = Pipe()
    p.standardOutput = out
    p.standardError = stderr ? out : FileHandle.nullDevice
    let inp = Pipe()
    if stdin != nil { p.standardInput = inp }
    do { try p.run() } catch { return (-1, "\(error)") }
    if let stdin {
        inp.fileHandleForWriting.write(Data(stdin.utf8))
        try? inp.fileHandleForWriting.close()
    }
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(data: data, encoding: .utf8) ?? "")
}

func shq(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

// MARK: - Network state (SCDynamicStore)

final class Callback { let fn: () -> Void; init(_ fn: @escaping () -> Void) { self.fn = fn } }

/// Dynamic store that calls `onChange` (on main) whenever service IPv4 state or interfaces change.
func makeStore(name: String, onChange: @escaping () -> Void) -> SCDynamicStore? {
    let box = Unmanaged.passRetained(Callback(onChange)) // lives for the process lifetime
    var ctx = SCDynamicStoreContext(version: 0, info: box.toOpaque(), retain: nil, release: nil, copyDescription: nil)
    guard let store = SCDynamicStoreCreate(nil, name as CFString, { _, _, info in
        guard let info else { return }
        Unmanaged<Callback>.fromOpaque(info).takeUnretainedValue().fn()
    }, &ctx) else { return nil }
    let patterns = ["State:/Network/Service/.*/IPv4", "State:/Network/Global/IPv4", "State:/Network/Interface/.*/IPv4"]
    SCDynamicStoreSetNotificationKeys(store, nil, patterns as CFArray)
    SCDynamicStoreSetDispatchQueue(store, .main)
    return store
}

func dsValue(_ store: SCDynamicStore, _ key: String) -> [String: Any]? {
    SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any]
}

func dsKeys(_ store: SCDynamicStore, _ pattern: String) -> [String] {
    SCDynamicStoreCopyKeyList(store, pattern as CFString) as? [String] ?? []
}

func isWireGuardService(_ store: SCDynamicStore, _ sid: String) -> Bool {
    (dsValue(store, "Setup:/Network/Service/\(sid)/Interface")?["SubType"] as? String)?.hasPrefix("com.wireguard") == true
}

struct VPN: Hashable {
    let kind: String // "GlobalProtect" | "WireGuard"
    let name: String
    let interface: String
    var label: String { kind == name ? "\(kind) (\(interface))" : "\(kind) “\(name)” (\(interface))" }
}

/// VPNs that are up right now: their service has an IPv4 address on an existing interface.
func activeVPNs(_ store: SCDynamicStore) -> [VPN] {
    var out: [VPN] = []
    for key in dsKeys(store, "State:/Network/Service/[^/]+/IPv4") {
        let parts = key.split(separator: "/")
        guard parts.count == 5, let v = dsValue(store, key),
              let addrs = v["Addresses"] as? [String], !addrs.isEmpty,
              let ifname = v["InterfaceName"] as? String, if_nametoindex(ifname) != 0 else { continue }
        if parts[3].hasPrefix("gpd") { // GlobalProtect publishes its tunnel as service "gpd.pan"
            out.append(VPN(kind: "GlobalProtect", name: "GlobalProtect", interface: ifname))
        }
    }

    // WireGuard.app (Network Extension): the running tunnel is published under a fresh service ID
    // unrelated to the configured one, so ask the NE connection status of each configured service.
    for key in dsKeys(store, "Setup:/Network/Service/[^/]+/Interface") {
        let parts = key.split(separator: "/")
        guard parts.count == 5, isWireGuardService(store, String(parts[3])),
              let conn = SCNetworkConnectionCreateWithServiceID(nil, String(parts[3]) as NSString as CFString, nil, nil),
              SCNetworkConnectionGetStatus(conn) == .connected else { continue }
        let ext = SCNetworkConnectionCopyExtendedStatus(conn) as? [String: Any]
        let ifname = (ext?["IPv4"] as? [String: Any])?["InterfaceName"] as? String ?? "?"
        let name = dsValue(store, "Setup:/Network/Service/\(parts[3])")?["UserDefinedName"] as? String ?? "WireGuard"
        out.append(VPN(kind: "WireGuard", name: name, interface: ifname))
    }
    // wg-quick (wireguard-tools) writes /var/run/wireguard/<name>.name containing the utun name
    let wgRun = "/var/run/wireguard"
    for f in (try? FileManager.default.contentsOfDirectory(atPath: wgRun)) ?? [] where f.hasSuffix(".name") {
        guard let ifname = try? String(contentsOfFile: "\(wgRun)/\(f)", encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines), !ifname.isEmpty, if_nametoindex(ifname) != 0 else { continue }
        out.append(VPN(kind: "WireGuard", name: String(f.dropLast(5)), interface: ifname))
    }
    return Array(Set(out)).sorted { $0.label < $1.label }
}

func stripPort(_ s: String) -> String {
    if s.hasPrefix("["), let end = s.firstIndex(of: "]") { return String(s[s.index(after: s.startIndex)..<end]) }
    let parts = s.split(separator: ":")
    return parts.count == 2 ? String(parts[0]) : s
}

/// VPN endpoints that must stay reachable while traffic is blocked, so the VPN can (re)connect.
func discoveredEndpoints(_ store: SCDynamicStore) -> [String] {
    var hosts: [String] = []
    for key in dsKeys(store, "Setup:/Network/Service/[^/]+/Interface") {
        let parts = key.split(separator: "/")
        guard parts.count == 5, isWireGuardService(store, String(parts[3])),
              let remote = dsValue(store, "Setup:/Network/Service/\(parts[3])/VPN")?["RemoteAddress"] as? String else { continue }
        hosts.append(stripPort(remote))
    }
    if let plist = NSDictionary(contentsOfFile: gpSettingsPlist) {
        func walk(_ v: Any) {
            if let d = v as? [String: Any] {
                for (k, val) in d {
                    if k == "Portal", let s = val as? String, !s.isEmpty { hosts.append(s) }
                    if k == "gateway-address", let s = val as? String { // "gateway=host,ipv4=1.2.3.4,ipv6="
                        for kv in s.split(separator: ",") {
                            let p = kv.split(separator: "=", maxSplits: 1)
                            if p.count == 2, ["gateway", "ipv4", "ipv6"].contains(p[0]) { hosts.append(String(p[1])) }
                        }
                    }
                    walk(val)
                }
            } else if let a = v as? [Any] { a.forEach(walk) }
        }
        walk(plist)
    }
    return Array(Set(hosts.map { stripPort($0.trimmingCharacters(in: .whitespaces)) }.filter { !$0.isEmpty })).sorted()
}

func isIPLiteral(_ s: String) -> Bool {
    var a4 = in_addr(), a6 = in6_addr()
    return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1
}

func resolve(_ host: String) -> [String] {
    if isIPLiteral(host) { return [host] }
    var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_protocol: 0,
                         ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
    var res: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, nil, &hints, &res) == 0 else { return [] }
    defer { freeaddrinfo(res) }
    var ips: [String] = []
    var cur = res
    while let ai = cur {
        var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
            ips.append(String(cString: buf).components(separatedBy: "%").first ?? "")
        }
        cur = ai.pointee.ai_next
    }
    return Array(Set(ips.filter { !$0.isEmpty })).sorted()
}

func isWildcardHost(_ s: String) -> Bool { s.hasPrefix("*.") && s.count > 2 }

/// Wildcard hosts can't be matched by name in pf (the allow table holds IPs only). DNS wildcard
/// zones answer ANY label, so probing random subdomains returns the service's IP pool; allow those.
/// Rarely fails closed (no answer → nothing allowed), but a probe leaking a random hostname is fine.
func resolveWildcard(_ domain: String) -> [String] {
    var ips: [String] = []
    for i in 0..<3 { // several probes to get the whole pool / addresses from multiple resolvers
        ips += resolve("vguard-probe-\(i)-\(Int.random(in: 0...999_999)).\(domain)")
    }
    return Array(Set(ips)).sorted()
}

func tunnelInterfaces() -> [String] {
    var names = Set<String>()
    var ifap: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifap) == 0 else { return [] }
    defer { freeifaddrs(ifap) }
    var cur = ifap
    while let i = cur {
        let n = String(cString: i.pointee.ifa_name)
        if tunnelPrefixes.contains(where: { n.hasPrefix($0) }) { names.insert(n) }
        cur = i.pointee.ifa_next
    }
    return names.sorted()
}

// MARK: - Status file (daemon → tray)

struct Status {
    var blocking = false
    var pausedUntil: Double = 0
    var vpns: [String] = []
    var allowed: [String: [String]] = [:] // host → resolved IPs
    var updated: Double = 0
    var error: String?

    var isFresh: Bool { Date().timeIntervalSince1970 - updated < 30 } // daemon heartbeat is 10 s

    static func read() -> Status? {
        guard let data = FileManager.default.contents(atPath: statusPath),
              let o = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        return Status(blocking: o["blocking"] as? Bool ?? false,
                      pausedUntil: o["pausedUntil"] as? Double ?? 0,
                      vpns: o["vpns"] as? [String] ?? [],
                      allowed: o["allowed"] as? [String: [String]] ?? [:],
                      updated: o["updated"] as? Double ?? 0,
                      error: o["error"] as? String)
    }

    func write() {
        var o: [String: Any] = ["blocking": blocking, "pausedUntil": pausedUntil, "vpns": vpns, "allowed": allowed, "updated": updated]
        if let error { o["error"] = error }
        guard let data = try? JSONSerialization.data(withJSONObject: o, options: [.prettyPrinted, .sortedKeys]) else { return }
        try? data.write(to: URL(fileURLWithPath: statusPath), options: .atomic)
        chmod(statusPath, 0o644)
    }
}

func readPause() -> Double {
    guard let s = try? String(contentsOfFile: pausePath, encoding: .utf8) else { return 0 }
    return Double(s.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
}

// MARK: - Firewall (pf, root only)

final class Firewall {
    private var loaded: String? // rules we last loaded into the anchor

    func makeRules(_ cfg: Config, allowIPs: [String]) -> String {
        var r: [String] = []
        r.append("table <vguard_allow> persist" + (allowIPs.isEmpty ? "" : " { \(allowIPs.joined(separator: ", ")) }"))
        r.append("pass quick on lo0 all")
        let tun = tunnelInterfaces()
        if !tun.isEmpty { r.append("pass quick on { \(tun.joined(separator: " ")) } all") }
        r.append("pass out quick inet proto udp from any port 68 to any port 67") // DHCP
        r.append("pass in quick inet proto udp from any port 67 to any port 68")
        r.append("pass quick inet6 proto udp from any port 546 to any port 547") // DHCPv6
        r.append("pass quick inet6 proto udp from any port 547 to any port 546")
        r.append("pass quick inet6 proto ipv6-icmp all icmp6-type { 133, 134, 135, 136 }") // RS/RA/NS/NA
        if cfg.allowDNS { r.append("pass out quick proto { tcp, udp } from any to any port 53") }
        if cfg.allowLAN {
            r.append("pass quick inet from any to { \(lanV4.joined(separator: ", ")) }")
            r.append("pass in quick inet from { \(lanV4.joined(separator: ", ")) } to any")
            r.append("pass quick inet6 from any to { \(lanV6.joined(separator: ", ")) }")
            r.append("pass in quick inet6 from { \(lanV6.joined(separator: ", ")) } to any")
        }
        r.append("pass out quick from any to <vguard_allow>")
        r.append("block return out quick all") // fail fast instead of hanging connections
        r.append("block drop in quick all")
        return r.joined(separator: "\n") + "\n"
    }

    func block(_ rules: String) throws {
        // If someone reloaded/flushed the main ruleset, our anchor would never be evaluated.
        if !run(pfctl, ["-s", "rules"], stderr: false).out.contains("anchor \"com.apple/*\"") {
            log("main pf ruleset lacks anchor \"com.apple/*\" — reloading /etc/pf.conf")
            run(pfctl, ["-f", "/etc/pf.conf"])
            loaded = nil
        }
        if !run(pfctl, ["-s", "info"], stderr: false).out.contains("Status: Enabled") || !FileManager.default.fileExists(atPath: tokenPath) {
            let (_, out) = run(pfctl, ["-E"]) // reference-counted enable; prints "Token : <n>"
            if let line = out.split(separator: "\n").first(where: { $0.hasPrefix("Token") }),
               let tok = line.split(separator: ":").last?.trimmingCharacters(in: .whitespaces) {
                try? tok.write(toFile: tokenPath, atomically: true, encoding: .utf8)
            }
            loaded = nil
        }
        let current = run(pfctl, ["-a", pfAnchor, "-s", "rules"], stderr: false).out
        if loaded != rules || !current.contains("block return out quick all") {
            let (code, out) = run(pfctl, ["-a", pfAnchor, "-f", "-"], stdin: rules)
            guard code == 0 else { loaded = nil; throw FirewallError(message: "pfctl failed: \(out.trimmingCharacters(in: .whitespacesAndNewlines))") }
            if loaded == nil { log("traffic BLOCKED") }
            loaded = rules
        }
    }

    func unblock() {
        let current = run(pfctl, ["-a", pfAnchor, "-s", "rules"], stderr: false).out
        if loaded != nil || !current.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            run(pfctl, ["-a", pfAnchor, "-F", "all"])
            log("traffic allowed")
        }
        if let tok = try? String(contentsOfFile: tokenPath, encoding: .utf8) {
            run(pfctl, ["-X", tok.trimmingCharacters(in: .whitespacesAndNewlines)])
            try? FileManager.default.removeItem(atPath: tokenPath)
        }
        loaded = nil
    }
}

struct FirewallError: Error { let message: String }

// MARK: - Daemon (runs as root via launchd)

final class Daemon {
    let fw = Firewall()
    var store: SCDynamicStore!
    var resolved: [String: [String]] = [:]
    var resolving = false
    var pending = false
    var lastSummary = ""
    var tokens: [Int32] = []
    var sources: [DispatchSourceSignal] = []

    func start() {
        guard getuid() == 0 else { log("daemon must run as root"); exit(1) }
        try? FileManager.default.createDirectory(atPath: supportDir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        store = makeStore(name: "VGuardDaemon") { [weak self] in self?.schedule() }
        listen(notifyReload) { [weak self] in self?.resolveAsync(); self?.schedule() }
        listen(notifyResume) { [weak self] in
            try? FileManager.default.removeItem(atPath: pausePath)
            self?.schedule()
        }
        for sig in [SIGTERM, SIGINT] {
            signal(sig, SIG_IGN)
            let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            src.setEventHandler { [weak self] in
                log("signal \(sig): removing block and exiting")
                self?.fw.unblock()
                var st = Status.read() ?? Status()
                st.blocking = false; st.updated = 0 // mark daemon as not running
                st.write()
                notify_post(notifyStatus)
                exit(0)
            }
            src.resume()
            sources.append(src)
        }
        Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in self?.evaluate() }
        Timer.scheduledTimer(withTimeInterval: 120, repeats: true) { [weak self] _ in self?.resolveAsync() }
        log("vguard daemon started")
        evaluate() // block immediately at boot, before DNS resolution finishes
        resolveAsync()
        RunLoop.main.run()
    }

    func listen(_ name: String, _ fn: @escaping () -> Void) {
        var t: Int32 = 0
        notify_register_dispatch(name, &t, .main) { _ in fn() }
        tokens.append(t)
    }

    /// Coalesce bursts of network-change callbacks.
    func schedule() {
        guard !pending else { return }
        pending = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            self?.pending = false
            self?.evaluate()
        }
    }

    func hosts(_ cfg: Config) -> [String] {
        Array(Set((cfg.autoDiscover ? discoveredEndpoints(store) : []) + cfg.extraHosts)).sorted()
    }

    func resolveAsync() {
        guard !resolving else { return }
        resolving = true
        let hs = hosts(Config.load())
        DispatchQueue.global(qos: .utility).async {
            var out: [String: [String]] = [:]
            for h in hs { out[h] = isWildcardHost(h) ? resolveWildcard(String(h.dropFirst(2))) : resolve(h) }
            DispatchQueue.main.async {
                self.resolving = false
                // keep previous IPs for hosts that failed to resolve this round (e.g. DNS hiccup)
                for (h, ips) in out where ips.isEmpty { out[h] = self.resolved[h] ?? [] }
                if out != self.resolved { self.resolved = out; self.evaluate() }
            }
        }
    }

    func evaluate() {
        let cfg = Config.load()
        let vpns = activeVPNs(store)
        let now = Date().timeIntervalSince1970
        var pausedUntil = readPause()
        if pausedUntil != 0 && pausedUntil <= now {
            try? FileManager.default.removeItem(atPath: pausePath)
            pausedUntil = 0
        }
        let wantHosts = hosts(cfg)
        let allowed = Dictionary(uniqueKeysWithValues: wantHosts.map { ($0, resolved[$0] ?? (isIPLiteral($0) ? [$0] : [])) })
        if Set(wantHosts) != Set(resolved.keys) { resolveAsync() }

        var st = Status(pausedUntil: pausedUntil, vpns: vpns.map(\.label), allowed: allowed, updated: now)
        if vpns.isEmpty && pausedUntil == 0 {
            let ips = Array(Set(allowed.values.flatMap { $0 })).sorted()
            do {
                try fw.block(fw.makeRules(cfg, allowIPs: ips))
                st.blocking = true
            } catch let e as FirewallError {
                st.error = e.message
                st.blocking = false
                log(e.message)
            } catch {}
        } else {
            fw.unblock()
        }
        st.write()

        let summary = "\(st.blocking)|\(st.pausedUntil)|\(st.vpns)|\(st.error ?? "")|\(st.allowed)"
        if summary != lastSummary {
            lastSummary = summary
            log("state: vpn=\(st.vpns.isEmpty ? "none" : st.vpns.joined(separator: ", ")) blocking=\(st.blocking)"
                + (pausedUntil > 0 ? " paused-until=\(Date(timeIntervalSince1970: pausedUntil))" : ""))
            notify_post(notifyStatus)
        }
    }
}

// MARK: - Tray app

func symbol(_ name: String, color: NSColor? = nil) -> NSImage? {
    guard var img = NSImage(systemSymbolName: name, accessibilityDescription: "VGuard") else { return nil }
    var cfg = NSImage.SymbolConfiguration(pointSize: 17, weight: .medium) // menu-bar default is ~15pt; 17 reads bigger
    if let color { cfg = cfg.applying(.init(paletteColors: [color])) } // paletteColors must be non-empty!
    if let scaled = img.withSymbolConfiguration(cfg) { img = scaled }
    img.isTemplate = color == nil // template = adapts to light/dark menu bar
    return img
}

/// Run a shell command as root via the standard macOS admin password prompt.
@discardableResult
func runAsAdmin(_ cmd: String, prompt: String) -> Bool {
    let esc = cmd.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    let p = prompt.replacingOccurrences(of: "\"", with: "'")
    var err: NSDictionary?
    NSAppleScript(source: "do shell script \"\(esc)\" with prompt \"\(p)\" with administrator privileges")?.executeAndReturnError(&err)
    guard let err else { return true }
    if (err[NSAppleScript.errorNumber] as? Int) != -128 { // -128 = user cancelled
        let a = NSAlert()
        a.messageText = "VGuard: command failed"
        a.informativeText = err[NSAppleScript.errorMessage] as? String ?? "\(err)"
        a.runModal()
    }
    return false
}

final class App: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    var store: SCDynamicStore?
    var vpns: [VPN] = []
    var status: Status?
    var notifyToken: Int32 = 0

    func applicationDidFinishLaunching(_ notification: Notification) {
        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu
        store = makeStore(name: "VGuardTray") { [weak self] in self?.refresh() }
        notify_register_dispatch(notifyStatus, &notifyToken, .main) { [weak self] _ in self?.refresh() }
        Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in self?.refresh() }
        refresh()
    }

    func refresh() {
        vpns = store.map(activeVPNs) ?? []
        status = Status.read()
        let ok = !vpns.isEmpty
        let btn = statusItem.button
        if let img = ok ? symbol("lock.shield") : symbol("exclamationmark.shield.fill", color: .systemRed) {
            btn?.image = img
            btn?.title = ""
        } else {
            btn?.image = nil
            btn?.title = ok ? "🛡" : "⚠️"
        }
        btn?.toolTip = ok ? "VPN: \(vpns.map(\.label).joined(separator: ", "))" : "No VPN — \(trafficLine)"
    }

    var daemonRunning: Bool { status?.isFresh == true }

    var trafficLine: String {
        guard let st = status, st.isFresh else { return "firewall daemon not running — traffic NOT blocked" }
        if let e = st.error { return "error: \(e)" }
        if st.pausedUntil > Date().timeIntervalSince1970 {
            return "protection paused until \(DateFormatter.localizedString(from: Date(timeIntervalSince1970: st.pausedUntil), dateStyle: .none, timeStyle: .short))"
        }
        return st.blocking ? "traffic BLOCKED" : "traffic allowed"
    }

    func info(_ menu: NSMenu, _ title: String) {
        let it = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        it.isEnabled = false
        menu.addItem(it)
    }

    func action(_ menu: NSMenu, _ title: String, _ sel: Selector, _ key: String = "", tag: Int = 0) {
        let it = NSMenuItem(title: title, action: sel, keyEquivalent: key)
        it.target = self
        it.tag = tag
        menu.addItem(it)
    }

    // NSMenuDelegate — rebuild menu each time it opens
    func menuWillOpen(_ menu: NSMenu) {
        refresh()
        menu.removeAllItems()
        if vpns.isEmpty {
            info(menu, "VPN: not connected")
        } else {
            for v in vpns { info(menu, "VPN: \(v.label)") }
        }
        info(menu, "Firewall: \(trafficLine)")

        let allowed = status?.allowed ?? [:]
        let endpoints = NSMenuItem(title: "Allowed while blocked (\(allowed.count))", action: nil, keyEquivalent: "")
        let sub = NSMenu()
        if allowed.isEmpty { info(sub, "none") }
        for h in allowed.keys.sorted() {
            let ips = allowed[h] ?? []
            info(sub, ips == [h] ? h : "\(h) → \(ips.isEmpty ? "unresolved" : ips.joined(separator: ", "))")
        }
        endpoints.submenu = sub
        menu.addItem(endpoints)
        menu.addItem(.separator())

        if !daemonRunning {
            action(menu, "Install Firewall Daemon…", #selector(installDaemon))
        } else if let st = status, st.pausedUntil > Date().timeIntervalSince1970 {
            action(menu, "Resume Protection", #selector(resume))
        } else {
            action(menu, "Pause Protection for 5 Minutes…", #selector(pause(_:)), tag: 5)
            action(menu, "Pause Protection for 1 Hour…", #selector(pause(_:)), tag: 60)
        }
        action(menu, "Settings…", #selector(openSettings), ",")
        action(menu, "Refresh", #selector(manualRefresh), "r")
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
    }

    @objc func manualRefresh() {
        notify_post(notifyReload)
        refresh()
    }

    @objc func pause(_ sender: NSMenuItem) {
        let until = Int(Date().timeIntervalSince1970) + sender.tag * 60
        let cmd = "mkdir -p \(shq(supportDir)) && echo \(until) > \(shq(pausePath)) && chmod 644 \(shq(pausePath))"
        if runAsAdmin(cmd, prompt: "VGuard wants to pause network blocking for \(sender.tag) minutes.") {
            notify_post(notifyReload)
        }
    }

    @objc func resume() { notify_post(notifyResume) }

    @objc func installDaemon() {
        guard let exe = Bundle.main.executablePath,
              let plist = Bundle.main.path(forResource: daemonLabel, ofType: "plist") else {
            let a = NSAlert()
            a.messageText = "Run VGuard from its app bundle (make install), or use `make install-daemon`."
            a.runModal()
            return
        }
        let cmd = [
            "install -d -o root -g wheel -m 755 /Library/PrivilegedHelperTools \(shq(supportDir))",
            "install -o root -g wheel -m 755 \(shq(exe)) \(daemonBinary)",
            "install -o root -g wheel -m 644 \(shq(plist)) \(daemonPlist)",
            "(launchctl bootout system/\(daemonLabel) 2>/dev/null; sleep 1; true)",
            "launchctl bootstrap system \(daemonPlist)",
        ].joined(separator: " && ")
        if runAsAdmin(cmd, prompt: "VGuard wants to install its firewall daemon.") {
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.refresh() }
        }
    }

    @objc func openSettings() {
        NSApp.activate(ignoringOtherApps: true)
        var cfg = Config.load()
        let discovered = store.map(discoveredEndpoints) ?? []
        let alert = NSAlert()
        alert.messageText = "VGuard settings"
        alert.informativeText = """
        While no VPN is connected, all traffic is blocked except the hosts below, DHCP, \
        and (optionally) DNS and LAN. Add hosts your VPN needs to connect — e.g. the SSO / \
        SAML login page — as a comma-separated list. Use "*.domain" to allow an entire \
        DNS wildcard zone (e.g. GlobalProtect cloud endpoints).

        Auto-discovered VPN endpoints: \(discovered.isEmpty ? "none" : discovered.joined(separator: ", "))
        """
        let hosts = NSTextField(frame: NSRect(x: 0, y: 0, width: 380, height: 24))
        hosts.placeholderString = "login.microsoftonline.com, *.gpcloudservice.com"
        hosts.stringValue = cfg.extraHosts.joined(separator: ", ")
        let lan = NSButton(checkboxWithTitle: "Allow local network (LAN, link-local, multicast)", target: nil, action: nil)
        lan.state = cfg.allowLAN ? .on : .off
        let dns = NSButton(checkboxWithTitle: "Allow DNS (needed to resolve VPN hosts)", target: nil, action: nil)
        dns.state = cfg.allowDNS ? .on : .off
        let auto = NSButton(checkboxWithTitle: "Auto-discover GlobalProtect / WireGuard endpoints", target: nil, action: nil)
        auto.state = cfg.autoDiscover ? .on : .off
        let stack = NSStackView(views: [hosts, lan, dns, auto])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.frame = NSRect(x: 0, y: 0, width: 380, height: 110)
        alert.accessoryView = stack
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = hosts
        guard alert.runModal() == .alertFirstButtonReturn else { return }

        cfg.extraHosts = hosts.stringValue.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        cfg.allowLAN = lan.state == .on
        cfg.allowDNS = dns.state == .on
        cfg.autoDiscover = auto.state == .on
        let tmp = NSTemporaryDirectory() + "vguard-config.json"
        guard (try? cfg.data().write(to: URL(fileURLWithPath: tmp))) != nil else { return }
        let cmd = "install -d -o root -g wheel -m 755 \(shq(supportDir)) && install -o root -g wheel -m 644 \(shq(tmp)) \(shq(configPath))"
        if runAsAdmin(cmd, prompt: "VGuard wants to update its firewall settings.") {
            notify_post(notifyReload)
        }
        try? FileManager.default.removeItem(atPath: tmp)
    }
}

// MARK: - main

if CommandLine.arguments.contains("--daemon") {
    Daemon().start()
} else if CommandLine.arguments.contains("--check") { // diagnostics, no root needed
    guard let store = SCDynamicStoreCreate(nil, "VGuardCheck" as CFString, nil, nil) else { exit(1) }
    let cfg = Config.load()
    let vpns = activeVPNs(store)
    print("Active VPNs: \(vpns.isEmpty ? "none" : vpns.map(\.label).joined(separator: ", "))")
    let hosts = Array(Set((cfg.autoDiscover ? discoveredEndpoints(store) : []) + cfg.extraHosts)).sorted()
    var ips: [String] = []
    for h in hosts {
        let r = isWildcardHost(h) ? resolveWildcard(String(h.dropFirst(2))) : resolve(h)
        ips += r
        var line = "Allowed: \(h) → \(r.joined(separator: ", "))"
        if r.isEmpty && isWildcardHost(h) {
            line += "   (zone has no DNS wildcard — auto-discovered endpoints and specific hostnames are used instead)"
        }
        print(line)
    }
    print("Would block: \(vpns.isEmpty)\n--- pf rules for anchor \(pfAnchor) ---")
    print(Firewall().makeRules(cfg, allowIPs: Array(Set(ips)).sorted()), terminator: "")
} else {
    let app = NSApplication.shared
    let delegate = App()
    app.delegate = delegate
    app.setActivationPolicy(.accessory)
    app.run()
}
