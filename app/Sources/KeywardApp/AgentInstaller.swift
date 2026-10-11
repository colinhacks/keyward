import Foundation

/// Registers the daemon with launchd, pointing at whatever copy of the app is
/// running.
///
/// This used to live in the nix-darwin flake, hardcoded to a path inside a git
/// checkout — so cleaning or moving the repo would have left SSH with no agent.
/// The app owns it instead: the plists are rewritten whenever the bundle moves
/// or the contents change, so relocating Keyward fixes itself on next launch.
enum AgentInstaller {
    static let agentLabel = "dev.danielsol.keyward.agent"
    static let watchdogLabel = "dev.danielsol.keyward.watchdog"

    private static var launchAgents: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents")
    }

    static var daemonPath: String {
        Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/keywardd").path
    }

    static func installIfNeeded() {
        guard FileManager.default.isExecutableFile(atPath: daemonPath) else {
            NSLog("keyward: no embedded daemon at \(daemonPath)")
            return
        }
        try? FileManager.default.createDirectory(at: launchAgents,
                                                 withIntermediateDirectories: true)
        let uid = getuid()
        sync(label: agentLabel, plist: agentPlist(), uid: uid)
        removeWatchdog(uid: uid)
    }

    /// The watchdog was a second LaunchAgent that probed the socket on a timer. The
    /// daemon now probes itself and exits when it gets no answer, so KeepAlive on the
    /// one agent does the same job; an install from before that still has the old plist.
    private static func removeWatchdog(uid: uid_t) {
        let url = launchAgents.appendingPathComponent("\(watchdogLabel).plist")
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        _ = launchctl(["bootout", "gui/\(uid)/\(watchdogLabel)"])
        try? FileManager.default.removeItem(at: url)
    }

    /// Only touches launchd when the plist actually changed — a rewrite on
    /// every launch would restart the agent and drop the socket for no reason.
    private static func sync(label: String, plist: String, uid: uid_t) {
        let url = launchAgents.appendingPathComponent("\(label).plist")
        let existing = try? String(contentsOf: url, encoding: .utf8)
        let loaded = isLoaded(label: label, uid: uid)
        if existing == plist && loaded { return }

        try? plist.write(to: url, atomically: true, encoding: .utf8)
        if loaded {
            _ = launchctl(["bootout", "gui/\(uid)/\(label)"])
        }
        _ = launchctl(["bootstrap", "gui/\(uid)", url.path])
        _ = launchctl(["kickstart", "-k", "gui/\(uid)/\(label)"])
    }

    private static func isLoaded(label: String, uid: uid_t) -> Bool {
        launchctl(["print", "gui/\(uid)/\(label)"]) == 0
    }

    @discardableResult
    private static func launchctl(_ args: [String]) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return -1 }
        p.waitUntilExit()
        return p.terminationStatus
    }

    // MARK: - plists

    private static var logPath: String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/keywardd.log").path
    }

    private static func agentPlist() -> String {
        // KeepAlive is unconditional, not `Crashed`: the failure that took
        // ssh-agent-mux down left the process alive and answering nothing,
        // which `Crashed` can never observe. It also means the daemon keeps
        // retrying while some other agent still holds the socket.
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key><string>\(agentLabel)</string>
          <key>ProgramArguments</key>
          <array><string>\(daemonPath)</string></array>
          <key>KeepAlive</key><true/>
          <key>RunAtLoad</key><true/>
          <key>ProcessType</key><string>Interactive</string>
          <key>StandardOutPath</key><string>\(logPath)</string>
          <key>StandardErrorPath</key><string>\(logPath)</string>
        </dict>
        </plist>
        """
    }

}
