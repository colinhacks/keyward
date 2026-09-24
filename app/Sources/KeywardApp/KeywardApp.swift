import SwiftUI

/// The socket has to be listening whether or not a window is on screen — the
/// app can be launched, restored, or left as a menu bar item with every window
/// closed, and a view's onAppear fires in none of those cases.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ note: Notification) {
        // Background agent: no Dock icon, and a launch (or an install script's
        // relaunch) never steals focus. LSUIElement in Info.plist says the same
        // to Launch Services; this covers a binary run outside the bundle.
        NSApp.setActivationPolicy(.accessory)
        ApprovalServer.shared.start()
        AgentInstaller.installIfNeeded()
    }
}

@main
struct KeywardApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var store = EventStore()

    // The menu bar item is the primary scene, so launch opens nothing: the card
    // panel is what the app is for, and it is raised by the daemon, not by a
    // window. The activity window still exists and opens from the menu.
    var body: some Scene {
        MenuBarExtra("Keyward", systemImage: "key.horizontal.fill") {
            MenuBarContent().environmentObject(store)
        }

        Window("Keyward", id: "main") {
            ContentView()
                .environmentObject(store)
                .frame(minWidth: 860, minHeight: 520)
                .onAppear { store.start() }
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
        // Scene order alone does not stop a Window scene from opening at
        // launch; this does (macOS 15+).
        .defaultLaunchBehavior(.suppressed)
    }
}

struct MenuBarContent: View {
    @EnvironmentObject var store: EventStore
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let recent = store.signEvents.suffix(6).reversed()
        if recent.isEmpty {
            Text("No signatures yet")
        } else {
            ForEach(Array(recent), id: \.id) { e in
                Text("\(e.appName) — \(e.who.destination ?? e.keyComment ?? e.outcome)")
            }
        }
        Divider()
        Toggle("Notify on every signature", isOn: $store.notifyOnSign)
        Divider()
        Button("Open Keyward") { openWindow(id: "main") }
        Button("Quit") { NSApplication.shared.terminate(nil) }
    }
}
