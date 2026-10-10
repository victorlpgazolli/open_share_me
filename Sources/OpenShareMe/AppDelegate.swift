import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Ensure the application runs strictly as an accessory (hidden from Dock, visible only in Menu Bar)
        NSApplication.shared.setActivationPolicy(.accessory)
    }
}
