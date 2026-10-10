import SwiftUI

/// Main application entry point configured with SwiftUI's MenuBarExtra.
@main
struct OpenShareMeApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        MenuBarExtra("OpenShareMe", systemImage: "arrow.down.circle") {
            ContentView()
        }
        .menuBarExtraStyle(.window)
    }
}
