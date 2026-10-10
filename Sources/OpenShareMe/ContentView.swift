import SwiftUI
import AppKit

enum AppScreen: Hashable {
    case initial
    case qrCode
    case settings
}

struct ContentView: View {
    // Native Swift MiDrop Receiver Server
    @StateObject private var receiver = MiDropReceiverServer()

    // Persisted Wi-Fi settings in App Storage
    @AppStorage("wifiPassword") private var savedWiFiPassword: String = ""
    @AppStorage("customSSID") private var savedCustomSSID: String = ""

    // Navigation and state
    @State private var currentScreen: AppScreen = .initial
    @State private var qrPayload: String = ""
    @State private var hasCopied: Bool = false
    @State private var isFetchingKeychain: Bool = false
    @State private var passwordInput: String = ""
    @State private var isPasswordRevealed: Bool = false
    @State private var preferredNetworks: [String] = []

    // Hardware and network state (loaded asynchronously)
    @State private var computerName: String = "Mac"
    @State private var localIP: String = "127.0.0.1"
    @State private var currentSSID: String = ""
    @State private var isWiFiOn: Bool = true
    @State private var isLoadingNetwork: Bool = false

    var body: some View {
        VStack(spacing: 0) {
            headerView
                .padding(.horizontal, 16)
                .padding(.top, 14)
                .padding(.bottom, 10)

            Divider()

            // Main body with fixed layout to avoid Auto Layout recursive constraint loops
            ZStack {
                switch currentScreen {
                case .initial:
                    initialView
                case .qrCode:
                    qrCodeView
                case .settings:
                    settingsView
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            Divider()

            footerView
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
        }
        .frame(width: 320, height: 470)
        .onAppear {
            passwordInput = savedWiFiPassword
            refreshNetworkState()
        }
    }

    // MARK: - Header
    private var headerView: some View {
        HStack {
            Image(systemName: "arrow.triangle.2.circlepath")
                .font(.system(size: 14, weight: .bold))
                .foregroundStyle(.blue)

            Text("OpenShareMe")
                .font(.system(size: 13, weight: .semibold))

            Spacer()

            if currentScreen == .settings {
                Button(action: {
                    currentScreen = .initial
                }) {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 14))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Close Settings")
            } else {
                Button(action: {
                    currentScreen = .settings
                }) {
                    Image(systemName: "gearshape")
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Wi-Fi & Pairing Settings")
            }

            Circle()
                .fill(receiver.isRunning ? Color.green : (isWiFiOn ? Color.blue : Color.orange))
                .frame(width: 8, height: 8)
                .help(statusTooltip)
        }
    }

    private var statusTooltip: String {
        if receiver.isRunning { return receiver.statusMessage }
        if !isWiFiOn { return "Wi-Fi is off" }
        return "Ready"
    }

    // MARK: - Initial Screen
    private var initialView: some View {
        VStack(spacing: 14) {
            Spacer(minLength: 0)

            if !isWiFiOn {
                VStack(spacing: 6) {
                    HStack(spacing: 6) {
                        Image(systemName: "wifi.slash")
                            .foregroundStyle(.orange)
                        Text("Wi-Fi is turned off")
                            .font(.caption)
                            .fontWeight(.medium)
                    }
                    Text("Turn on Wi-Fi so devices can find and connect to this Mac.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)

                    Button("Open Wi-Fi Settings") {
                        SystemNetworkInfo.openWiFiSettings()
                    }
                    .buttonStyle(.link)
                    .font(.caption2)
                }
                .padding(10)
                .frame(maxWidth: .infinity)
                .background(Color.orange.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            } else if effectiveSSID.isEmpty {
                VStack(spacing: 6) {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.triangle")
                            .foregroundStyle(.yellow)
                        Text("No Wi-Fi Network Configured")
                            .font(.caption)
                            .fontWeight(.medium)
                    }
                    Text("Select or enter your Wi-Fi network in Settings.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)

                    Button("Configure Network") {
                        currentScreen = .settings
                    }
                    .buttonStyle(.link)
                    .font(.caption2)
                }
                .padding(10)
                .frame(maxWidth: .infinity)
                .background(Color.yellow.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            } else {
                VStack(spacing: 6) {
                    HStack(spacing: 6) {
                        Image(systemName: "wifi")
                            .foregroundStyle(.blue)
                        Text(effectiveSSID)
                            .font(.caption)
                            .fontWeight(.semibold)
                    }
                    Text("Native Swift receiver ready on port 8181.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding(10)
                .frame(maxWidth: .infinity)
                .background(Color.secondary.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            if savedWiFiPassword.isEmpty && !effectiveSSID.isEmpty {
                HStack(spacing: 6) {
                    Image(systemName: "key.fill")
                        .font(.caption2)
                        .foregroundStyle(.blue)
                    Text("Wi-Fi password not set")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Configure") {
                        currentScreen = .settings
                    }
                    .buttonStyle(.link)
                    .font(.caption2)
                }
                .padding(8)
                .background(Color.blue.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }

            Spacer(minLength: 0)

            Button(action: startReceivingAndShowQR) {
                HStack(spacing: 8) {
                    Image(systemName: "arrow.down.doc.fill")
                    Text("Receive File")
                        .fontWeight(.medium)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)

            Spacer(minLength: 0)
        }
    }

    // MARK: - QR Code Screen (with Live Server Status)
    private var qrCodeView: some View {
        VStack(spacing: 8) {
            VStack(spacing: 2) {
                Text("Scan to Connect")
                    .font(.subheadline)
                    .fontWeight(.semibold)

                Text("Point your mobile scanner or ShareMe app")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            // High contrast QR code display
            if let qrImage = QRCodeGenerator.generateNSImage(from: qrPayload, size: 150) {
                VStack {
                    Image(nsImage: qrImage)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 140, height: 140)
                }
                .padding(6)
                .background(Color.white)
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .shadow(color: .black.opacity(0.12), radius: 4, x: 0, y: 2)
            }

            // Live Receiver Status Card
            VStack(spacing: 4) {
                HStack {
                    Circle()
                        .fill(receiver.currentTransferFile != nil ? Color.blue : (receiver.peerName != nil ? Color.green : Color.orange))
                        .frame(width: 6, height: 6)
                    Text(receiver.statusMessage)
                        .font(.caption2)
                        .fontWeight(.medium)
                        .lineLimit(1)
                    Spacer()
                }

                if let currentFile = receiver.currentTransferFile {
                    VStack(alignment: .leading, spacing: 2) {
                        ProgressView(value: receiver.transferProgress)
                            .progressViewStyle(.linear)
                        HStack {
                            Text(currentFile)
                                .font(.caption2)
                                .lineLimit(1)
                            Spacer()
                            Text("\(Int(receiver.transferProgress * 100))%")
                                .font(.caption2.monospaced())
                        }
                    }
                } else if let lastFile = receiver.lastReceivedFile {
                    HStack {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                            .font(.caption)
                        Text(lastFile.lastPathComponent)
                            .font(.caption2)
                            .lineLimit(1)
                        Spacer()
                        Button("Show in Finder") {
                            NSWorkspace.shared.activateFileViewerSelecting([lastFile])
                        }
                        .buttonStyle(.link)
                        .font(.caption2)
                    }
                }
            }
            .padding(6)
            .background(Color.secondary.opacity(0.08))
            .clipShape(RoundedRectangle(cornerRadius: 6))

            // Action buttons
            HStack(spacing: 8) {
                Button(action: copyPayloadToClipboard) {
                    Label(hasCopied ? "Copied!" : "Copy Payload", systemImage: hasCopied ? "checkmark" : "doc.on.doc")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .foregroundStyle(hasCopied ? .green : .primary)

                Button(action: {
                    QRCodeGenerator.openAsPNG(text: qrPayload)
                }) {
                    Label("Open PNG", systemImage: "arrow.up.right.square")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
            }
            .controlSize(.small)

            Button(action: stopReceivingAndGoBack) {
                Label("Back", systemImage: "chevron.left")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.plain)
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }

    // MARK: - Settings Screen
    private var settingsView: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Wi-Fi Configuration")
                .font(.subheadline)
                .fontWeight(.semibold)

            // Wi-Fi Network Name / Picker
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("Wi-Fi Network (SSID):")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Spacer()
                    if isLoadingNetwork {
                        ProgressView()
                            .controlSize(.mini)
                    }
                }

                HStack {
                    TextField("Network Name", text: $currentSSID)
                        .textFieldStyle(.roundedBorder)

                    if !preferredNetworks.isEmpty {
                        Menu {
                            ForEach(preferredNetworks.prefix(8), id: \.self) { net in
                                Button(net) {
                                    currentSSID = net
                                    savedCustomSSID = net
                                }
                            }
                        } label: {
                            Image(systemName: "chevron.down.circle")
                                .foregroundStyle(.blue)
                        }
                        .menuStyle(.borderlessButton)
                        .frame(width: 20)
                        .help("Choose from saved Wi-Fi networks")
                    }

                    Button(action: refreshNetworkState) {
                        Image(systemName: "arrow.clockwise")
                            .font(.caption2)
                    }
                    .buttonStyle(.plain)
                    .help("Refresh networks")
                }
            }
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.secondary.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: 6))

            // Password configuration
            VStack(alignment: .leading, spacing: 4) {
                Text("Wi-Fi Password (pd):")
                    .font(.caption2)
                    .foregroundStyle(.secondary)

                HStack {
                    if isPasswordRevealed {
                        TextField("Wi-Fi Password", text: $passwordInput)
                            .textFieldStyle(.roundedBorder)
                    } else {
                        SecureField("Wi-Fi Password", text: $passwordInput)
                            .textFieldStyle(.roundedBorder)
                    }

                    Button(action: { isPasswordRevealed.toggle() }) {
                        Image(systemName: isPasswordRevealed ? "eye.slash" : "eye")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                }

                HStack {
                    Button(action: fetchPasswordFromKeychain) {
                        HStack(spacing: 4) {
                            Image(systemName: "key")
                            Text(isFetchingKeychain ? "Fetching..." : "Fetch from Keychain")
                        }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.mini)
                    .disabled(effectiveSSID.isEmpty || isFetchingKeychain)

                    Spacer()

                    Button("Save") {
                        savedWiFiPassword = passwordInput
                        savedCustomSSID = currentSSID
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.mini)
                }
            }

            Divider()

            // Internet sharing info
            // VStack(alignment: .leading, spacing: 3) {
            //     Text("macOS Internet Sharing (Hotspot)")
            //         .font(.caption2)
            //         .fontWeight(.semibold)
            //     Text("To broadcast a Wi-Fi network from Ethernet, configure macOS Sharing:")
            //         .font(.caption2)
            //         .foregroundStyle(.secondary)

            //     Button("Open Internet Sharing Settings...") {
            //         SystemNetworkInfo.openInternetSharingSettings()
            //     }
            //     .buttonStyle(.link)
            //     .font(.caption2)
            // }

            Spacer(minLength: 0)

            Button(action: {
                savedWiFiPassword = passwordInput
                savedCustomSSID = currentSSID
                currentScreen = .initial
            }) {
                Text("Done")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
        }
    }

    // MARK: - Footer
    private var footerView: some View {
        HStack {
            Text("OpenShareMe v0.1.0")
                .font(.caption2)
                .foregroundStyle(.tertiary)

            Spacer()

            Button(role: .destructive, action: {
                receiver.stop()
                NSApplication.shared.terminate(nil)
            }) {
                Text("Quit")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
        }
    }

    // MARK: - Actions & Helpers
    private var effectiveSSID: String {
        let cleaned = currentSSID.trimmingCharacters(in: .whitespacesAndNewlines)
        if !cleaned.isEmpty && !cleaned.contains("<redacted>") {
            return cleaned
        }
        if !savedCustomSSID.isEmpty && !savedCustomSSID.contains("<redacted>") {
            return savedCustomSSID
        }
        return ""
    }

    private func refreshNetworkState() {
        isLoadingNetwork = true
        DispatchQueue.global(qos: .userInitiated).async {
            let name = SystemNetworkInfo.getComputerName()
            let ip = SystemNetworkInfo.getLocalIPAddress()
            let wifiOn = SystemNetworkInfo.isWiFiPoweredOn()
            let preferred = SystemNetworkInfo.getPreferredNetworks()
            let detectedSSID = SystemNetworkInfo.getSSID() ?? ""

            DispatchQueue.main.async {
                self.computerName = name
                self.localIP = ip
                self.isWiFiOn = wifiOn
                self.preferredNetworks = preferred

                if self.currentSSID.isEmpty || self.currentSSID.contains("<redacted>") {
                    if !self.savedCustomSSID.isEmpty && !self.savedCustomSSID.contains("<redacted>") {
                        self.currentSSID = self.savedCustomSSID
                    } else if !detectedSSID.isEmpty && !detectedSSID.contains("<redacted>") {
                        self.currentSSID = detectedSSID
                    } else if let firstPref = preferred.first {
                        self.currentSSID = firstPref
                    }
                }

                self.isLoadingNetwork = false
            }
        }
    }

    private func fetchPasswordFromKeychain() {
        let ssid = effectiveSSID
        guard !ssid.isEmpty, !ssid.contains("<redacted>") else { return }
        isFetchingKeychain = true

        DispatchQueue.global(qos: .userInitiated).async {
            let password = SystemNetworkInfo.fetchKeychainWiFiPassword(for: ssid)
            DispatchQueue.main.async {
                self.isFetchingKeychain = false
                if let pwd = password, !pwd.isEmpty {
                    self.passwordInput = pwd
                    self.savedWiFiPassword = pwd
                }
            }
        }
    }

    private func startReceivingAndShowQR() {
        let ssidToUse = !effectiveSSID.isEmpty ? effectiveSSID : "MacShare_\(abs(computerName.hashValue) % 1000)"
        let passwordToUse = !savedWiFiPassword.isEmpty ? savedWiFiPassword : SystemNetworkInfo.generateSessionPassword()
        let macAddress = SystemNetworkInfo.getMACAddress()
        let deviceId = SystemNetworkInfo.getDeviceID()

        if let payload = SharePayload.createDynamicPayload(
            computerName: computerName,
            deviceId: deviceId,
            ssid: ssidToUse,
            password: passwordToUse,
            ipAddress: localIP,
            port: 8181,
            macAddress: macAddress,
            versionCode: 34805
        ) {
            qrPayload = payload
        } else {
            qrPayload = ""
        }

        // Start the native Swift receiver server on TCP port 8181
        receiver.start(port: 8181)
        currentScreen = .qrCode
    }

    private func stopReceivingAndGoBack() {
        receiver.stop()
        currentScreen = .initial
    }

    private func copyPayloadToClipboard() {
        guard !qrPayload.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(qrPayload, forType: .string)
        hasCopied = true

        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            hasCopied = false
        }
    }
}
