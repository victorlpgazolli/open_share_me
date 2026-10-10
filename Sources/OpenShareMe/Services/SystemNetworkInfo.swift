import Foundation
import CoreWLAN
import CoreLocation
import AppKit

/// Resolves dynamic network, hardware, and system information for the running Mac.
final class SystemNetworkInfo {

    /// Retrieves the user-friendly computer name (e.g., "Victor's MacBook Pro" or "mini").
    static func getComputerName() -> String {
        if let name = Host.current().localizedName, !name.isEmpty {
            return name
        }
        return ProcessInfo.processInfo.hostName
    }

    /// Identifies the Wi-Fi network interface name (e.g., "en1" or "en0").
    static func getWiFiInterfaceName() -> String {
        if let iface = CWWiFiClient.shared().interface()?.interfaceName, !iface.isEmpty {
            return iface
        }
        return "en1"
    }

    /// Checks if the Wi-Fi hardware interface is currently powered on.
    static func isWiFiPoweredOn() -> Bool {
        return CWWiFiClient.shared().interface()?.powerOn() ?? false
    }

    /// Retrieves the list of preferred/saved Wi-Fi networks from the Mac.
    static func getPreferredNetworks() -> [String] {
        let wifiInterface = getWiFiInterfaceName()
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        task.arguments = ["-listpreferredwirelessnetworks", wifiInterface]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            guard let str = String(data: data, encoding: .utf8) else { return [] }

            return str.components(separatedBy: "\n")
                .dropFirst()
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { network in
                    !network.isEmpty &&
                    !network.contains("<redacted>") &&
                    !network.hasPrefix("Preferred networks")
                }
        } catch {
            return []
        }
    }

    /// Detects the currently connected Wi-Fi SSID, bypassing macOS Sonoma/Sequoia redaction.
    static func getSSID() -> String? {
        // 1. Try CoreWLAN SSID lookup (works when location authorization is granted)
        if let cwSSID = CWWiFiClient.shared().interface()?.ssid(),
           !cwSSID.isEmpty,
           !cwSSID.contains("<redacted>") {
            return cwSSID
        }

        // 2. Query preferred/saved networks as primary fallback
        // On macOS Sonoma 14.5+ and Sequoia, Apple redacts SSID to "<redacted>" in CLI commands.
        // The top preferred network is the current / primary network configured on this device.
        let preferred = getPreferredNetworks()
        if let topNetwork = preferred.first, !topNetwork.isEmpty {
            return topNetwork
        }

        return nil
    }

    /// Queries the macOS System Keychain to fetch the stored Wi-Fi password for an SSID.
    /// Note: macOS displays a system authorization dialog requiring user confirmation.
    static func fetchKeychainWiFiPassword(for ssid: String, timeout: TimeInterval = 10.0) -> String? {
        let cleanedSSID = ssid.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanedSSID.isEmpty, !cleanedSSID.contains("<redacted>") else {
            return nil
        }

        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        task.arguments = ["find-generic-password", "-D", "AirPort network password", "-a", cleanedSSID, "-w"]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()

        do {
            try task.run()

            let deadline = Date().addingTimeInterval(timeout)
            while task.isRunning && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.1)
            }

            if task.isRunning {
                task.terminate()
                return nil
            }

            if task.terminationStatus == 0 {
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let password = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                if let password = password, !password.isEmpty {
                    return password
                }
            }
        } catch {
            print("Failed to fetch password from Keychain: \(error)")
        }

        return nil
    }

    /// Finds the active local IPv4 address (excluding loopback).
    static func getLocalIPAddress() -> String {
        var address: String?
        var ifaddr: UnsafeMutablePointer<ifaddrs>?

        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return "127.0.0.1"
        }
        defer { freeifaddrs(ifaddr) }

        let wifiInterface = getWiFiInterfaceName()

        for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let interface = ptr.pointee
            let addrFamily = interface.ifa_addr.pointee.sa_family

            if addrFamily == UInt8(AF_INET) {
                let name = String(cString: interface.ifa_name)
                let flags = Int32(interface.ifa_flags)

                if (flags & IFF_UP) != 0 && (flags & IFF_LOOPBACK) == 0 {
                    var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    getnameinfo(
                        interface.ifa_addr,
                        socklen_t(interface.ifa_addr.pointee.sa_len),
                        &hostname,
                        socklen_t(hostname.count),
                        nil,
                        0,
                        NI_NUMERICHOST
                    )
                    let ip = String(cString: hostname)

                    // Prefer active Wi-Fi interface if present
                    if name == wifiInterface {
                        return ip
                    }
                    if address == nil || name == "en0" {
                        address = ip
                    }
                }
            }
        }

        return address ?? "127.0.0.1"
    }

    /// Retrieves the hardware MAC address of the active network interface.
    static func getMACAddress() -> String {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return "00:00:00:00:00:00"
        }
        defer { freeifaddrs(ifaddr) }

        let wifiInterface = getWiFiInterfaceName()
        var fallbackMAC: String?

        for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let interface = ptr.pointee
            let name = String(cString: interface.ifa_name)

            if interface.ifa_addr.pointee.sa_family == UInt8(AF_LINK) {
                let sdl = withUnsafePointer(to: interface.ifa_addr.pointee) {
                    $0.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { $0.pointee }
                }
                let data = withUnsafePointer(to: sdl.sdl_data) {
                    $0.withMemoryRebound(to: UInt8.self, capacity: Int(sdl.sdl_alen)) {
                        Array(UnsafeBufferPointer(start: $0 + Int(sdl.sdl_nlen), count: Int(sdl.sdl_alen)))
                    }
                }

                if data.count == 6 {
                    let mac = data.map { String(format: "%02X", $0) }.joined(separator: ":")
                    if name == wifiInterface {
                        return mac
                    }
                    if fallbackMAC == nil && (name == "en0" || name == "en1") {
                        fallbackMAC = mac
                    }
                }
            }
        }

        return fallbackMAC ?? "00:00:00:00:00:00"
    }

    /// Generates a randomized session token if no password is configured.
    static func generateSessionPassword() -> String {
        let chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        return String((0..<12).compactMap { _ in chars.randomElement() })
    }

    /// Generates a dynamic 10-digit device identifier based on hardware fingerprint.
    static func getDeviceID() -> String {
        let name = getComputerName()
        let mac = getMACAddress()
        let hash = abs("\(name):\(mac)".hashValue)
        let numeric = (hash % 900_000_000) + 1_000_000_000
        return String(numeric)
    }

    /// Opens macOS System Settings directly to Internet Sharing.
    static func openInternetSharingSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.Sharing-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }

    /// Opens macOS System Settings directly to Wi-Fi settings.
    static func openWiFiSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.wifi-settings-extension") {
            NSWorkspace.shared.open(url)
        }
    }
}
