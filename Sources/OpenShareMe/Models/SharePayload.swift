import Foundation

/// Access Point (AP) connection payload.
struct APPayload: Codable {
    /// Wi-Fi SSID / Network name
    let ss: String
    /// Wi-Fi / Hotspot password or session token
    let pd: String
    /// Host IPv4 address
    let ip: String
    /// TCP receiver port (standard MiDrop/ShareMe port is 8181)
    let pt: Int
}

/// Bluetooth / MAC address payload.
struct BTPayload: Codable {
    /// MAC address formatted as XX:XX:XX:XX:XX:XX
    let ad: String
    /// 5GHz Wi-Fi support flag
    let fiveG: Int
    /// Protocol version/capability flag
    let p2: Int

    enum CodingKeys: String, CodingKey {
        case ad
        case fiveG = "5g"
        case p2
    }
}

/// Outer envelope representing the device handshake payload.
struct SharePayload: Codable {
    /// Current computer name
    let nm: String
    /// Dynamic device / session identifier
    let id: String
    /// Device type icon index (1 = computer / general device)
    let ic: Int
    /// Base64 encoded JSON string of APPayload
    let ap: String
    /// Base64 encoded JSON string of BTPayload
    let bt: String
    /// Protocol flag: sa (server available)
    let sa: Int
    /// Protocol flag: rq (request mode)
    let rq: Int
    /// Protocol version code
    let vs: Int

    /// Builds the complete Base64 string required for the QR code payload.
    static func createDynamicPayload(
        computerName: String,
        deviceId: String,
        ssid: String,
        password: String,
        ipAddress: String,
        port: Int = 8181,
        macAddress: String,
        versionCode: Int = 34805
    ) -> String? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]

        do {
            let apPayload = APPayload(ss: ssid, pd: password, ip: ipAddress, pt: port)
            let apData = try encoder.encode(apPayload)
            let apBase64 = apData.base64EncodedString()

            let btPayload = BTPayload(ad: macAddress, fiveG: 1, p2: 1)
            let btData = try encoder.encode(btPayload)
            let btBase64 = btData.base64EncodedString()

            let envelope = SharePayload(
                nm: computerName,
                id: deviceId,
                ic: 1,
                ap: apBase64,
                bt: btBase64,
                sa: 1,
                rq: 0,
                vs: versionCode
            )
            let envelopeData = try encoder.encode(envelope)
            return envelopeData.base64EncodedString()
        } catch {
            print("Failed to encode SharePayload: \(error)")
            return nil
        }
    }
}
