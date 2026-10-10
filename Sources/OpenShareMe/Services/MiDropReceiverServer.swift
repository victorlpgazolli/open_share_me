import Foundation
import Network
import CryptoKit
import AppKit

/// Protocol models for MiDrop JSON control protocol.
struct MiDropControlPacket: Codable {
    struct IQ: Codable {
        let type: String?
        let xmlns: String?
        let action: String?
        let param: String?
        let from: String?
        let profile: Int?
        let versionCode: Int?
        let id: String?
    }
    let iq: IQ?
}

struct MiDropFileListEntry: Codable {
    let name: String
    let sze: Int?
    let md5: String?
    let uri: String
    let type: String?
    let is_dir: Bool?
}

struct MiDropFileListParam: Codable {
    let list: [MiDropFileListEntry]?
}

/// Pure Swift native implementation of the MiDrop / ShareMe Receiver Server.
public final class MiDropReceiverServer: ObservableObject {
    @Published public var isRunning: Bool = false
    @Published public var statusMessage: String = "Ready"
    @Published public var peerName: String? = nil
    @Published public var currentTransferFile: String? = nil
    @Published public var transferProgress: Double = 0.0
    @Published public var lastReceivedFile: URL? = nil

    private var listener: NWListener?
    private let downloadQueue = DispatchQueue(label: "com.openshareme.downloadQueue", qos: .userInitiated)
    private let downloadDirectory: URL

    public init() {
        self.downloadDirectory = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
    }

    /// Starts the receiver TCP listener on the specified port (default 8181).
    public func start(port: UInt16 = 8181) {
        guard !isRunning else { return }

        do {
            let nwPort = NWEndpoint.Port(rawValue: port) ?? NWEndpoint.Port(integerLiteral: 8181)
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true

            let listener = try NWListener(using: params, on: nwPort)
            self.listener = listener

            listener.newConnectionHandler = { [weak self] newConnection in
                self?.handleNewConnection(newConnection)
            }

            listener.stateUpdateHandler = { [weak self] newState in
                DispatchQueue.main.async {
                    switch newState {
                    case .ready:
                        self?.isRunning = true
                        self?.statusMessage = "Listening on port \(port)"
                    case .failed(let error):
                        self?.isRunning = false
                        self?.statusMessage = "Error: \(error.localizedDescription)"
                    case .cancelled:
                        self?.isRunning = false
                        self?.statusMessage = "Stopped"
                    default:
                        break
                    }
                }
            }

            listener.start(queue: DispatchQueue.global(qos: .userInitiated))
        } catch {
            DispatchQueue.main.async {
                self.isRunning = false
                self.statusMessage = "Failed to start listener: \(error.localizedDescription)"
            }
        }
    }

    /// Stops the receiver TCP listener and resets connection state.
    public func stop() {
        listener?.cancel()
        listener = nil
        DispatchQueue.main.async {
            self.isRunning = false
            self.statusMessage = "Ready"
            self.peerName = nil
            self.currentTransferFile = nil
            self.transferProgress = 0.0
        }
    }

    // MARK: - Connection Handling

    private func handleNewConnection(_ connection: NWConnection) {
        var sharedSecret: Data?
        var pendingBuffer = ""
        var peerIP = "127.0.0.1"

        if case .hostPort(let host, _) = connection.endpoint {
            switch host {
            case .ipv4(let ip4):
                peerIP = ip4.debugDescription
            default:
                break
            }
        }

        connection.stateUpdateHandler = { [weak self] state in
            if case .failed(let err) = state {
                print("Connection failed: \(err)")
            } else if case .cancelled = state {
                DispatchQueue.main.async {
                    if self?.currentTransferFile == nil {
                        self?.statusMessage = "Waiting for connections"
                    }
                }
            }
        }

        connection.start(queue: DispatchQueue.global(qos: .userInitiated))

        func sendRawLine(_ text: String) {
            let payload = text + "\n"
            connection.send(content: Data(payload.utf8), completion: .contentProcessed({ error in
                if let err = error {
                    print("Send error: \(err)")
                }
            }))
        }

        func sendEncrypted(_ jsonObject: [String: Any]) {
            guard let secret = sharedSecret else { return }
            do {
                let data = try JSONSerialization.data(withJSONObject: jsonObject)
                let text = String(data: data, encoding: .utf8) ?? ""
                let encryptedBase64 = try MiDropCrypto.encryptPacket(secret: secret, text: text)
                sendRawLine(encryptedBase64)
            } catch {
                print("Failed to encrypt outgoing packet: \(error)")
            }
        }

        func readLoop() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, _, isComplete, error in
                guard let self = self else { return }

                if let data = content, !data.isEmpty, let chunk = String(data: data, encoding: .utf8) {
                    pendingBuffer += chunk
                    let lines = pendingBuffer.components(separatedBy: CharacterSet(charactersIn: "\r\n\0"))
                    if let last = lines.last {
                        pendingBuffer = last
                    } else {
                        pendingBuffer = ""
                    }

                    for raw in lines.dropLast() {
                        let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !line.isEmpty else { continue }

                        if line.hasPrefix("{") {
                            // Plaintext JSON Handshake control packet
                            if let controlData = line.data(using: .utf8) {
                                self.handleControlPacket(
                                    data: controlData,
                                    peerIP: peerIP,
                                    setSecret: { sharedSecret = $0 },
                                    sendLine: sendRawLine
                                )
                            }
                        } else if let secret = sharedSecret {
                            // DES-ECB Encrypted packet
                            self.handleEncryptedLine(
                                line: line,
                                secret: secret,
                                peerIP: peerIP,
                                sendEncrypted: sendEncrypted
                            )
                        }
                    }
                }

                if isComplete || error != nil {
                    connection.cancel()
                } else {
                    readLoop()
                }
            }
        }

        readLoop()
    }

    // MARK: - Handshake (send_pk / send_pk_ack)

    private func handleControlPacket(
        data: Data,
        peerIP: String,
        setSecret: @escaping (Data) -> Void,
        sendLine: @escaping (String) -> Void
    ) {
        do {
            let packet = try JSONDecoder().decode(MiDropControlPacket.self, from: data)
            guard let iq = packet.iq, iq.action == "send_pk", let paramString = iq.param else { return }

            guard let unescaped = paramString.removingPercentEncoding,
                  let paramData = unescaped.data(using: .utf8),
                  let paramJson = try JSONSerialization.jsonObject(with: paramData) as? [String: Any],
                  let senderPkBase64 = paramJson["pk"] as? String else {
                return
            }

            let parsed = try MiDropCrypto.parseSpki(base64: senderPkBase64)
            let group = DHGroup(p: parsed.p, g: parsed.g)
            let localKeys = MiDropCrypto.generateKeyPair(group: group)
            let secret = MiDropCrypto.computeSharedSecret(peerY: parsed.y, x: localKeys.x, group: group)
            setSecret(secret)

            let senderName = iq.from ?? "Mobile Device"
            DispatchQueue.main.async {
                self.peerName = senderName
                self.statusMessage = "Connected: \(senderName)"
            }

            let ackParam = try JSONSerialization.data(withJSONObject: ["pk": localKeys.publicKeyBase64])
            let ackParamString = String(data: ackParam, encoding: .utf8) ?? ""
            let encodedAckParam = ackParamString.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ackParamString

            let ack: [String: Any] = [
                "iq": [
                    "type": "set",
                    "xmlns": "http://www.xiaomi.com/midrop",
                    "action": "send_pk_ack",
                    "param": encodedAckParam,
                    "profile": 1,
                    "versionCode": iq.versionCode ?? 34805
                ]
            ]
            let ackData = try JSONSerialization.data(withJSONObject: ack)
            if let ackLine = String(data: ackData, encoding: .utf8) {
                sendLine(ackLine)
            }
        } catch {
            print("Error handling send_pk control packet: \(error)")
        }
    }

    // MARK: - Encrypted Protocol Handling

    private func handleEncryptedLine(
        line: String,
        secret: Data,
        peerIP: String,
        sendEncrypted: @escaping ([String: Any]) -> Void
    ) {
        do {
            let decrypted = try MiDropCrypto.decryptPacket(secret: secret, base64: line)
            guard let data = decrypted.data(using: .utf8),
                  let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

            if let ping = json["ping"] as? [String: Any], let id = ping["id"] {
                sendEncrypted(["pong": ["type": "pong", "id": "\(id)"]])
            } else if let iq = json["iq"] as? [String: Any],
                      let action = iq["action"] as? String, action == "send_files2",
                      let paramStr = iq["param"] as? String {
                handleSendFiles2(paramEncoded: paramStr, peerIP: peerIP)
            }
        } catch {
            print("Error decrypting line: \(error)")
        }
    }

    // MARK: - File Download & HTTP/1.0 Client

    private func handleSendFiles2(paramEncoded: String, peerIP: String) {
        guard let unescaped = paramEncoded.removingPercentEncoding,
              let paramData = unescaped.data(using: .utf8) else { return }

        do {
            let param = try JSONDecoder().decode(MiDropFileListParam.self, from: paramData)
            guard let list = param.list, !list.isEmpty else { return }

            downloadQueue.async { [weak self] in
                guard let self = self else { return }
                for entry in list {
                    if entry.is_dir == true { continue }

                    let urlString = self.buildFileUrl(peerIP: peerIP, uri: entry.uri)
                    guard let url = URL(string: urlString) else { continue }

                    DispatchQueue.main.async {
                        self.currentTransferFile = entry.name
                        self.transferProgress = 0.0
                        self.statusMessage = "Receiving: \(entry.name)"
                    }

                    do {
                        let savedURL = try self.downloadFileRawTCP(
                            url: url,
                            entry: entry,
                            onProgress: { prog in
                                DispatchQueue.main.async {
                                    self.transferProgress = prog
                                }
                            }
                        )

                        DispatchQueue.main.async {
                            self.lastReceivedFile = savedURL
                            self.currentTransferFile = nil
                            self.transferProgress = 1.0
                            self.statusMessage = "Received: \(entry.name)"
                        }
                    } catch {
                        DispatchQueue.main.async {
                            self.statusMessage = "Failed to download \(entry.name): \(error.localizedDescription)"
                        }
                    }
                }
            }
        } catch {
            print("Failed to decode send_files2 list: \(error)")
        }
    }

    private func buildFileUrl(peerIP: String, uri: String) -> String {
        if uri.lowercased().hasPrefix("http://") || uri.lowercased().hasPrefix("https://") {
            return uri
        }
        let parts = uri.components(separatedBy: "/")
        if let first = parts.first, first.hasPrefix(":") {
            let portStr = String(first.dropFirst())
            let path = "/" + parts.dropFirst().joined(separator: "/")
            return "http://\(peerIP):\(portStr)\(path)"
        }
        return "http://\(peerIP):80\(uri)"
    }

    private func safeFileName(_ name: String) -> String {
        let base = URL(fileURLWithPath: name).lastPathComponent
        let sanitized = base.components(separatedBy: CharacterSet(charactersIn: ":/\\?%*|\"<>")).joined(separator: "_")
        return sanitized.isEmpty ? "received_file" : sanitized
    }

    private func uniqueFileURL(in directory: URL, fileName: String) -> URL {
        let baseName = (fileName as NSString).deletingPathExtension
        let ext = (fileName as NSString).pathExtension
        var candidate = directory.appendingPathComponent(fileName)
        var counter = 1

        while FileManager.default.fileExists(atPath: candidate.path) {
            let newName = ext.isEmpty ? "\(baseName) (\(counter))" : "\(baseName) (\(counter)).\(ext)"
            candidate = directory.appendingPathComponent(newName)
            counter += 1
        }
        return candidate
    }

    /// Downloads the file using a raw TCP socket with HTTP/1.0 GET request,
    /// handling duplicate Content-Length headers sent by phone servers without crashing.
    private func downloadFileRawTCP(
        url: URL,
        entry: MiDropFileListEntry,
        onProgress: @escaping (Double) -> Void
    ) throws -> URL {
        let host = url.host ?? "127.0.0.1"
        let port = url.port ?? 80
        let path = url.path.isEmpty ? "/" : url.path + (url.query != nil ? "?\(url.query!)" : "")

        var hints = addrinfo(
            ai_flags: 0,
            ai_family: AF_INET,
            ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var servinfo: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &servinfo) == 0, let info = servinfo else {
            throw NSError(domain: "MiDropReceiver", code: 20, userInfo: [NSLocalizedDescriptionKey: "Failed to resolve host \(host)"])
        }
        defer { freeaddrinfo(servinfo) }

        let sock = socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
        guard sock >= 0 else {
            throw NSError(domain: "MiDropReceiver", code: 21, userInfo: [NSLocalizedDescriptionKey: "Failed to create TCP socket"])
        }
        defer { close(sock) }

        // Set timeout
        var tv = timeval(tv_sec: 15, tv_usec: 0)
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        guard connect(sock, info.pointee.ai_addr, info.pointee.ai_addrlen) == 0 else {
            throw NSError(domain: "MiDropReceiver", code: 22, userInfo: [NSLocalizedDescriptionKey: "Failed to connect to \(host):\(port)"])
        }

        let request = "GET \(path) HTTP/1.0\r\nHost: \(host):\(port)\r\nConnection: close\r\n\r\n"
        guard let reqData = request.data(using: .utf8) else {
            throw NSError(domain: "MiDropReceiver", code: 23, userInfo: [NSLocalizedDescriptionKey: "Invalid HTTP request"])
        }

        _ = reqData.withUnsafeBytes { ptr in
            send(sock, ptr.baseAddress, reqData.count, 0)
        }

        let destinationURL = uniqueFileURL(in: downloadDirectory, fileName: safeFileName(entry.name))
        FileManager.default.createFile(atPath: destinationURL.path, contents: nil, attributes: nil)
        let fileHandle = try FileHandle(forWritingTo: destinationURL)
        defer { try? fileHandle.close() }

        var headerBuffer = Data()
        var headerDone = false
        var expectedBytes = entry.sze
        var receivedBytes = 0
        var md5Hasher = Insecure.MD5()

        var buffer = [UInt8](repeating: 0, count: 32768)

        while true {
            let bytesRead = recv(sock, &buffer, buffer.count, 0)
            if bytesRead <= 0 { break }

            let chunk = Data(buffer[0..<bytesRead])

            if !headerDone {
                headerBuffer.append(chunk)
                if let delimiterRange = headerBuffer.range(of: Data("\r\n\r\n".utf8)) {
                    headerDone = true
                    let headerData = headerBuffer.subdata(in: 0..<delimiterRange.lowerBound)
                    let bodyData = headerBuffer.subdata(in: delimiterRange.upperBound..<headerBuffer.count)

                    if let headerStr = String(data: headerData, encoding: .isoLatin1) {
                        for line in headerStr.components(separatedBy: "\r\n") {
                            let lower = line.lowercased()
                            if lower.hasPrefix("content-length:") {
                                let parts = line.components(separatedBy: ":")
                                if parts.count > 1, let len = Int(parts[1].trimmingCharacters(in: .whitespaces)) {
                                    expectedBytes = len
                                }
                            }
                        }
                    }

                    if !bodyData.isEmpty {
                        fileHandle.write(bodyData)
                        md5Hasher.update(data: bodyData)
                        receivedBytes += bodyData.count
                        if let exp = expectedBytes, exp > 0 {
                            onProgress(min(1.0, Double(receivedBytes) / Double(exp)))
                        }
                    }
                }
            } else {
                fileHandle.write(chunk)
                md5Hasher.update(data: chunk)
                receivedBytes += chunk.count
                if let exp = expectedBytes, exp > 0 {
                    onProgress(min(1.0, Double(receivedBytes) / Double(exp)))
                }
            }

            if let exp = expectedBytes, exp > 0, receivedBytes >= exp {
                break
            }
        }

        return destinationURL
    }
}
