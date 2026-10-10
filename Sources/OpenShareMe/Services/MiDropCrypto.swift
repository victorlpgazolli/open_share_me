import Foundation
import CommonCrypto

// MARK: - BigUInt (Arbitrary-Precision Unsigned Integer for Diffie-Hellman)

public struct BigUInt: Equatable, Comparable {
    public var words: [UInt64]

    public init() {
        self.words = []
    }

    public init(_ value: UInt64) {
        self.words = value == 0 ? [] : [value]
    }

    public init(words: [UInt64]) {
        var w = words
        while w.last == 0 { w.removeLast() }
        self.words = w
    }

    public init(hex: String) {
        var s = hex.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("0x") { s = String(s.dropFirst(2)) }
        var words: [UInt64] = []
        while !s.isEmpty {
            let start = s.index(s.endIndex, offsetBy: -min(16, s.count))
            let chunk = String(s[start..<s.endIndex])
            s = String(s[..<start])
            if let v = UInt64(chunk, radix: 16) {
                words.append(v)
            }
        }
        self.init(words: words)
    }

    public init(data: Data) {
        var s = ""
        for b in data {
            s += String(format: "%02x", b)
        }
        self.init(hex: s)
    }

    public func toData(paddedTo byteLength: Int? = nil) -> Data {
        let hex = toHexString()
        var s = hex
        if let pad = byteLength {
            let targetHexCount = pad * 2
            if s.count < targetHexCount {
                s = String(repeating: "0", count: targetHexCount - s.count) + s
            }
        } else if s.count % 2 != 0 {
            s = "0" + s
        }

        var data = Data()
        var index = s.startIndex
        while index < s.endIndex {
            let nextIndex = s.index(index, offsetBy: 2)
            if let byte = UInt8(s[index..<nextIndex], radix: 16) {
                data.append(byte)
            }
            index = nextIndex
        }
        return data
    }

    public func toHexString() -> String {
        guard !words.isEmpty else { return "0" }
        var result = String(words.last!, radix: 16)
        for w in words.dropLast().reversed() {
            let chunk = String(w, radix: 16)
            result += String(repeating: "0", count: 16 - chunk.count) + chunk
        }
        return result
    }

    public static func < (lhs: BigUInt, rhs: BigUInt) -> Bool {
        if lhs.words.count != rhs.words.count {
            return lhs.words.count < rhs.words.count
        }
        for (a, b) in zip(lhs.words.reversed(), rhs.words.reversed()) {
            if a != b { return a < b }
        }
        return false
    }

    public static func + (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        var result: [UInt64] = []
        var carry: UInt64 = 0
        let count = max(lhs.words.count, rhs.words.count)
        for i in 0..<count {
            let a = i < lhs.words.count ? lhs.words[i] : 0
            let b = i < rhs.words.count ? rhs.words[i] : 0
            let (sum1, c1) = a.addingReportingOverflow(b)
            let (sum2, c2) = sum1.addingReportingOverflow(carry)
            result.append(sum2)
            carry = (c1 ? 1 : 0) + (c2 ? 1 : 0)
        }
        if carry > 0 { result.append(carry) }
        return BigUInt(words: result)
    }

    public static func - (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        var result: [UInt64] = []
        var borrow: UInt64 = 0
        for i in 0..<lhs.words.count {
            let a = lhs.words[i]
            let b = i < rhs.words.count ? rhs.words[i] : 0
            let (diff1, b1) = a.subtractingReportingOverflow(b)
            let (diff2, b2) = diff1.subtractingReportingOverflow(borrow)
            result.append(diff2)
            borrow = (b1 ? 1 : 0) + (b2 ? 1 : 0)
        }
        return BigUInt(words: result)
    }

    public static func * (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        guard !lhs.words.isEmpty && !rhs.words.isEmpty else { return BigUInt() }
        var result = [UInt64](repeating: 0, count: lhs.words.count + rhs.words.count)
        for i in 0..<lhs.words.count {
            var carry: UInt64 = 0
            for j in 0..<rhs.words.count {
                let (hi, lo) = lhs.words[i].multipliedFullWidth(by: rhs.words[j])
                let (sum1, c1) = result[i + j].addingReportingOverflow(lo)
                let (sum2, c2) = sum1.addingReportingOverflow(carry)
                result[i + j] = sum2
                carry = hi + (c1 ? 1 : 0) + (c2 ? 1 : 0)
            }
            result[i + rhs.words.count] += carry
        }
        return BigUInt(words: result)
    }

    public func quotientAndRemainder(dividingBy rhs: BigUInt) -> (quotient: BigUInt, remainder: BigUInt) {
        precondition(!rhs.words.isEmpty, "Division by zero in BigUInt")
        if self < rhs { return (BigUInt(), self) }
        if self == rhs { return (BigUInt(1), BigUInt()) }

        var q = BigUInt()
        var r = BigUInt()
        for i in (0..<self.bitLength).reversed() {
            r = r << 1
            if self.testBit(i) { r = r | BigUInt(1) }
            if r >= rhs {
                r = r - rhs
                q = q.setBit(i)
            }
        }
        return (q, r)
    }

    public static func % (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        return lhs.quotientAndRemainder(dividingBy: rhs).remainder
    }

    public var bitLength: Int {
        guard let last = words.last else { return 0 }
        return (words.count - 1) * 64 + (64 - last.leadingZeroBitCount)
    }

    public var byteLength: Int {
        return (bitLength + 7) / 8
    }

    public func testBit(_ i: Int) -> Bool {
        let wordIndex = i / 64
        guard wordIndex < words.count else { return false }
        return (words[wordIndex] & (1 << (i % 64))) != 0
    }

    public func setBit(_ i: Int) -> BigUInt {
        var w = words
        let wordIndex = i / 64
        while w.count <= wordIndex { w.append(0) }
        w[wordIndex] |= (1 << (i % 64))
        return BigUInt(words: w)
    }

    public static func << (lhs: BigUInt, rhs: Int) -> BigUInt {
        guard rhs > 0 && !lhs.words.isEmpty else { return lhs }
        let wordShift = rhs / 64
        let bitShift = rhs % 64
        var result = [UInt64](repeating: 0, count: wordShift)
        var carry: UInt64 = 0
        for w in lhs.words {
            let newW = (w << bitShift) | carry
            result.append(newW)
            carry = bitShift > 0 ? (w >> (64 - bitShift)) : 0
        }
        if carry > 0 { result.append(carry) }
        return BigUInt(words: result)
    }

    public static func >> (lhs: BigUInt, rhs: Int) -> BigUInt {
        guard rhs > 0 && !lhs.words.isEmpty else { return lhs }
        let wordShift = rhs / 64
        let bitShift = rhs % 64
        if wordShift >= lhs.words.count { return BigUInt() }
        var result: [UInt64] = []
        for i in wordShift..<lhs.words.count {
            let low = lhs.words[i] >> bitShift
            let high = (bitShift > 0 && i + 1 < lhs.words.count) ? (lhs.words[i + 1] << (64 - bitShift)) : 0
            result.append(low | high)
        }
        return BigUInt(words: result)
    }

    public static func | (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        let count = max(lhs.words.count, rhs.words.count)
        var res: [UInt64] = []
        for i in 0..<count {
            let a = i < lhs.words.count ? lhs.words[i] : 0
            let b = i < rhs.words.count ? rhs.words[i] : 0
            res.append(a | b)
        }
        return BigUInt(words: res)
    }
}

// MARK: - Modular Exponentiation

public func modPow(_ base: BigUInt, _ exp: BigUInt, _ mod: BigUInt) -> BigUInt {
    var res = BigUInt(1)
    var b = base % mod
    var e = exp
    while e > BigUInt() {
        if e.testBit(0) {
            res = (res * b) % mod
        }
        e = e >> 1
        b = (b * b) % mod
    }
    return res
}

// MARK: - ASN.1 DER Encoding / Decoding

private struct TLV {
    let tag: UInt8
    let value: Data
    let endOffset: Int
}

private func derLen(_ n: Int) -> Data {
    if n < 0x80 { return Data([UInt8(n)]) }
    var bytes: [UInt8] = []
    var temp = n
    while temp > 0 {
        bytes.insert(UInt8(temp & 0xff), at: 0)
        temp >>= 8
    }
    return Data([0x80 | UInt8(bytes.count)] + bytes)
}

private func tlv(_ tag: UInt8, _ value: Data) -> Data {
    return Data([tag]) + derLen(value.count) + value
}

private func derInt(_ buf: Data) -> Data {
    var b = buf
    while b.count > 1 && b[b.startIndex] == 0 {
        b = b.dropFirst()
    }
    if let first = b.first, (first & 0x80) != 0 {
        b = Data([0x00]) + b
    }
    return tlv(0x02, b)
}

private func readTlv(_ data: Data, offset: Int = 0) throws -> TLV {
    guard offset + 2 <= data.count else {
        throw NSError(domain: "MiDropCrypto", code: 1, userInfo: [NSLocalizedDescriptionKey: "DER truncated"])
    }
    var off = offset
    let tag = data[data.startIndex + off]
    off += 1
    var len = Int(data[data.startIndex + off])
    off += 1
    if (len & 0x80) != 0 {
        let n = len & 0x7f
        guard n > 0 && n <= 4 && off + n <= data.count else {
            throw NSError(domain: "MiDropCrypto", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid DER length"])
        }
        len = 0
        for _ in 0..<n {
            len = len * 256 + Int(data[data.startIndex + off])
            off += 1
        }
    }
    let end = off + len
    guard end <= data.count else {
        throw NSError(domain: "MiDropCrypto", code: 3, userInfo: [NSLocalizedDescriptionKey: "DER TLV exceeds buffer"])
    }
    let val = Data(data[data.startIndex + off ..< data.startIndex + end])
    return TLV(tag: tag, value: val, endOffset: end)
}

// MARK: - Diffie-Hellman Protocol Structures

public struct DHGroup {
    public let p: BigUInt
    public let g: BigUInt

    public static let defaultGroup = DHGroup(
        p: BigUInt(hex: "ad2da572b49028ecd6e5ac40eeaf0d0a834805ba11e0aaee1357f8177a2190a3"),
        g: BigUInt(hex: "5c6a17022bddf71c64b656da3896a97753af89782888653e6491031f19e46b70")
    )
}

public struct DHKeyPair {
    public let x: BigUInt
    public let y: BigUInt
    public let group: DHGroup
    public let publicKeyBase64: String
}

public struct ParsedSpki {
    public let y: BigUInt
    public let p: BigUInt
    public let g: BigUInt
    public let format: String
}

// MARK: - MiDropCrypto Engine

public final class MiDropCrypto {

    /// Builds SubjectPublicKeyInfo (PKCS#3) in DER format and returns base64.
    public static func buildSpki(y: BigUInt, group: DHGroup = .defaultGroup) -> String {
        let pData = derInt(group.p.toData())
        let gData = derInt(group.g.toData())
        let params = tlv(0x30, pData + gData)
        let oid = Data([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x03, 0x01])
        let alg = tlv(0x30, oid + params)
        let bits = tlv(0x03, Data([0x00]) + derInt(y.toData()))
        let spki = tlv(0x30, alg + bits)
        return spki.base64EncodedString()
    }

    /// Parses an incoming SPKI Base64 string from the sender.
    public static func parseSpki(base64: String) throws -> ParsedSpki {
        guard let data = Data(base64Encoded: base64) else {
            throw NSError(domain: "MiDropCrypto", code: 4, userInfo: [NSLocalizedDescriptionKey: "Invalid base64"])
        }
        let outer = try readTlv(data)
        guard outer.tag == 0x30 else {
            throw NSError(domain: "MiDropCrypto", code: 5, userInfo: [NSLocalizedDescriptionKey: "SPKI does not start with SEQUENCE"])
        }

        let alg = try readTlv(outer.value, offset: 0)
        let bits = try readTlv(outer.value, offset: alg.endOffset)
        guard bits.tag == 0x03 && bits.value.first == 0 else {
            throw NSError(domain: "MiDropCrypto", code: 6, userInfo: [NSLocalizedDescriptionKey: "Invalid BIT STRING in SPKI"])
        }
        let yTlv = try readTlv(Data(bits.value.dropFirst()))
        guard yTlv.tag == 0x02 else {
            throw NSError(domain: "MiDropCrypto", code: 7, userInfo: [NSLocalizedDescriptionKey: "Y is not INTEGER"])
        }

        let oid = try readTlv(alg.value, offset: 0)
        let params = try readTlv(alg.value, offset: oid.endOffset)
        guard oid.tag == 0x06 && params.tag == 0x30 else {
            throw NSError(domain: "MiDropCrypto", code: 8, userInfo: [NSLocalizedDescriptionKey: "Missing DH params"])
        }

        let pTlv = try readTlv(params.value, offset: 0)
        let gTlv = try readTlv(params.value, offset: pTlv.endOffset)
        guard pTlv.tag == 0x02 && gTlv.tag == 0x02 else {
            throw NSError(domain: "MiDropCrypto", code: 9, userInfo: [NSLocalizedDescriptionKey: "p or g is not INTEGER"])
        }

        let p = BigUInt(data: pTlv.value)
        let g = BigUInt(data: gTlv.value)
        let y = BigUInt(data: yTlv.value)

        let oidHex = oid.value.map { String(format: "%02x", $0) }.joined()
        let format = oidHex == "2a8648ce3e0201" ? "X9.42" : (oidHex == "2a864886f70d010301" ? "PKCS#3" : "OID \(oidHex)")

        return ParsedSpki(y: y, p: p, g: g, format: format)
    }

    /// Generates a private/public DH keypair for the given group.
    public static func generateKeyPair(group: DHGroup = .defaultGroup) -> DHKeyPair {
        let byteCount = max(8, group.p.byteLength)
        var randomBytes = [UInt8](repeating: 0, count: byteCount)
        _ = SecRandomCopyBytes(kSecRandomDefault, byteCount, &randomBytes)
        let raw = BigUInt(data: Data(randomBytes))
        let x = (raw % (group.p - BigUInt(3))) + BigUInt(2)
        let y = modPow(group.g, x, group.p)
        let pubBase64 = buildSpki(y: y, group: group)
        return DHKeyPair(x: x, y: y, group: group, publicKeyBase64: pubBase64)
    }

    /// Computes shared secret: K = peerY ^ x mod p.
    public static func computeSharedSecret(peerY: BigUInt, x: BigUInt, group: DHGroup = .defaultGroup) -> Data {
        let k = modPow(peerY, x, group.p)
        return k.toData(paddedTo: group.p.byteLength)
    }

    /// Derives 8-byte DES key from the first 8 bytes of shared secret.
    public static func desKey(secret: Data) -> Data {
        return secret.prefix(8)
    }

    /// Decrypts DES-ECB PKCS7 padded packet string from base64.
    public static func decryptPacket(secret: Data, base64: String) throws -> String {
        guard let data = Data(base64Encoded: base64) else {
            throw NSError(domain: "MiDropCrypto", code: 10, userInfo: [NSLocalizedDescriptionKey: "Invalid base64 packet"])
        }
        let key = desKey(secret: secret)
        let outLength = data.count + kCCBlockSizeDES
        var outBytes = [UInt8](repeating: 0, count: outLength)
        var numBytesDecrypted: size_t = 0

        let status = key.withUnsafeBytes { keyPtr in
            data.withUnsafeBytes { dataPtr in
                CCCrypt(
                    CCOperation(kCCDecrypt),
                    CCAlgorithm(kCCAlgorithmDES),
                    CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode),
                    keyPtr.baseAddress,
                    kCCKeySizeDES,
                    nil,
                    dataPtr.baseAddress,
                    data.count,
                    &outBytes,
                    outLength,
                    &numBytesDecrypted
                )
            }
        }

        guard status == kCCSuccess else {
            throw NSError(domain: "MiDropCrypto", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "DES Decrypt failed with status \(status)"])
        }

        let decData = Data(outBytes.prefix(numBytesDecrypted))
        guard let str = String(data: decData, encoding: .utf8) else {
            throw NSError(domain: "MiDropCrypto", code: 11, userInfo: [NSLocalizedDescriptionKey: "Decrypted bytes not valid UTF-8"])
        }
        return str
    }

    /// Encrypts UTF-8 text using DES-ECB PKCS7 and returns Base64.
    public static func encryptPacket(secret: Data, text: String) throws -> String {
        let data = Data(text.utf8)
        let key = desKey(secret: secret)
        let outLength = data.count + kCCBlockSizeDES
        var outBytes = [UInt8](repeating: 0, count: outLength)
        var numBytesEncrypted: size_t = 0

        let status = key.withUnsafeBytes { keyPtr in
            data.withUnsafeBytes { dataPtr in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmDES),
                    CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode),
                    keyPtr.baseAddress,
                    kCCKeySizeDES,
                    nil,
                    dataPtr.baseAddress,
                    data.count,
                    &outBytes,
                    outLength,
                    &numBytesEncrypted
                )
            }
        }

        guard status == kCCSuccess else {
            throw NSError(domain: "MiDropCrypto", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "DES Encrypt failed with status \(status)"])
        }

        return Data(outBytes.prefix(numBytesEncrypted)).base64EncodedString()
    }
}
