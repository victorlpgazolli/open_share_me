
This repo is open for contribution, submit your PR and we will review.

## Architecture

- [`OpenShareMeApp.swift`](file:///Users/victorgazolli/projects/opensource/open_share_me/Sources/OpenShareMe/OpenShareMeApp.swift): SwiftUI application lifecycle with `MenuBarExtra(.window)`.
- [`MiDropCrypto.swift`](file:///Users/victorgazolli/projects/opensource/open_share_me/Sources/OpenShareMe/Services/MiDropCrypto.swift):
  - `BigUInt`: Arbitrary-precision integer arithmetic and binary modular exponentiation (`modPow`).
  - ASN.1 DER Parser & Builder: `parseSpki` and `buildSpki` (PKCS#3 and X9.42 compatible).
  - Diffie-Hellman Key Exchange and shared secret derivation.
  - DES-ECB PKCS7 encryption and decryption via `CommonCrypto`.
- [`MiDropReceiverServer.swift`](file:///Users/victorgazolli/projects/opensource/open_share_me/Sources/OpenShareMe/Services/MiDropReceiverServer.swift):
  - Native TCP server on port `8181` using `NWListener`.
  - Handles `send_pk` handshake and `send_pk_ack` response.
  - Handles DES-encrypted control channels, `ping`/`pong`, and `send_files2`.
  - Downloads incoming files over TCP HTTP/1.0 directly to `~/Downloads` with MD5 checksum verification.
- [`SystemNetworkInfo.swift`](file:///Users/victorgazolli/projects/opensource/open_share_me/Sources/OpenShareMe/Services/SystemNetworkInfo.swift): Dynamically discovers local IP, hardware MAC, and filters out macOS Sonoma/Sequoia `<redacted>` SSID strings.
- [`ContentView.swift`](file:///Users/victorgazolli/projects/opensource/open_share_me/Sources/OpenShareMe/ContentView.swift): SwiftUI popover interface with fixed dimensions to guarantee Auto Layout stability.

## How to Run

### Option 1: Swift CLI
```bash
swift run
```

### Option 2: Xcode Project
```bash
open OpenShareMe.xcodeproj
```
Press `Cmd + R` to run. (Regenerate anytime via `xcodegen generate`).
