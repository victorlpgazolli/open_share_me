# OpenShareMe (macOS)

This project is an open source alternative for xiaomi pc/webshare solution, using this project you can send files from any Xiaomi phone to your Mac. 

It implements the Xiaomi MiDrop / ShareMe protocol natively.

## Demo

<video width=220 src="./assets/demo.mp4" controls></video>


## Features

- **Automatic Server Lifecycle**:
  - Clicking **"Receive File"** starts the native Swift receiver on TCP port `8181` and shows the pairing QR code.
- **Live Transfer UI**:
  - Automatically saves incoming files to `~/Downloads` with collision renaming (`file (1).ext`) and MD5 integrity verification.
- **Dynamic Handshake QR Code**:
  - Auto-resolves current computer name, active local IPv4, and Wi-Fi SSID.
  - Built-in Wi-Fi password management with **"Fetch from Keychain"** support.

## How to contribute

Native macOS menu bar application built with **SwiftUI**, `MenuBarExtra`, and native **Swift** networking & cryptography.

- [CONTRIBUTING.md](./CONTRIBUTING.md)