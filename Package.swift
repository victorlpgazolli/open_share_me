// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OpenShareMe",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "OpenShareMe", targets: ["OpenShareMe"])
    ],
    targets: [
        .executableTarget(
            name: "OpenShareMe",
            path: "Sources/OpenShareMe",
            exclude: [
                "Resources/Info.plist"
            ]
        )
    ]
)
