// swift-tools-version: 6.0
import PackageDescription

// The app target lives in its own package so `swift test` on Linux keeps
// working for KeyLeaseCore — nothing here can compile without a Darwin SDK.
let package = Package(
    name: "KeyLeaseApp",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "KeyLease", targets: ["KeyLease"])
    ],
    dependencies: [
        .package(path: "../desktop-macos")
    ],
    targets: [
        .executableTarget(
            name: "KeyLease",
            dependencies: [
                .product(name: "KeyLeaseCore", package: "desktop-macos")
            ]
        ),
        .testTarget(
            name: "KeyLeaseTests",
            dependencies: [
                "KeyLease",
                .product(name: "KeyLeaseCore", package: "desktop-macos")
            ]
        )
    ]
)
