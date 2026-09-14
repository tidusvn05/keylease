// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "KeyLeaseCore",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "KeyLeaseCore", targets: ["KeyLeaseCore"])
    ],
    targets: [
        .target(name: "KeyLeaseCore"),
        .testTarget(
            name: "KeyLeaseCoreTests",
            dependencies: ["KeyLeaseCore"]
        ),
    ]
)
