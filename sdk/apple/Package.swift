// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "DesfireEV3",
    platforms: [.macOS(.v14), .iOS(.v16)],
    products: [
        .library(name: "DesfireEV3", targets: ["DesfireEV3"]),
        .library(name: "DesfireEV3CoreNFC", targets: ["DesfireEV3CoreNFC"]),
    ],
    targets: [
        .systemLibrary(name: "CDesfire"),
        .target(name: "DesfireEV3", dependencies: ["CDesfire"]),
        .target(name: "DesfireEV3CoreNFC", dependencies: ["DesfireEV3"]),
        .testTarget(name: "DesfireEV3Tests", dependencies: ["DesfireEV3"]),
    ]
)
