// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "httpsig",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "HTTPSig", targets: ["HTTPSig"]),
    ],
    targets: [
        .target(
            name: "HTTPSig",
            path: "Sources/HTTPSig"
        ),
        .testTarget(
            name: "HTTPSigTests",
            dependencies: ["HTTPSig"],
            path: "Tests/HTTPSigTests"
        ),
    ]
)
