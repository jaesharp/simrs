// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SimRS",
    products: [
        .library(name: "SimRS", targets: ["SimRS"]),
    ],
    targets: [
        .systemLibrary(
            name: "CSimRS",
            pkgConfig: nil
        ),
        .target(
            name: "SimRS",
            dependencies: ["CSimRS"]
        ),
        .testTarget(
            name: "SimRSTests",
            dependencies: ["SimRS"]
        ),
    ]
)
