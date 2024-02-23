// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "EcdhP256",
    products: [
        .library(
            name: "EcdhP256",
            targets: [
                "EcdhLib",
                "EcdhP256"
            ]
        ),
    ],
    targets: [
        .target(
            name: "EcdhLib",
            path: "EcdhLib"
        ),
        .target(
            name: "EcdhP256",
            dependencies: [
                .target(name: "EcdhLib")
            ],
            path: "EcdhP256"
        ),
        .testTarget(
            name: "EcdhP256Tests",
            dependencies: ["EcdhP256"]),
    ]
)
