// swift-tools-version:6.4
//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift HTTP Server open source project
//
// Copyright (c) 2025 Apple Inc. and the Swift HTTP Server project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift HTTP Server project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

let extraSettings: [SwiftSetting] = [
    .strictMemorySafety(),
    .enableExperimentalFeature("SuppressedAssociatedTypesWithDefaults"),
    .enableExperimentalFeature("LifetimeDependence"),
    .enableExperimentalFeature("Lifetimes"),
    .enableUpcomingFeature("LifetimeDependence"),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("InternalImportsByDefault"),
]

var traits: Set<Trait> = [
    .trait(
        name: "Configuration",
        description: "Enables initializing NIOHTTPServerConfiguration from a swift-configuration ConfigProvider"
    ),
    .trait(
        name: "HTTP3",
        description: "Enables HTTP/3 support"
    ),
    .trait(
        name: "IOUring",
        description: "Lets PlatformHTTPServer perform its I/O with io_uring on Linux"
    ),
    .trait(
        name: "UnstableHTTPDatagrams",
        description: "Enables support for reading and writing unreliable HTTP datagrams"
    ),
]

let defaultTraits: Set<String> = ["Configuration"]

// Workaround to ensure that all traits are included in documentation. Swift Package Index adds SPI_GENERATE_DOCS
// (https://github.com/SwiftPackageIndex/SwiftPackageIndex-Server/issues/2336) when building documentation, so only
// tweak the default traits in this condition.
let spiGenerateDocs = ProcessInfo.processInfo.environment["SPI_GENERATE_DOCS"] != nil

// Conditionally add the swift-docc plugin only when previewing docs locally.
// Preview with:
// ```
// SWIFT_PREVIEW_DOCS=1 swift package --disable-sandbox preview-documentation --target NIOHTTPServer
// ```
let previewDocs = ProcessInfo.processInfo.environment["SWIFT_PREVIEW_DOCS"] != nil

// Enable all traits for other CI actions.
let enableAllTraitsExplicit = ProcessInfo.processInfo.environment["ENABLE_ALL_TRAITS"] != nil

let enableAllTraits = spiGenerateDocs || previewDocs || enableAllTraitsExplicit
let addDoccPlugin = previewDocs || spiGenerateDocs
let enableAllCIFlags = enableAllTraitsExplicit

traits.insert(
    .default(
        enabledTraits: enableAllTraits ? Set(traits.map(\.name)) : defaultTraits
    ),
)

let package = Package(
    name: "swift-http-server",
    platforms: [  // TODO: Needed until https://github.com/swiftlang/swift/issues/89028 is fixed
        .macOS("27.0"),
        .iOS(.v18),
        .watchOS(.v11),
        .tvOS(.v18),
        .visionOS(.v2),
    ],
    products: [
        .library(
            name: "NIOHTTPServer",
            targets: ["NIOHTTPServer"]
        ),
        .library(
            name: "PlatformHTTPServer",
            targets: ["PlatformHTTPServer"]
        ),
        .executable(
            name: "HTTPServerBenchmark",
            targets: ["HTTPServerBenchmark"]
        ),
    ],
    traits: traits,
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-http-api-proposal.git",
            .upToNextMinor(from: "0.3.0")
        ),
        .package(url: "https://github.com/apple/swift-distributed-tracing.git", from: "1.4.1"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.19.3"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.14.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.103.0"),
        .package(url: "https://github.com/apple/swift-nio-quic.git", .upToNextMinor(from: "0.4.0")),
        .package(url: "https://github.com/apple/swift-nio-quic-helpers.git", .upToNextMinor(from: "0.1.0")),
        .package(url: "https://github.com/apple/swift-nio-http3.git", .upToNextMinor(from: "0.3.0")),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.37.0"),
        // [prototype] A fork that accepts swift-crypto 5, whose in-place AES-GCM the TLS records use.
        .package(
            url: "https://github.pie.apple.com/fbusch/swift-nio-extras.git",
            revision: "dffb028f7ccce038498115c46d06ee3694246496"
        ),
        .package(url: "https://github.com/apple/swift-nio-http2.git", from: "1.44.0"),
        // [prototype] The platform HTTP server is built on forks in the internal GitHub, pinned to revisions of their
        // branches. Bump them from the leaves up: binary-parsing, then the packages that depend on it, then this one.
        // The state machine package only provides `HTTP2StateMachine`. Its name gives it a different package identity
        // than the `swift-nio-http2` above, which keeps providing `NIOHTTP2` for the NIO server.
        .package(
            url: "https://github.pie.apple.com/fbusch/swift-nio-http2-state-machine.git",
            revision: "f685563cbf0dd32ef2877a88d3f29aeaf9bdfe6e"
        ),
        // The HTTP/3 and QPACK state machines of swift-nio-http3 without NIO, as a package with an identity of its own.
        .package(
            url: "https://github.pie.apple.com/fbusch/swift-nio-http3-state-machine.git",
            revision: "762c20f51a6f80b86e915dd8b8d2df6594223b05"
        ),
        .package(
            url: "https://github.pie.apple.com/fbusch/swift-tls.git",
            revision: "d85e2fb9e335e87f11d0bddcd80aa0a41361d56b"
        ),
        .package(
            url: "https://github.pie.apple.com/fbusch/swift-platform-executors.git",
            revision: "0fd00d15d73bd0570d4c29b45cccc80aa4a4f9c6",
            traits: [
                "ExperimentalAsyncStreaming",
                .trait(name: "ExperimentalIOUring", condition: .when(traits: ["IOUring"])),
            ]
        ),
        .package(
            url: "https://github.pie.apple.com/fbusch/swift-binary-parsing.git",
            revision: "b462b9b5a429b46b4e95e645e330e47a9a2446c8"
        ),
        .package(
            url: "https://github.com/apple/swift-async-algorithms.git",
            exact: "1.1.7",
            traits: ["UnstableAsyncStreaming"]
        ),
        .package(
            url: "https://github.com/apple/swift-collections.git",
            exact: "1.7.1",
            traits: ["UnstableContainersPreview", "UnstableHashedContainers"]
        ),
        .package(url: "https://github.com/apple/swift-http-types.git", from: "1.5.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "5.0.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-configuration.git", from: "1.2.0", traits: []),
        .package(url: "https://github.com/swift-server/swift-service-lifecycle.git", from: "2.11.0"),
    ],
    targets: [
        .target(
            name: "ExampleSupport",
            dependencies: [
                .product(name: "Tracing", package: "swift-distributed-tracing")
            ],
            swiftSettings: extraSettings
        ),
        .executableTarget(
            name: "RequestHandlerExample",
            dependencies: [
                "ExampleSupport",
                .product(name: "Instrumentation", package: "swift-distributed-tracing"),
                .product(name: "Logging", package: "swift-log"),
                "NIOHTTPServer",
            ],
            swiftSettings: extraSettings
        ),
        .executableTarget(
            name: "StreamResetExample",
            dependencies: [
                "ExampleSupport",
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOHTTP2", package: "swift-nio-http2"),
                .product(name: "NIOHTTP3", package: "swift-nio-http3", condition: .when(traits: ["HTTP3"])),
                "NIOHTTPServer",
            ],
            swiftSettings: extraSettings
        ),
        .executableTarget(
            name: "ConnectionHandlerExample",
            dependencies: [
                "ExampleSupport",
                .product(name: "Instrumentation", package: "swift-distributed-tracing"),
                .product(name: "Logging", package: "swift-log"),
                "NIOHTTPServer",
            ],
            swiftSettings: extraSettings
        ),
        .target(
            name: "NIOHTTPServer",
            dependencies: [
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOHTTP2", package: "swift-nio-http2"),
                .product(name: "NIOHPACK", package: "swift-nio-http2"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOHTTPTypesHTTP1", package: "swift-nio-extras"),
                .product(name: "NIOHTTPTypesHTTP2", package: "swift-nio-extras"),
                .product(name: "NIOCertificateReloading", package: "swift-nio-extras"),
                .product(
                    name: "Configuration",
                    package: "swift-configuration",
                    condition: .when(traits: ["Configuration"])
                ),
                .product(name: "NIOExtras", package: "swift-nio-extras"),
                .product(name: "NIOQUIC", package: "swift-nio-quic", condition: .when(traits: ["HTTP3"])),
                .product(
                    name: "NIOQUICHelpers",
                    package: "swift-nio-quic-helpers",
                    condition: .when(traits: ["HTTP3"])
                ),
                .product(name: "NIOHTTP3", package: "swift-nio-http3", condition: .when(traits: ["HTTP3"])),
                .product(name: "HTTPAPIs", package: "swift-http-api-proposal"),
            ],
            swiftSettings: extraSettings
        ),
        .target(
            name: "PlatformHTTPServer",
            dependencies: [
                .product(name: "AsyncStreaming", package: "swift-async-algorithms"),
                .product(name: "BasicContainers", package: "swift-collections"),
                .product(name: "ContainersPreview", package: "swift-collections"),
                .product(name: "DequeModule", package: "swift-collections"),
                .product(name: "HeapModule", package: "swift-collections"),
                .product(name: "SpanPreview", package: "swift-collections"),
                .product(name: "BinaryParsing", package: "swift-binary-parsing"),
                .product(name: "BinaryParsingAsync", package: "swift-binary-parsing"),
                .product(name: "BinarySerialization", package: "swift-binary-parsing"),
                .product(name: "HTTP2StateMachine", package: "swift-nio-http2-state-machine"),
                .product(name: "HTTP3StateMachine", package: "swift-nio-http3-state-machine"),
                .product(name: "QPACKStateMachine", package: "swift-nio-http3-state-machine"),
                .product(name: "SwiftTLSStateMachine", package: "swift-tls"),
                .product(name: "PlatformExecutors", package: "swift-platform-executors"),
                .product(name: "HTTPAPIs", package: "swift-http-api-proposal"),
                .product(name: "HTTPTypes", package: "swift-http-types"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "CryptoExtras", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            swiftSettings: extraSettings
        ),
        // Serves the same response with `NIOHTTPServer` or the `PlatformHTTPServer`, so that a load generator can compare
        // the two.
        .executableTarget(
            name: "HTTPServerBenchmark",
            dependencies: [
                "NIOHTTPServer",
                "PlatformHTTPServer",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "BasicContainers", package: "swift-collections"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "HTTPAPIs", package: "swift-http-api-proposal"),
                .product(name: "HTTPTypes", package: "swift-http-types"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "X509", package: "swift-certificates"),
            ],
            swiftSettings: extraSettings
        ),
        .testTarget(
            name: "PlatformHTTPServerTests",
            dependencies: [
                "PlatformHTTPServer",
                .product(name: "Logging", package: "swift-log"),
                .product(name: "HTTP2StateMachine", package: "swift-nio-http2-state-machine"),
                .product(name: "HTTP3StateMachine", package: "swift-nio-http3-state-machine"),
                .product(name: "QPACKStateMachine", package: "swift-nio-http3-state-machine"),
                .product(name: "BinaryParsing", package: "swift-binary-parsing"),
                .product(name: "BinaryParsingAsync", package: "swift-binary-parsing"),
                .product(name: "BinarySerialization", package: "swift-binary-parsing"),
                .product(name: "AsyncStreaming", package: "swift-async-algorithms"),
                .product(name: "BasicContainers", package: "swift-collections"),
                .product(name: "ContainersPreview", package: "swift-collections"),
                .product(name: "SpanPreview", package: "swift-collections"),
                .product(name: "HTTPAPIs", package: "swift-http-api-proposal"),
                .product(name: "HTTPTypes", package: "swift-http-types"),
                .product(name: "PlatformExecutors", package: "swift-platform-executors"),
                .product(name: "SwiftTLSStateMachine", package: "swift-tls"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "CryptoExtras", package: "swift-crypto"),
            ],
            swiftSettings: extraSettings
        ),
        .testTarget(
            name: "NIOHTTPServerTests",
            dependencies: [
                .product(name: "Logging", package: "swift-log"),
                .product(name: "ServiceLifecycle", package: "swift-service-lifecycle"),
                .product(name: "ServiceLifecycleTestKit", package: "swift-service-lifecycle"),
                "NIOHTTPServer",
            ]
        ),
    ]
)
