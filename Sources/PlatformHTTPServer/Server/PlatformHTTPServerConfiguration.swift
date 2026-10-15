//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift HTTP Server open source project
//
// Copyright (c) 2026 Apple Inc. and the Swift HTTP Server project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift HTTP Server project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

public import X509

/// The configuration of a ``PlatformHTTPServer``.
@available(anyAppleOS 27.0, *)
public struct PlatformHTTPServerConfiguration: Sendable {
    /// The IPv4 address to bind to, for example `"127.0.0.1"` or `"0.0.0.0"`.
    public var host: String

    /// The TCP port to bind to. Port `0` lets the system pick a free port.
    public var port: Int

    /// The certificate chain that the server presents, leaf first.
    public var certificateChain: [Certificate]

    /// The private key of the leaf certificate. It has to be a P-256 key.
    public var privateKey: Certificate.PrivateKey

    /// The number of threads that run the connections of the server. `nil` uses one thread per core.
    public var threadCount: Int?

    /// The configuration of every HTTP/2 connection.
    public var http2: HTTP2ServerConfiguration

    /// Creates a configuration.
    public init(
        host: String,
        port: Int,
        certificateChain: [Certificate],
        privateKey: Certificate.PrivateKey,
        threadCount: Int? = nil,
        http2: HTTP2ServerConfiguration = .init()
    ) {
        self.host = host
        self.port = port
        self.certificateChain = certificateChain
        self.privateKey = privateKey
        self.threadCount = threadCount
        self.http2 = http2
    }
}
