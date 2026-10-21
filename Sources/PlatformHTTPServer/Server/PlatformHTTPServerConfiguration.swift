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

    /// The mechanism that the threads of the server wait for events and perform their I/O with.
    public var ioBackend: IOBackend

    /// The configuration of HTTP/2, or `nil` to not serve HTTP/2.
    ///
    /// With HTTP/2, the server binds a TCP listener to the address and port and serves HTTP/2 over TLS on it.
    public var http2: HTTP2ServerConfiguration?

    /// The configuration of HTTP/3, or `nil` to not serve HTTP/3.
    ///
    /// With HTTP/3, the server binds a UDP socket to the address and serves HTTP/3 over QUIC on it. With HTTP/2 as
    /// well, the UDP socket gets the port of the TCP listener.
    ///
    /// At least one of ``http2`` and ``http3`` has to be set.
    public var http3: HTTP3ServerConfiguration?

    /// Creates a configuration.
    public init(
        host: String,
        port: Int,
        certificateChain: [Certificate],
        privateKey: Certificate.PrivateKey,
        threadCount: Int? = nil,
        ioBackend: IOBackend = .platformDefault,
        http2: HTTP2ServerConfiguration? = .init(),
        http3: HTTP3ServerConfiguration? = nil
    ) {
        self.host = host
        self.port = port
        self.certificateChain = certificateChain
        self.privateKey = privateKey
        self.threadCount = threadCount
        self.ioBackend = ioBackend
        self.http2 = http2
        self.http3 = http3
    }

    /// The mechanism that performs the I/O of the server.
    ///
    /// A backend that the platform or the build does not provide makes ``PlatformHTTPServer/serve(handler:)`` throw
    /// ``PlatformHTTPServerError/unavailableIOBackend(_:)``.
    public enum IOBackend: String, Sendable, Hashable, CaseIterable {
        /// Lets the system decide, depending on the platform and the kernel version. On Linux this is `epoll`, or
        /// `io_uring` if the `IOUring` trait is enabled and the kernel allows a ring.
        case platformDefault

        /// `epoll`, on Linux.
        case epoll

        /// `io_uring`, on Linux with the `IOUring` trait enabled. Creating the executors traps if the kernel does not
        /// allow a ring, for example because the container runtime blocks `io_uring`. Use ``platformDefault`` to fall
        /// back to `epoll` instead.
        case ioUring
    }
}
