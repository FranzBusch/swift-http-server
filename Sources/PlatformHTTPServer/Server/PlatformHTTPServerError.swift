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

public import HTTP2StateMachine

/// An error that ends a request or a connection of the ``PlatformHTTPServer``.
@available(anyAppleOS 27.0, *)
public enum PlatformHTTPServerError: Error, Sendable {
    /// The peer reset the stream with the given error code.
    case streamReset(HTTP2ErrorCode)

    /// The TLS handshake completed without negotiating `h2`.
    ///
    /// The associated string is the protocol the peer offered, or `nil` if the peer did not offer ALPN at all.
    case alpnMismatch(String?)

    /// The request headers were missing a required pseudo-header or contained an illegal combination.
    case malformedRequest(String)

    /// The peer sent a `CONNECT` request, which the server does not support.
    case unsupportedConnect

    /// The connection ended while the request was still being received.
    case connectionClosed

    /// The configured host is not an IPv4 address.
    case invalidHost(String)

    /// The selected I/O backend does not exist on this platform or in this build.
    case unavailableIOBackend(PlatformHTTPServerConfiguration.IOBackend)

    /// The configuration enables neither HTTP/2 nor HTTP/3.
    case noHTTPVersion
}
