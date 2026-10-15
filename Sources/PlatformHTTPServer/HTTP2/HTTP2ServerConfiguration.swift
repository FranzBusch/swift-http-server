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

/// The configuration of the server side of an HTTP/2 connection.
@available(anyAppleOS 27.0, *)
public struct HTTP2ServerConfiguration: Sendable {
    /// The number of streams that a client may have open at the same time. The server refuses more.
    public var maxConcurrentStreams: Int

    /// The size of the flow control window of every stream that the server advertises to the client.
    public var initialWindowSize: Int

    /// The number of frames that the streams of a connection may queue for the connection before the streams have
    /// to wait.
    public var outboundQueueHighWatermark: Int

    /// Creates a configuration.
    public init(
        maxConcurrentStreams: Int = 100,
        initialWindowSize: Int = 65535,
        outboundQueueHighWatermark: Int = 64
    ) {
        self.maxConcurrentStreams = maxConcurrentStreams
        self.initialWindowSize = initialWindowSize
        self.outboundQueueHighWatermark = outboundQueueHighWatermark
    }

    /// The settings that the server sends to the client in its connection preface.
    var settings: [HTTP2Setting] {
        [
            HTTP2Setting(parameter: .maxConcurrentStreams, value: UInt32(self.maxConcurrentStreams)),
            HTTP2Setting(parameter: .initialWindowSize, value: UInt32(self.initialWindowSize)),
        ]
    }
}

/// An error that ends an HTTP/2 connection.
@available(anyAppleOS 27.0, *)
public struct HTTP2ConnectionFailure: Error, Sendable, CustomStringConvertible {
    /// The error code that the server sends to the client in its GOAWAY frame.
    public var code: HTTP2ErrorCode

    /// A description of the violation.
    public var reason: String

    /// Creates a failure.
    public init(code: HTTP2ErrorCode, reason: String) {
        self.code = code
        self.reason = reason
    }

    public var description: String {
        "HTTP2ConnectionFailure(\(self.code), \(self.reason))"
    }
}
