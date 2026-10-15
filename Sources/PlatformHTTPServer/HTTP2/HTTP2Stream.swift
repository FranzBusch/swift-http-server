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

public import AsyncStreaming
public import HTTP2StateMachine

public import BasicContainers
import ContainersPreview

/// Something that a peer sent on a stream after the request head.
@available(anyAppleOS 27.0, *)
public enum HTTP2StreamEvent: Sendable {
    /// A DATA frame.
    case data([UInt8], endStream: Bool)
    /// A trailing HEADERS frame. It always ends the stream.
    case trailers(HPACKHeaders)
    /// The peer reset the stream.
    case reset(HTTP2ErrorCode)
}

/// A frame that a stream sends to its peer.
@available(anyAppleOS 27.0, *)
public enum HTTP2StreamOutput: Sendable {
    /// A HEADERS frame.
    case headers(HPACKHeaders, endStream: Bool)
    /// A DATA frame. The driver splits it to respect flow control and the maximum frame size of the peer.
    case data([UInt8], endStream: Bool)
    /// A RST_STREAM frame.
    case reset(HTTP2ErrorCode)
}

/// A frame that the driver writes to the connection, as seen by the writing side of the driver.
@available(anyAppleOS 27.0, *)
enum HTTP2OutboundFrame: Sendable {
    case stream(HTTP2StreamID, HTTP2StreamOutput)
    /// A frame that the reading side produced, for example an acknowledgement of a PING.
    case control(HTTP2Frame)
    /// The peer changed its settings.
    case peerSettings(initialWindowSize: UInt32?, maxFrameSize: UInt32?)
    /// The peer raised a flow control window. Stream 0 is the connection.
    case peerWindowUpdate(HTTP2StreamID, UInt32)
}

@available(anyAppleOS 27.0, *)
typealias HTTP2OutboundSource = MultiProducerSingleConsumerAsyncChannel<HTTP2OutboundFrame, Void, any Error>.Source

/// The inbound side of a stream: what the peer sends after the request head.
@available(anyAppleOS 27.0, *)
public struct HTTP2StreamInbound: ~Copyable, @unchecked Sendable {
    private var iterator: AsyncStream<HTTP2StreamEvent>.Iterator

    init(iterator: AsyncStream<HTTP2StreamEvent>.Iterator) {
        self.iterator = iterator
    }

    /// The next event on the stream, or `nil` if the stream ended without more events.
    ///
    /// The stream ends when the connection closes, or when the stream reset or its last event was delivered.
    public mutating func next() async -> HTTP2StreamEvent? {
        await self.iterator.next()
    }
}

/// The outbound side of a stream: what the server sends to the peer.
@available(anyAppleOS 27.0, *)
public struct HTTP2StreamOutbound: ~Copyable, Sendable {
    /// The identifier of the stream.
    public let id: HTTP2StreamID

    private var source: HTTP2OutboundSource

    init(id: HTTP2StreamID, source: consuming HTTP2OutboundSource) {
        self.id = id
        self.source = source
    }

    /// Creates another outbound side of the same stream, for example to reset the stream after the response was
    /// handed to a consumer.
    public mutating func clone() -> HTTP2StreamOutbound {
        HTTP2StreamOutbound(id: self.id, source: self.source.clone())
    }

    /// Sends all outputs in order.
    ///
    /// The call suspends while the connection is not ready to take more frames.
    public mutating func send(_ outputs: consuming UniqueArray<HTTP2StreamOutput>) async throws {
        var frames = UniqueArray<HTTP2OutboundFrame>(minimumCapacity: outputs.count)
        let id = self.id
        outputs.consumeAll { span in
            while !span.isEmpty {
                frames.append(.stream(id, span.removeFirst()))
            }
        }
        try await self.source.write(buffer: &frames)
    }

    /// Sends a single output.
    public mutating func send(_ output: HTTP2StreamOutput) async throws {
        var outputs = UniqueArray<HTTP2StreamOutput>(minimumCapacity: 1)
        outputs.append(output)
        try await self.send(outputs)
    }
}

/// A stream that a client opened on a connection.
///
/// The ``HTTP2ServerDriver`` creates a stream for the first HEADERS frame of every request and runs the
/// handler of the server in its own child task. The handler owns the stream: it reads the rest of the request from
/// ``inbound`` and writes the response to ``outbound``.
@available(anyAppleOS 27.0, *)
@frozen
public struct HTTP2Stream: ~Copyable, Sendable {
    /// The identifier of the stream.
    public let id: HTTP2StreamID

    /// The headers of the request.
    public let requestHeaders: HPACKHeaders

    /// Whether the request ended with its headers, so that no body or trailers follow.
    public let requestEndStream: Bool

    /// The events after the request headers.
    public var inbound: HTTP2StreamInbound

    /// The sending side of the stream.
    public var outbound: HTTP2StreamOutbound

    init(
        id: HTTP2StreamID,
        requestHeaders: HPACKHeaders,
        requestEndStream: Bool,
        inbound: consuming HTTP2StreamInbound,
        outbound: consuming HTTP2StreamOutbound
    ) {
        self.id = id
        self.requestHeaders = requestHeaders
        self.requestEndStream = requestEndStream
        self.inbound = inbound
        self.outbound = outbound
    }
}
