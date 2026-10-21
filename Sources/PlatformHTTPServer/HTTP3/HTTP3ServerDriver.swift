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

import AsyncStreaming
import BasicContainers
import ContainersPreview
import DequeModule
import HTTP2StateMachine
import HTTPTypes
import Synchronization

/// The streams of an HTTP/3 connection that have a handler.
///
/// Unlike HTTP/2, the requests of HTTP/3 can arrive in any order, because QUIC orders the bytes within a stream but
/// not across streams.
@available(anyAppleOS 27.0, *)
final class HTTP3StreamRegistry: Sendable {
    private struct Entry {
        var inbox: HTTP2StreamInbox
        var endStreamReceived: Bool
    }

    private let streams = Mutex<[UInt64: Entry]>([:])

    var count: Int { self.streams.withLock { $0.count } }

    func open(_ id: UInt64, endStreamReceived: Bool, inbox: HTTP2StreamInbox) {
        self.streams.withLock { $0[id] = Entry(inbox: inbox, endStreamReceived: endStreamReceived) }
    }

    /// Delivers an event to the handler of a stream, unless the handler is done.
    func deliver(_ event: HTTP2StreamEvent, to id: UInt64) {
        self.streams.withLock { streams in
            guard var entry = streams[id], !entry.endStreamReceived else { return }
            switch event {
            case .data(_, let endStream):
                entry.endStreamReceived = endStream
            case .trailers, .reset:
                entry.endStreamReceived = true
            }
            entry.inbox.yield(event)
            if entry.endStreamReceived {
                entry.inbox.finish()
            }
            streams[id] = entry
        }
    }

    func close(_ id: UInt64) {
        let entry = self.streams.withLock { $0.removeValue(forKey: id) }
        entry?.inbox.finish()
    }

    func closeAll() {
        let entries = self.streams.withLock { streams in
            let entries = Array(streams.values)
            streams.removeAll()
            return entries
        }
        for entry in entries {
            entry.inbox.finish()
        }
    }
}

/// The configuration of the HTTP/3 side of the server.
@available(anyAppleOS 27.0, *)
public struct HTTP3ServerConfiguration: Sendable {
    /// The transport configuration of every connection.
    public var quic: QUICConnectionConfiguration

    /// The outbound frames of all streams that the writing side buffers before the streams wait.
    public var outboundQueueHighWatermark: Int

    public init(quic: QUICConnectionConfiguration = .init(), outboundQueueHighWatermark: Int = 64) {
        self.quic = quic
        self.outboundQueueHighWatermark = outboundQueueHighWatermark
    }
}

/// Runs the server side of an HTTP/3 connection.
///
/// Like the ``HTTP2ServerDriver``, the driver runs a reading and a writing side concurrently and starts a child task
/// for every request. The handler gets an ``HTTP2Stream``: its events and outputs are the same for both versions,
/// so that `PlatformHTTPServer` handles the requests of both with the same code. The driver maps the stream IDs and
/// the error codes.
@available(anyAppleOS 27.0, *)
struct HTTP3ServerDriver: Sendable {
    var configuration: HTTP3ServerConfiguration

    init(configuration: HTTP3ServerConfiguration = .init()) {
        self.configuration = configuration
    }

    /// The stream ID that the handler sees for a request stream of QUIC: the request streams 0, 4, 8, ... of the
    /// client become 1, 3, 5, ... like the streams of a client in HTTP/2.
    static func handlerStreamID(_ quicStreamID: UInt64) -> HTTP2StreamID {
        HTTP2StreamID(UInt32(truncatingIfNeeded: (quicStreamID >> 2) * 2 + 1))
    }

    static func quicStreamID(_ handlerStreamID: HTTP2StreamID) -> UInt64 {
        UInt64(handlerStreamID.value - 1) / 2 * 4
    }

    static func h3ErrorCode(_ code: HTTP2StateMachine.HTTP2ErrorCode) -> HTTP3ErrorCode {
        switch code {
        case .noError: .noError
        case .protocolError: .generalProtocolError
        case .refusedStream: .requestRejected
        case .cancel: .requestCancelled
        default: .internalError
        }
    }

    static func h2ErrorCode(_ code: HTTP3ErrorCode) -> HTTP2StateMachine.HTTP2ErrorCode {
        switch code {
        case .noError: .noError
        case .requestRejected: .refusedStream
        case .requestCancelled: .cancel
        case .generalProtocolError, .messageError, .frameUnexpected, .frameError: .protocolError
        default: .internalError
        }
    }

    /// Runs the connection until the client closes it or an error occurs.
    func run(
        connection: HTTP3Connection,
        onStream handler: @escaping @Sendable (consuming HTTP2Stream) async -> Void
    ) async throws {
        let configuration = self.configuration
        let registry = HTTP3StreamRegistry()
        try await connection.withRequestStreams { reader, writer in
            var reader = reader
            var writer: HTTP3OutputWriter? = writer
            try await MultiProducerSingleConsumerAsyncChannel<HTTP2OutboundFrame, Void, any Error>.withChannel(
                throwing: (any Error).self,
                backpressureStrategy: .watermark(
                    low: max(1, configuration.outboundQueueHighWatermark / 4),
                    high: configuration.outboundQueueHighWatermark
                )
            ) { channel, source in
                var channel = channel
                var source = source
                _ = try await withConcurrently {
                    try await Self.readSide(reader: &reader, source: &source, registry: registry, handler: handler)
                } _: {
                    try await Self.writeSide(writer: &writer, channel: &channel)
                }
            }
        }
    }

    private static func readSide(
        reader: inout HTTP3EventReader,
        source: inout HTTP2OutboundSource,
        registry: HTTP3StreamRegistry,
        handler: @escaping @Sendable (consuming HTTP2Stream) async -> Void
    ) async throws {
        var failure: (any Error)? = nil
        do {
            try await withThrowingDiscardingTaskGroup { group in
                defer {
                    registry.closeAll()
                    group.cancelAll()
                }
                var ended = false
                while !ended {
                    var opened = UniqueArray<HTTP2Stream>()
                    ended = try await reader.read { events, finalElement in
                        for index in events.indices {
                            switch events[index] {
                            case .headers(let streamID, let fields, let endStream):
                                let inbox = HTTP2StreamInbox(finished: endStream)
                                registry.open(streamID, endStreamReceived: endStream, inbox: inbox)
                                let id = Self.handlerStreamID(streamID)
                                opened.append(
                                    HTTP2Stream(
                                        id: id,
                                        requestHeaders: Self.hpackHeaders(fields),
                                        requestEndStream: endStream,
                                        inbound: HTTP2StreamInbound(inbox: inbox),
                                        outbound: HTTP2StreamOutbound(id: id, source: source.clone())
                                    )
                                )
                            case .data(let streamID, let payload, let endStream):
                                registry.deliver(.data(payload, endStream: endStream), to: streamID)
                            case .trailers(let streamID, let fields):
                                registry.deliver(.trailers(Self.hpackHeaders(fields)), to: streamID)
                            case .reset(let streamID, let code):
                                registry.deliver(.reset(Self.h2ErrorCode(code)), to: streamID)
                            }
                        }
                        return finalElement != nil
                    }
                    while !opened.isEmpty {
                        let box = Transfer(opened.removeLast())
                        group.addTask {
                            let stream = box.take()
                            let quicID = Self.quicStreamID(stream.id)
                            await handler(stream)
                            registry.close(quicID)
                        }
                    }
                }
            }
        } catch {
            failure = error
        }
        // Ends the writing side once it has written everything that is queued.
        source.clone().finish()
        if let failure, !(failure is CancellationError) {
            throw failure
        }
    }

    private static func writeSide(
        writer: inout HTTP3OutputWriter?,
        channel: inout MultiProducerSingleConsumerAsyncChannel<HTTP2OutboundFrame, Void, any Error>
    ) async throws {
        var outputs = UniqueArray<HTTP3RequestOutput>(minimumCapacity: 64)
        var ended = false
        while !ended {
            ended = try await channel.read { items, finalElement in
                while let item = items.popFirst() {
                    guard case .stream(let id, let output) = item else { continue }
                    let streamID = Self.quicStreamID(id)
                    switch output {
                    case .headers(let headers, let endStream):
                        outputs.append(.headers(streamID: streamID, fields: Self.fields(headers), endStream: endStream))
                    case .data(let payload, let endStream):
                        outputs.append(.data(streamID: streamID, payload: payload, endStream: endStream))
                    case .reset(let code):
                        outputs.append(.reset(streamID: streamID, code: Self.h3ErrorCode(code)))
                    }
                }
                if outputs.count > 0 {
                    try await writer!.write(buffer: &outputs)
                }
                return finalElement != nil
            }
        }
        try await writer.take()!.finish()
    }

    private static func hpackHeaders(_ fields: [HTTPField]) -> HPACKHeaders {
        var headers: [HPACKHeader] = []
        headers.reserveCapacity(fields.count)
        for field in fields {
            headers.append(HPACKHeader(name: field.name.rawName, value: field.value))
        }
        return HPACKHeaders(headers)
    }

    private static func fields(_ headers: HPACKHeaders) -> [HTTPField] {
        var fields: [HTTPField] = []
        fields.reserveCapacity(headers.headers.count)
        for header in headers.headers {
            guard let name = HTTPField.Name(parsed: header.name) else { continue }
            fields.append(HTTPField(name: name, value: header.value))
        }
        return fields
    }
}

/// Moves a value into a child task.
@available(anyAppleOS 27.0, *)
private final class Transfer<Value: ~Copyable>: @unchecked Sendable {
    private var value: Value?

    init(_ value: consuming Value) {
        self.value = consume value
    }

    func take() -> Value {
        self.value.take()!
    }
}
