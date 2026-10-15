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

import BasicContainers
import ContainersPreview
import DequeModule

/// Runs the server side of an HTTP/2 connection on top of a reader and a writer of frames.
///
/// The driver reads the frames of the client, applies the connection level frames such as SETTINGS and PING, decodes
/// the headers and routes the frames to their streams. For every new request it starts a child task that runs the
/// handler with an ``HTTP2Stream``. The streams write their frames back through the driver, which encodes the
/// headers, applies flow control, and writes the frames to the connection.
///
/// The driver consists of two concurrent halves, one that reads and one that writes, so that a slow peer that does
/// not read cannot stall the processing of the frames that it sends.
///
/// ```swift
/// let driver = HTTP2ServerDriver()
/// try await driver.run(reader: frameReader, writer: frameWriter) { stream in
///     // Handle the request and write the response.
/// }
/// ```
@available(anyAppleOS 27.0, *)
public struct HTTP2ServerDriver: Sendable {
    /// The configuration of the connection.
    public var configuration: HTTP2ServerConfiguration

    /// Creates a driver.
    public init(configuration: HTTP2ServerConfiguration = .init()) {
        self.configuration = configuration
    }

    /// Runs the connection until the client closes it or an error occurs.
    ///
    /// The handler runs in a child task of the caller for every stream that the client opens. When the connection
    /// ends, the tasks of the handlers are cancelled and awaited before this method returns.
    ///
    /// - Parameters:
    ///   - reader: The frames that the client sends. It has to start with the SETTINGS frame of the client.
    ///   - writer: The frames that are sent to the client.
    ///   - handler: Handles one stream. It owns the stream.
    /// - Throws: The error that ended the connection, if the client did not close it cleanly.
    public func run<
        FrameReader: AsyncReader<HTTP2Frame, any Error, Void> & Sendable & ~Copyable & ~Escapable,
        FrameWriter: CallerAsyncWriter<HTTP2Frame, any Error, Void> & Sendable & ~Copyable & ~Escapable
    >(
        reader: consuming FrameReader,
        writer: consuming FrameWriter,
        onStream handler: @escaping @Sendable (consuming HTTP2Stream) async -> Void
    ) async throws {
        let configuration = self.configuration
        let registry = HTTP2StreamRegistry()
        var reader = reader
        var writer: FrameWriter? = writer

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
                try await Self.readSide(
                    reader: &reader,
                    source: &source,
                    registry: registry,
                    configuration: configuration,
                    handler: handler
                )
            } _: {
                try await Self.writeSide(writer: &writer, channel: &channel, configuration: configuration)
            }
        }
    }

    // MARK: - Reading side

    private struct ReadState: ~Copyable {
        var connection = HTTP2ConnectionStateMachine(role: .server)
        var decoder = HPACKDecoder()
        var prefaceReceived = false
        var unacknowledgedConnectionData = 0
    }

    private static func readSide<
        FrameReader: AsyncReader<HTTP2Frame, any Error, Void> & Sendable & ~Copyable & ~Escapable
    >(
        reader: inout FrameReader,
        source: inout HTTP2OutboundSource,
        registry: HTTP2StreamRegistry,
        configuration: HTTP2ServerConfiguration,
        handler: @escaping @Sendable (consuming HTTP2Stream) async -> Void
    ) async throws {
        var state = ReadState()
        _ = state.connection.sendPreface(settings: configuration.settings)

        var failure: (any Error)? = nil
        do {
            try await withThrowingDiscardingTaskGroup { group in
                defer {
                    // Whatever ends the loop, no stream receives anything anymore and the handlers should stop.
                    registry.closeAll()
                    group.cancelAll()
                }

                var ended = false
                while !ended {
                    ended = try await reader.read { frames, finalElement in
                        var index = frames.startIndex
                        while index != frames.endIndex {
                            let span = frames.nextSpan(after: &index)
                            for position in 0..<span.count {
                                let newStream = try await Self.handle(
                                    span[position],
                                    state: &state,
                                    source: &source,
                                    registry: registry,
                                    configuration: configuration
                                )
                                if let newStream {
                                    let box = Transfer(newStream)
                                    group.addTask {
                                        let stream = box.take()
                                        let id = stream.id
                                        await handler(stream)
                                        registry.close(id)
                                    }
                                }
                            }
                        }
                        return finalElement != nil
                    }
                }
            }
        } catch {
            failure = error
        }

        if let failure {
            // Tell the client why the connection ends. This is best effort: the writing side might be gone.
            var goAway = UniqueArray<HTTP2OutboundFrame>()
            let code = (failure as? HTTP2ConnectionFailure)?.code ?? .internalError
            goAway.append(
                .control(
                    HTTP2Frame(
                        streamID: .connectionStream,
                        payload: .goAway(
                            .init(lastStreamID: HTTP2StreamID(registry.lastPeerStreamID), errorCode: code)
                        )
                    )
                )
            )
            try? await source.write(buffer: &goAway)
        }

        // Ends the writing side once it has written everything that is queued.
        source.clone().finish()
        if let failure, !(failure is CancellationError) {
            throw failure
        }
    }

    /// Handles one frame of the client.
    ///
    /// - Returns: A new stream if the frame opened one.
    private static func handle(
        _ frame: HTTP2Frame,
        state: inout ReadState,
        source: inout HTTP2OutboundSource,
        registry: HTTP2StreamRegistry,
        configuration: HTTP2ServerConfiguration
    ) async throws -> HTTP2Stream? {
        if !state.prefaceReceived {
            guard case .settings(.settings) = frame.payload else {
                throw HTTP2ConnectionFailure(
                    code: .protocolError,
                    reason: "The connection preface of the client has to contain a SETTINGS frame"
                )
            }
        }

        switch frame.payload {
        case .settings(.settings(let settings)):
            if state.prefaceReceived {
                switch state.connection.receiveSettings(settings) {
                case .acknowledgeSettings:
                    break
                case .error:
                    throw HTTP2ConnectionFailure(code: .protocolError, reason: "Invalid SETTINGS frame")
                }
            } else {
                switch state.connection.receivePreface(settings: settings) {
                case .received:
                    state.prefaceReceived = true
                case .error:
                    throw HTTP2ConnectionFailure(code: .protocolError, reason: "Invalid connection preface")
                }
            }
            var initialWindowSize: UInt32? = nil
            var maxFrameSize: UInt32? = nil
            for setting in settings {
                if setting.parameter == .initialWindowSize {
                    guard setting.value <= 0x7fff_ffff else {
                        throw HTTP2ConnectionFailure(code: .flowControlError, reason: "Invalid window size")
                    }
                    initialWindowSize = setting.value
                } else if setting.parameter == .maxFrameSize {
                    guard (16384...16_777_215).contains(setting.value) else {
                        throw HTTP2ConnectionFailure(code: .protocolError, reason: "Invalid maximum frame size")
                    }
                    maxFrameSize = setting.value
                }
            }
            var outbound = UniqueArray<HTTP2OutboundFrame>(minimumCapacity: 2)
            outbound.append(.control(HTTP2Frame(streamID: .connectionStream, payload: .settings(.ack))))
            if initialWindowSize != nil || maxFrameSize != nil {
                outbound.append(.peerSettings(initialWindowSize: initialWindowSize, maxFrameSize: maxFrameSize))
            }
            try await source.write(buffer: &outbound)
            return nil

        case .settings(.ack):
            return nil

        case .ping(let data, let ack):
            switch state.connection.receivePing(data: data, ack: ack) {
            case .sendPingAck(let pingData):
                var outbound = UniqueArray<HTTP2OutboundFrame>(minimumCapacity: 1)
                outbound.append(
                    .control(HTTP2Frame(streamID: .connectionStream, payload: .ping(pingData, ack: true)))
                )
                try await source.write(buffer: &outbound)
            case .pingAcknowledged:
                break
            case .error:
                throw HTTP2ConnectionFailure(code: .protocolError, reason: "Invalid PING frame")
            }
            return nil

        case .goAway(let goAway):
            switch state.connection.receiveGoAway(lastStreamID: goAway.lastStreamID, errorCode: goAway.errorCode) {
            case .goingAway:
                break
            case .error:
                throw HTTP2ConnectionFailure(code: .protocolError, reason: "Invalid GOAWAY frame")
            }
            return nil

        case .priority:
            return nil

        case .windowUpdate(let increment):
            guard increment > 0 else {
                throw HTTP2ConnectionFailure(code: .protocolError, reason: "WINDOW_UPDATE without increment")
            }
            if frame.streamID == .connectionStream {
                switch state.connection.connectionWindowUpdate(by: increment) {
                case .updated:
                    break
                case .error:
                    throw HTTP2ConnectionFailure(code: .flowControlError, reason: "Connection window overflow")
                }
            }
            var outbound = UniqueArray<HTTP2OutboundFrame>(minimumCapacity: 1)
            outbound.append(.peerWindowUpdate(frame.streamID, increment))
            try await source.write(buffer: &outbound)
            return nil

        case .rstStream(let code):
            guard frame.streamID != .connectionStream else {
                throw HTTP2ConnectionFailure(code: .protocolError, reason: "RST_STREAM on the connection")
            }
            _ = registry.deliver(.reset(code), to: frame.streamID)
            return nil

        case .data(let payload):
            guard frame.streamID != .connectionStream else {
                throw HTTP2ConnectionFailure(code: .protocolError, reason: "DATA on the connection")
            }
            let length = payload.data.count
            switch registry.deliver(.data(payload.data, endStream: payload.endStream), to: frame.streamID) {
            case .delivered:
                // The server consumes the data as fast as the streams read it from their queues, so the windows are
                // replenished right away. This keeps the client sending, but gives no back pressure to it.
                var outbound = UniqueArray<HTTP2OutboundFrame>(minimumCapacity: 2)
                if length > 0 && !payload.endStream {
                    outbound.append(
                        .control(
                            HTTP2Frame(
                                streamID: frame.streamID,
                                payload: .windowUpdate(windowSizeIncrement: UInt32(length))
                            )
                        )
                    )
                }
                state.unacknowledgedConnectionData += length
                if state.unacknowledgedConnectionData >= 16384 {
                    outbound.append(
                        .control(
                            HTTP2Frame(
                                streamID: .connectionStream,
                                payload: .windowUpdate(windowSizeIncrement: UInt32(state.unacknowledgedConnectionData))
                            )
                        )
                    )
                    state.unacknowledgedConnectionData = 0
                }
                if outbound.count > 0 {
                    try await source.write(buffer: &outbound)
                }
            case .ignored:
                state.unacknowledgedConnectionData += length
            case .idleStream:
                throw HTTP2ConnectionFailure(code: .protocolError, reason: "DATA on an idle stream")
            case .streamClosed:
                var outbound = UniqueArray<HTTP2OutboundFrame>(minimumCapacity: 1)
                outbound.append(.stream(frame.streamID, .reset(.streamClosed)))
                try await source.write(buffer: &outbound)
            }
            return nil

        case .headers(let payload):
            guard frame.streamID != .connectionStream else {
                throw HTTP2ConnectionFailure(code: .protocolError, reason: "HEADERS on the connection")
            }
            // Every header block has to pass the decoder, also the ones of refused streams, because the dynamic table
            // is shared by all streams of the connection.
            let headers: HPACKHeaders
            do {
                headers = try state.decoder.decode(payload.headerBlock)
            } catch {
                throw HTTP2ConnectionFailure(code: .compressionError, reason: "Invalid header block: \(error)")
            }

            if registry.isNewPeerStream(frame.streamID) {
                if registry.count >= configuration.maxConcurrentStreams {
                    var outbound = UniqueArray<HTTP2OutboundFrame>(minimumCapacity: 1)
                    outbound.append(.stream(frame.streamID, .reset(.refusedStream)))
                    try await source.write(buffer: &outbound)
                    return nil
                }
                let (events, continuation) = AsyncStream<HTTP2StreamEvent>.makeStream()
                registry.open(frame.streamID, endStreamReceived: payload.endStream, continuation: continuation)
                if payload.endStream {
                    continuation.finish()
                }
                return HTTP2Stream(
                    id: frame.streamID,
                    requestHeaders: headers,
                    requestEndStream: payload.endStream,
                    inbound: HTTP2StreamInbound(iterator: events.makeAsyncIterator()),
                    outbound: HTTP2StreamOutbound(id: frame.streamID, source: source.clone())
                )
            }

            guard payload.endStream else {
                if registry.contains(frame.streamID) {
                    throw HTTP2ConnectionFailure(code: .protocolError, reason: "Trailers without END_STREAM")
                }
                return nil
            }
            switch registry.deliver(.trailers(headers), to: frame.streamID) {
            case .delivered, .ignored:
                break
            case .idleStream:
                throw HTTP2ConnectionFailure(code: .protocolError, reason: "HEADERS on an invalid stream")
            case .streamClosed:
                var outbound = UniqueArray<HTTP2OutboundFrame>(minimumCapacity: 1)
                outbound.append(.stream(frame.streamID, .reset(.streamClosed)))
                try await source.write(buffer: &outbound)
            }
            return nil
        }
    }

    // MARK: - Writing side

    private static func writeSide<
        FrameWriter: CallerAsyncWriter<HTTP2Frame, any Error, Void> & Sendable & ~Copyable & ~Escapable
    >(
        writer: inout FrameWriter?,
        channel: inout MultiProducerSingleConsumerAsyncChannel<HTTP2OutboundFrame, Void, any Error>,
        configuration: HTTP2ServerConfiguration
    ) async throws {
        var state = HTTP2OutboundState()
        var frames = UniqueArray<HTTP2Frame>(minimumCapacity: 64)

        frames.append(
            HTTP2Frame(streamID: .connectionStream, payload: .settings(.settings(configuration.settings)))
        )
        try await writer!.write(buffer: &frames)

        var ended = false
        while !ended {
            ended = try await channel.read { items, finalElement in
                while let item = items.popFirst() {
                    state.process(item, into: &frames)
                }
                if frames.count > 0 {
                    try await writer!.write(buffer: &frames)
                }
                return finalElement != nil
            }
        }

        try await writer.take()!.finish()
    }
}

/// Moves a value into a child task.
///
/// The receiving task takes the value exactly once.
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
