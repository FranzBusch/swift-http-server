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
@_spi(PackageInternal) import HTTP3StateMachine
import HTTPTypes
@_spi(PackageInternal) import QPACKStateMachine

/// What the client sends on a request stream of an HTTP/3 connection.
@available(anyAppleOS 27.0, *)
enum HTTP3RequestEvent: Sendable {
    /// The request head. It is the first event of a stream.
    case headers(streamID: UInt64, fields: [HTTPField], endStream: Bool)
    case data(streamID: UInt64, payload: [UInt8], endStream: Bool)
    /// The trailers, which end the stream.
    case trailers(streamID: UInt64, fields: [HTTPField])
    /// The client reset the stream or asked the server to stop sending, or the stream was malformed.
    case reset(streamID: UInt64, code: HTTP3ErrorCode)
}

/// What the server sends on a request stream of an HTTP/3 connection.
@available(anyAppleOS 27.0, *)
enum HTTP3RequestOutput: Sendable {
    case headers(streamID: UInt64, fields: [HTTPField], endStream: Bool)
    case data(streamID: UInt64, payload: [UInt8], endStream: Bool)
    case reset(streamID: UInt64, code: HTTP3ErrorCode)
}

/// An HTTP/3 connection on top of a QUIC connection (RFC 9114).
///
/// The connection maps the streams of QUIC to HTTP/3: it opens the control stream of the server with its SETTINGS,
/// reads the control stream of the client, drains the QPACK streams, and parses the request streams into frames and
/// field sections. The driver above it, the ``HTTP3ServerDriver``, sees request streams only, like
/// ``HTTPConnection`` turns TLS bytes into the frames of HTTP/2.
///
/// The server's QPACK decoder has a dynamic table capacity of 0, so the client encodes with the static table and
/// literals only, and neither side needs its encoder or decoder stream (RFC 9204, section 4.2).
@available(anyAppleOS 27.0, *)
struct HTTP3Connection: Sendable {
    /// The unidirectional stream of the server that carries its control frames.
    static var controlStreamID: UInt64 { 3 }

    let quic: QUICConnection

    init(quic: QUICConnection) {
        self.quic = quic
    }

    /// Opens the control stream and provides the events and the outputs of the request streams.
    func withRequestStreams<Return: ~Copyable>(
        _ body: (consuming HTTP3EventReader, consuming HTTP3OutputWriter) async throws -> Return
    ) async throws -> Return {
        try await self.quic.withSplit { reader, writer in
            var writer = writer
            var frames = UniqueArray<QUICFrame>(minimumCapacity: 1)
            frames.append(
                .stream(
                    QUICStreamFrame(
                        streamID: Self.controlStreamID,
                        offset: 0,
                        data: HTTP3Wire.controlStreamPreface(),
                        fin: false
                    )
                )
            )
            try await writer.write(buffer: &frames)
            return try await body(
                HTTP3EventReader(upstream: reader, quic: self.quic),
                HTTP3OutputWriter(downstream: writer)
            )
        }
    }
}

/// The encoding of the frames that the server writes (RFC 9114, section 7).
@available(anyAppleOS 27.0, *)
enum HTTP3Wire {
    static func appendVarint(_ value: UInt64, to bytes: inout [UInt8]) {
        switch value {
        case 0..<(1 << 6):
            bytes.append(UInt8(value))
        case (1 << 6)..<(1 << 14):
            bytes.append(0x40 | UInt8(value >> 8))
            bytes.append(UInt8(truncatingIfNeeded: value))
        case (1 << 14)..<(1 << 30):
            bytes.append(0x80 | UInt8(value >> 24))
            for shift in stride(from: 16, through: 0, by: -8) {
                bytes.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
            }
        default:
            bytes.append(0xc0 | UInt8(value >> 56))
            for shift in stride(from: 48, through: 0, by: -8) {
                bytes.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
            }
        }
    }

    /// Reads a variable-length integer at the start of the bytes.
    static func readVarint(_ bytes: [UInt8]) -> (value: UInt64, length: Int)? {
        guard let first = bytes.first else { return nil }
        let length = 1 << Int(first >> 6)
        guard bytes.count >= length else { return nil }
        var value = UInt64(first & 0x3f)
        for index in 1..<length {
            value = value << 8 | UInt64(bytes[index])
        }
        return (value, length)
    }

    /// The stream type and the SETTINGS frame that open the control stream of the server.
    static func controlStreamPreface() -> [UInt8] {
        var settings: [UInt8] = []
        // SETTINGS_QPACK_MAX_TABLE_CAPACITY and SETTINGS_QPACK_BLOCKED_STREAMS: no dynamic table.
        Self.appendVarint(0x01, to: &settings)
        Self.appendVarint(0, to: &settings)
        Self.appendVarint(0x07, to: &settings)
        Self.appendVarint(0, to: &settings)

        var bytes: [UInt8] = []
        Self.appendVarint(HTTP3StreamType.Unidirectional.control.rawValue, to: &bytes)
        Self.appendVarint(0x04, to: &bytes)
        Self.appendVarint(UInt64(settings.count), to: &bytes)
        bytes.append(contentsOf: settings)
        return bytes
    }

    /// Appends a HEADERS frame with the fields encoded with the static table of QPACK.
    static func appendHeaders(_ fields: [HTTPField], to bytes: inout [UInt8]) {
        let section = StaticQPACKEncoder().encode(headers: fields)
        var payload: [UInt8] = []
        payload.reserveCapacity(16 * fields.count)
        _ = payload.writeFieldSectionPrefix(section.prefix)
        for line in section.lines {
            _ = payload.writeFieldLine(line, preferHuffmanEncoding: false)
        }
        Self.appendVarint(0x01, to: &bytes)
        Self.appendVarint(UInt64(payload.count), to: &bytes)
        bytes.append(contentsOf: payload)
    }

    /// Appends a DATA frame.
    static func appendData(_ payload: [UInt8], to bytes: inout [UInt8]) {
        Self.appendVarint(0x00, to: &bytes)
        Self.appendVarint(UInt64(payload.count), to: &bytes)
        bytes.append(contentsOf: payload)
    }

    /// The bytes of a GOAWAY frame.
    static func goaway(_ id: UInt64) -> [UInt8] {
        var payload: [UInt8] = []
        Self.appendVarint(id, to: &payload)
        var bytes: [UInt8] = []
        Self.appendVarint(0x07, to: &bytes)
        Self.appendVarint(UInt64(payload.count), to: &bytes)
        bytes.append(contentsOf: payload)
        return bytes
    }
}

/// The frame decoder of one stream of the client.
@available(anyAppleOS 27.0, *)
private final class HTTP3InboundStream {
    var machine: HTTP3StreamStateMachine
    var receivedHeaders = false

    init(type: HTTP3StreamType.Framed) {
        self.machine = HTTP3StreamStateMachine(streamType: type, incoming: true, preferHuffmanEncoding: false)
    }
}

/// A unidirectional stream of the client.
@available(anyAppleOS 27.0, *)
private enum HTTP3UnidirectionalStream {
    /// The stream type is not complete yet.
    case pendingType([UInt8])
    case control(HTTP3InboundStream)
    /// A QPACK stream or an unknown type, whose bytes are dropped.
    case discard
}

/// A failure that ends the connection with an HTTP/3 error code (RFC 9114, section 8).
@available(anyAppleOS 27.0, *)
struct HTTP3ConnectionFailure: Error, Sendable {
    var code: HTTP3ErrorCode
    var reason: String
}

/// Reads the events of the request streams of an ``HTTP3Connection``.
@available(anyAppleOS 27.0, *)
struct HTTP3EventReader: AsyncReader, ~Copyable {
    typealias ReadElement = HTTP3RequestEvent
    typealias ReadFailure = any Error
    typealias Buffer = UniqueArray<HTTP3RequestEvent>
    typealias FinalElement = Void

    private var upstream: QUICFrameReader
    private let quic: QUICConnection
    private var requestStreams: [UInt64: HTTP3InboundStream] = [:]
    private var unidirectionalStreams: [UInt64: HTTP3UnidirectionalStream] = [:]
    private var hasControlStream = false
    private var decoder = QPACKDecoder(dynamicTableMaxCapacity: 0)
    private var events = UniqueArray<HTTP3RequestEvent>()

    init(upstream: consuming QUICFrameReader, quic: QUICConnection) {
        self.upstream = upstream
        self.quic = quic
    }

    mutating func read<Return: ~Copyable, Failure: Error>(
        body: (inout UniqueArray<HTTP3RequestEvent>, consuming Void?) async throws(Failure) -> Return
    ) async throws(EitherError<any Error, Failure>) -> Return {
        self.events.removeAll(keepingCapacity: true)
        var ended = false
        do {
            while self.events.isEmpty && !ended {
                var frames: [QUICFrame] = []
                ended = try await self.upstream.read { buffer, finalElement in
                    frames.reserveCapacity(buffer.count)
                    for index in buffer.indices {
                        frames.append(buffer[index])
                    }
                    return finalElement != nil
                }
                for frame in frames {
                    try self.handle(frame)
                }
            }
        } catch let failure as HTTP3ConnectionFailure {
            self.quic.close(applicationErrorCode: failure.code.rawValue, reason: failure.reason)
            throw .first(failure)
        } catch {
            throw .first(error)
        }

        do throws(Failure) {
            return try await body(&self.events, ended ? () : nil)
        } catch {
            throw .second(error)
        }
    }

    private static func isClientBidirectional(_ id: UInt64) -> Bool { id & 0x03 == 0 }
    private static func isClientUnidirectional(_ id: UInt64) -> Bool { id & 0x03 == 2 }

    private mutating func handle(_ frame: QUICFrame) throws {
        switch frame {
        case .stream(let stream):
            if Self.isClientBidirectional(stream.streamID) {
                try self.handleRequestBytes(stream)
            } else if Self.isClientUnidirectional(stream.streamID) {
                try self.handleUnidirectionalBytes(stream)
            }

        case .resetStream(let streamID, let code, _):
            if Self.isClientBidirectional(streamID) {
                if self.requestStreams.removeValue(forKey: streamID) != nil {
                    self.events.append(.reset(streamID: streamID, code: HTTP3ErrorCode(rawValue: code)))
                }
            } else if case .control = self.unidirectionalStreams[streamID] {
                throw HTTP3ConnectionFailure(code: .closedCriticalStream, reason: "The control stream was reset")
            }

        case .stopSending(let streamID, let code):
            guard Self.isClientBidirectional(streamID) else {
                if streamID == HTTP3Connection.controlStreamID {
                    throw HTTP3ConnectionFailure(code: .closedCriticalStream, reason: "STOP_SENDING on the control stream")
                }
                return
            }
            // The client does not want the response anymore: the stream is reset, and the handler learns it.
            self.quic.reset(streamID: streamID, applicationErrorCode: HTTP3ErrorCode.requestCancelled.rawValue)
            self.events.append(.reset(streamID: streamID, code: HTTP3ErrorCode(rawValue: code)))

        default:
            break
        }
    }

    // MARK: Request streams

    private mutating func handleRequestBytes(_ frame: QUICStreamFrame) throws {
        let stream: HTTP3InboundStream
        if let existing = self.requestStreams[frame.streamID] {
            stream = existing
        } else if frame.offset == 0 {
            stream = HTTP3InboundStream(type: .request)
            self.requestStreams[frame.streamID] = stream
        } else {
            // The stream ended before; what follows is not delivered.
            return
        }
        stream.machine.buffer(frame.data)
        if frame.fin {
            stream.machine.inputClosed()
        }

        while true {
            switch stream.machine.decodeNext() {
            case .returnFrame(let decoded):
                switch decoded {
                case .headers(let headers):
                    if stream.receivedHeaders {
                        self.events.append(.trailers(streamID: frame.streamID, fields: headers.fields))
                    } else {
                        stream.receivedHeaders = true
                        self.events.append(.headers(streamID: frame.streamID, fields: headers.fields, endStream: false))
                    }
                case .data(let data):
                    self.events.append(.data(streamID: frame.streamID, payload: data.payload, endStream: false))
                default:
                    // The validator rejects the other frames on request streams.
                    break
                }

            case .decodeHeader(let partial):
                self.decode(partial, on: frame.streamID, into: stream)

            case .inputClosed(let closed):
                self.requestStreams.removeValue(forKey: frame.streamID)
                switch closed {
                case .emitEvent:
                    self.markEnd(of: frame.streamID)
                case .emitErrorAndEvent(let error), .resetStream(let error):
                    self.resetRequest(frame.streamID, code: error.h3ErrorCode ?? .requestIncomplete)
                }
                return

            case .emitStreamError(let error):
                self.requestStreams.removeValue(forKey: frame.streamID)
                self.resetRequest(frame.streamID, code: error.h3ErrorCode ?? .messageError)
                return

            case .emitConnectionError(let error):
                throw HTTP3ConnectionFailure(code: error.h3ErrorCode ?? .generalProtocolError, reason: error.message)

            case .callAgain:
                continue

            case .needMoreBytes, .alreadyClosed, .previousError:
                return
            }
        }
    }

    private mutating func decode(_ partial: HTTP3PartialFrame.Headers, on streamID: UInt64, into stream: HTTP3InboundStream) {
        let section = partial.fieldSection
        guard let prefix = self.decoder.decodeFieldSectionPrefix(section.prefix) else {
            stream.machine.gotHeaderDecodeError(
                HTTP3Error(code: .qpackDecoderError, message: "Invalid field section prefix", cause: nil, errorCode: .qpackDecompressionFailed, location: .here()),
                isConnectionError: true
            )
            return
        }
        switch self.decoder.decodeFieldSection(prefix: prefix, lines: section.lines, streamID: QUICStreamID(rawValue: streamID)) {
        case .success(let fields, _):
            stream.machine.gotHeaderDecodeResult(fields)
        case .missingInsertCount, .error:
            // Without a dynamic table, a section that refers to one cannot be decoded.
            stream.machine.gotHeaderDecodeError(
                HTTP3Error(code: .qpackDecoderError, message: "Invalid field section", cause: nil, errorCode: .qpackDecompressionFailed, location: .here()),
                isConnectionError: true
            )
        }
    }

    /// Marks the last event of the stream as the end of the stream, or adds an empty one.
    private mutating func markEnd(of streamID: UInt64) {
        var index = self.events.count - 1
        while index >= 0 {
            switch self.events[index] {
            case .headers(let id, let fields, _) where id == streamID:
                self.events[index] = .headers(streamID: id, fields: fields, endStream: true)
                return
            case .data(let id, let payload, _) where id == streamID:
                self.events[index] = .data(streamID: id, payload: payload, endStream: true)
                return
            case .trailers(let id, _) where id == streamID:
                return
            default:
                index -= 1
            }
        }
        self.events.append(.data(streamID: streamID, payload: [], endStream: true))
    }

    private mutating func resetRequest(_ streamID: UInt64, code: HTTP3ErrorCode) {
        self.quic.stopSending(streamID: streamID, applicationErrorCode: code.rawValue)
        self.quic.reset(streamID: streamID, applicationErrorCode: code.rawValue)
        self.events.append(.reset(streamID: streamID, code: code))
    }

    // MARK: Unidirectional streams

    private mutating func handleUnidirectionalBytes(_ frame: QUICStreamFrame) throws {
        var state = self.unidirectionalStreams[frame.streamID] ?? .pendingType([])
        var bytes = frame.data
        if case .pendingType(let pending) = state {
            bytes = pending + bytes
            guard let (rawType, length) = HTTP3Wire.readVarint(bytes) else {
                self.unidirectionalStreams[frame.streamID] = .pendingType(bytes)
                return
            }
            bytes.removeFirst(length)
            switch HTTP3StreamType.Unidirectional(rawValue: rawType) {
            case .control:
                guard !self.hasControlStream else {
                    throw HTTP3ConnectionFailure(code: .streamCreationError, reason: "A second control stream")
                }
                self.hasControlStream = true
                state = .control(HTTP3InboundStream(type: .control))
            case .qpackEncoder, .qpackDecoder:
                state = .discard
            case .push:
                throw HTTP3ConnectionFailure(code: .streamCreationError, reason: "A client must not open push streams")
            case .unknown:
                // Unknown stream types are ignored (RFC 9114, section 6.2).
                self.quic.stopSending(streamID: frame.streamID, applicationErrorCode: HTTP3ErrorCode.streamCreationError.rawValue)
                state = .discard
            }
        }
        self.unidirectionalStreams[frame.streamID] = state

        switch state {
        case .control(let control):
            control.machine.buffer(bytes)
            if frame.fin {
                throw HTTP3ConnectionFailure(code: .closedCriticalStream, reason: "The control stream was closed")
            }
            while true {
                switch control.machine.decodeNext() {
                case .returnFrame:
                    // SETTINGS of a client hold nothing that this server uses: it does not encode with a dynamic
                    // table, sends no datagrams and no pushes. GOAWAY of a client concerns pushes. The validator
                    // checks the order and the types of the frames.
                    continue
                case .emitConnectionError(let error), .emitStreamError(let error):
                    throw HTTP3ConnectionFailure(code: error.h3ErrorCode ?? .frameUnexpected, reason: error.message)
                case .inputClosed:
                    throw HTTP3ConnectionFailure(code: .closedCriticalStream, reason: "The control stream was closed")
                case .callAgain:
                    continue
                case .decodeHeader, .needMoreBytes, .alreadyClosed, .previousError:
                    return
                }
            }
        case .discard, .pendingType:
            return
        }
    }
}

/// Writes the outputs of the request streams of an ``HTTP3Connection``.
@available(anyAppleOS 27.0, *)
struct HTTP3OutputWriter: CallerAsyncWriter, ~Copyable, Sendable {
    typealias WriteElement = HTTP3RequestOutput
    typealias WriteFailure = any Error
    typealias FinalElement = Void

    private var downstream: QUICFrameWriter
    private var frames = UniqueArray<QUICFrame>()

    init(downstream: consuming QUICFrameWriter) {
        self.downstream = downstream
    }

    mutating func write<Buffer: RangeReplaceableContainer<HTTP3RequestOutput> & ~Copyable>(
        buffer: inout Buffer
    ) async throws(any Error) where Buffer.Element: ~Copyable {
        self.frames.removeAll(keepingCapacity: true)
        // The outputs of a stream that follow each other go out in one STREAM frame.
        var pendingStream: UInt64? = nil
        var pendingBytes: [UInt8] = []
        func flush(fin: Bool, into frames: inout UniqueArray<QUICFrame>) {
            if let streamID = pendingStream, fin || !pendingBytes.isEmpty {
                frames.append(.stream(QUICStreamFrame(streamID: streamID, offset: 0, data: pendingBytes, fin: fin)))
            }
            pendingStream = nil
            pendingBytes = []
        }

        var index = buffer.startIndex
        while index < buffer.endIndex {
            let span = buffer.nextSpan(after: &index)
            for position in span.indices {
                switch span[position] {
                case .headers(let streamID, let fields, let endStream):
                    if pendingStream != streamID { flush(fin: false, into: &self.frames) }
                    pendingStream = streamID
                    HTTP3Wire.appendHeaders(fields, to: &pendingBytes)
                    if endStream { flush(fin: true, into: &self.frames) }
                case .data(let streamID, let payload, let endStream):
                    if pendingStream != streamID { flush(fin: false, into: &self.frames) }
                    pendingStream = streamID
                    if !payload.isEmpty {
                        HTTP3Wire.appendData(payload, to: &pendingBytes)
                    }
                    if endStream { flush(fin: true, into: &self.frames) }
                case .reset(let streamID, let code):
                    if pendingStream == streamID {
                        pendingStream = nil
                        pendingBytes = []
                    } else {
                        flush(fin: false, into: &self.frames)
                    }
                    self.frames.append(.resetStream(streamID: streamID, applicationErrorCode: code.rawValue, finalSize: 0))
                    self.frames.append(.stopSending(streamID: streamID, applicationErrorCode: code.rawValue))
                }
            }
        }
        flush(fin: false, into: &self.frames)
        buffer.removeAll()
        try await self.downstream.write(buffer: &self.frames)
    }

    consuming func finish<Buffer: RangeReplaceableContainer<HTTP3RequestOutput> & ~Copyable>(
        buffer: inout Buffer,
        finalElement: consuming Void
    ) async throws(any Error) where Buffer.Element: ~Copyable {
        try await self.write(buffer: &buffer)
    }
}

// The reader is used by one task at a time; its decoders are owned by it.
@available(anyAppleOS 27.0, *)
extension HTTP3EventReader: @unchecked Sendable {}
