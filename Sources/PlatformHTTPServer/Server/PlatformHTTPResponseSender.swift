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
public import BasicContainers
public import ContainersPreview
import HTTP2StateMachine
public import HTTPAPIs
public import HTTPTypes
import Synchronization

/// Sends the response to a request that the ``PlatformHTTPServer`` received.
@available(anyAppleOS 27.0, *)
public struct PlatformHTTPResponseSender: HTTPResponseSender, ~Copyable {
    /// The state that survives the consumption of the sender, so that the server can check after the handler
    /// returned whether the response was completed.
    final class State: Sendable {
        private let finished = Mutex(false)

        var finishedWriting: Bool {
            self.finished.withLock { $0 }
        }

        func markFinished() {
            self.finished.withLock { $0 = true }
        }
    }

    private var outbound: HTTP2StreamOutbound
    private let state: State

    init(outbound: consuming HTTP2StreamOutbound, state: State) {
        self.outbound = outbound
        self.state = state
    }

    public mutating func sendInformational(_ response: HTTPResponse) async throws {
        precondition(response.status.kind == .informational, "sendInformational requires a 1xx response")
        try await self.outbound.send(.headers(HPACKBridge.encodeResponseHead(response), endStream: false))
    }

    public consuming func send(_ response: HTTPResponse) async throws -> ResponseBodyWriter {
        precondition(response.status.kind != .informational, "send requires a non-1xx response")
        var outbound = self.outbound
        try await outbound.send(.headers(HPACKBridge.encodeResponseHead(response), endStream: false))
        return ResponseBodyWriter(outbound: outbound, state: self.state)
    }

    // This signature has to match the requirement label for label and type for type. A mismatch silently
    // reinstates the default implementation that sends the head and the body in separate steps.
    public consuming func sendAndFinish<Buffer: RangeReplaceableContainer<UInt8> & ~Copyable>(
        _ response: HTTPResponse,
        buffer: inout Buffer,
        trailer: HTTPFields? = nil
    ) async throws where Buffer.Element: ~Copyable {
        precondition(response.status.kind != .informational, "sendAndFinish requires a non-1xx response")
        var outbound = self.outbound
        let state = self.state

        let payload = Self.drain(&buffer)
        let hasBody = !payload.isEmpty
        let hasTrailers = trailer != nil

        // The head, the body and the trailers go to the connection in one batch. The last frame carries END_STREAM.
        var outputs = UniqueArray<HTTP2StreamOutput>(minimumCapacity: 3)
        outputs.append(
            .headers(HPACKBridge.encodeResponseHead(response), endStream: !hasBody && !hasTrailers)
        )
        if hasBody {
            outputs.append(.data(payload, endStream: !hasTrailers))
        }
        if let trailer {
            outputs.append(.headers(HPACKBridge.encodeTrailers(trailer), endStream: true))
        }
        try await outbound.send(outputs)
        state.markFinished()
    }

    /// Moves the bytes of the container into an array.
    fileprivate static func drain<Buffer: RangeReplaceableContainer<UInt8> & ~Copyable>(
        _ buffer: inout Buffer
    ) -> [UInt8] where Buffer.Element: ~Copyable {
        guard buffer.count > 0 else { return [] }
        var payload: [UInt8] = []
        payload.reserveCapacity(buffer.count)
        var consumer = buffer.consumeAll()
        while true {
            let span = consumer.drainNext()
            if span.isEmpty { break }
            let bytes = span.span
            for index in 0..<bytes.count {
                payload.append(bytes[index])
            }
        }
        return payload
    }

    /// Writes the body of a response.
    ///
    /// Every call to ``write(buffer:)`` becomes a DATA frame. ``finish(buffer:finalElement:)`` ends the stream with
    /// the last DATA frame, or with a HEADERS frame if there are trailers.
    public struct ResponseBodyWriter: CallerAsyncWriter, ~Copyable {
        public typealias WriteElement = UInt8
        public typealias WriteFailure = any Error
        public typealias FinalElement = HTTPFields?

        private var outbound: HTTP2StreamOutbound
        private let state: State

        fileprivate init(outbound: consuming HTTP2StreamOutbound, state: State) {
            self.outbound = outbound
            self.state = state
        }

        public mutating func write<Buffer: RangeReplaceableContainer<UInt8> & ~Copyable>(
            buffer: inout Buffer
        ) async throws(WriteFailure) where Buffer.Element: ~Copyable {
            guard buffer.count > 0 else { return }
            let payload = PlatformHTTPResponseSender.drain(&buffer)
            try await self.outbound.send(.data(payload, endStream: false))
        }

        public consuming func finish<Buffer: RangeReplaceableContainer<UInt8> & ~Copyable>(
            buffer: inout Buffer,
            finalElement: consuming HTTPFields?
        ) async throws(WriteFailure) where Buffer.Element: ~Copyable {
            let payload = PlatformHTTPResponseSender.drain(&buffer)
            let trailers = finalElement
            var outbound = self.outbound
            let state = self.state

            var outputs = UniqueArray<HTTP2StreamOutput>(minimumCapacity: 2)
            if !payload.isEmpty || trailers == nil {
                outputs.append(.data(payload, endStream: trailers == nil))
            }
            if let trailers {
                outputs.append(.headers(HPACKBridge.encodeTrailers(trailers), endStream: true))
            }
            try await outbound.send(outputs)
            state.markFinished()
        }
    }
}

@available(*, unavailable)
extension PlatformHTTPResponseSender: Sendable {}

@available(*, unavailable)
extension PlatformHTTPResponseSender.ResponseBodyWriter: Sendable {}
