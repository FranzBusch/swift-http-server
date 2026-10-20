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
    ///
    /// It owns the outbound side of the stream, which the sender and its body writer borrow for every send. After the
    /// handler returned, the server resets the stream through it if needed. A second outbound side for that would
    /// cost a producer of the outbound channel per stream.
    final class State: Sendable {
        private struct Storage: ~Copyable {
            var outbound: HTTP2StreamOutbound?
            var finished = false
        }

        private let storage: Mutex<Storage>

        init(outbound: consuming HTTP2StreamOutbound) {
            self.storage = Mutex(Storage(outbound: outbound))
        }

        var finishedWriting: Bool {
            self.storage.withLock { $0.finished }
        }

        func markFinished() {
            self.storage.withLock { $0.finished = true }
        }

        /// Sends all outputs in order on the stream.
        ///
        /// The sender and its body writer are not `Sendable` and the server only sends after the handler returned,
        /// so no two sends overlap.
        func send(_ outputs: consuming UniqueArray<HTTP2StreamOutput>) async throws {
            var outbound = self.takeOutbound()!
            do {
                try await outbound.send(outputs)
            } catch {
                self.putBack(outbound)
                throw error
            }
            self.putBack(outbound)
        }

        /// Sends a single output on the stream.
        func send(_ output: HTTP2StreamOutput) async throws {
            var outputs = UniqueArray<HTTP2StreamOutput>(minimumCapacity: 1)
            outputs.append(output)
            try await self.send(outputs)
        }

        private func takeOutbound() -> HTTP2StreamOutbound? {
            self.storage.withLock { $0.outbound.take() }
        }

        private func putBack(_ outbound: consuming HTTP2StreamOutbound) {
            var outbound = Optional(outbound)
            self.storage.withLock { swap(&$0.outbound, &outbound) }
        }
    }

    private let state: State

    init(state: State) {
        self.state = state
    }

    public mutating func sendInformational(_ response: HTTPResponse) async throws {
        precondition(response.status.kind == .informational, "sendInformational requires a 1xx response")
        try await self.state.send(.headers(HPACKBridge.encodeResponseHead(response), endStream: false))
    }

    public consuming func send(_ response: HTTPResponse) async throws -> ResponseBodyWriter {
        precondition(response.status.kind != .informational, "send requires a non-1xx response")
        try await self.state.send(.headers(HPACKBridge.encodeResponseHead(response), endStream: false))
        return ResponseBodyWriter(state: self.state)
    }

    // This signature has to match the requirement label for label and type for type. A mismatch silently
    // reinstates the default implementation that sends the head and the body in separate steps.
    //
    // The generic methods are inlinable and only drain the buffer, so that the caller specializes that part for its
    // container. The rest does not depend on the container.
    @inlinable
    public consuming func sendAndFinish<Buffer: RangeReplaceableContainer<UInt8> & ~Copyable>(
        _ response: HTTPResponse,
        buffer: inout Buffer,
        trailer: HTTPFields? = nil
    ) async throws where Buffer.Element: ~Copyable {
        let payload = Self.drain(&buffer)
        try await self.sendAndFinish(response, payload: payload, trailer: trailer)
    }

    @usableFromInline
    consuming func sendAndFinish(_ response: HTTPResponse, payload: [UInt8], trailer: HTTPFields?) async throws {
        precondition(response.status.kind != .informational, "sendAndFinish requires a non-1xx response")
        let state = self.state

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
        try await state.send(outputs)
        state.markFinished()
    }

    /// Moves the bytes of the container into an array.
    @inlinable
    static func drain<Buffer: RangeReplaceableContainer<UInt8> & ~Copyable>(
        _ buffer: inout Buffer
    ) -> [UInt8] where Buffer.Element: ~Copyable {
        guard buffer.count > 0 else { return [] }
        var payload: [UInt8] = []
        payload.reserveCapacity(buffer.count)
        var consumer = buffer.consumeAll()
        while true {
            let chunk = consumer.drainNext()
            if chunk.isEmpty { break }
            chunk.span.withUnsafeBufferPointer { bytes in
                unsafe payload.append(contentsOf: bytes)
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

        private let state: State

        fileprivate init(state: State) {
            self.state = state
        }

        @inlinable
        public mutating func write<Buffer: RangeReplaceableContainer<UInt8> & ~Copyable>(
            buffer: inout Buffer
        ) async throws(WriteFailure) where Buffer.Element: ~Copyable {
            guard buffer.count > 0 else { return }
            let payload = PlatformHTTPResponseSender.drain(&buffer)
            try await self.write(payload: payload)
        }

        @usableFromInline
        mutating func write(payload: [UInt8]) async throws(WriteFailure) {
            try await self.state.send(.data(payload, endStream: false))
        }

        @inlinable
        public consuming func finish<Buffer: RangeReplaceableContainer<UInt8> & ~Copyable>(
            buffer: inout Buffer,
            finalElement: consuming HTTPFields?
        ) async throws(WriteFailure) where Buffer.Element: ~Copyable {
            let payload = PlatformHTTPResponseSender.drain(&buffer)
            try await self.finish(payload: payload, trailers: finalElement)
        }

        @usableFromInline
        consuming func finish(payload: [UInt8], trailers: HTTPFields?) async throws(WriteFailure) {
            let state = self.state

            var outputs = UniqueArray<HTTP2StreamOutput>(minimumCapacity: 2)
            if !payload.isEmpty || trailers == nil {
                outputs.append(.data(payload, endStream: trailers == nil))
            }
            if let trailers {
                outputs.append(.headers(HPACKBridge.encodeTrailers(trailers), endStream: true))
            }
            try await state.send(outputs)
            state.markFinished()
        }
    }
}

@available(*, unavailable)
extension PlatformHTTPResponseSender: Sendable {}

@available(*, unavailable)
extension PlatformHTTPResponseSender.ResponseBodyWriter: Sendable {}
