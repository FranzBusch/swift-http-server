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
import HTTP2StateMachine
import SpanPreview

@testable import PlatformHTTPServer

/// A reader of frames that is fed by a test.
@available(anyAppleOS 27.0, *)
struct TestFrameReader: AsyncReader, ~Copyable, @unchecked Sendable {
    typealias ReadElement = HTTP2Frame
    typealias ReadFailure = any Error
    typealias Buffer = UniqueArray<HTTP2Frame>
    typealias FinalElement = Void

    var iterator: AsyncStream<HTTP2Frame>.Iterator

    mutating func read<Return: ~Copyable, Failure: Error>(
        body: (inout UniqueArray<HTTP2Frame>, consuming Void?) async throws(Failure) -> Return
    ) async throws(EitherError<any Error, Failure>) -> Return {
        var buffer = UniqueArray<HTTP2Frame>()
        let next = await self.iterator.next()
        do {
            if let next {
                buffer.append(next)
                return try await body(&buffer, nil)
            }
            return try await body(&buffer, ())
        } catch {
            throw .second(error)
        }
    }
}

/// A writer of frames that a test observes.
@available(anyAppleOS 27.0, *)
struct TestFrameWriter: CallerAsyncWriter, ~Copyable, @unchecked Sendable {
    typealias WriteElement = HTTP2Frame
    typealias WriteFailure = any Error
    typealias FinalElement = Void

    let continuation: AsyncStream<HTTP2Frame>.Continuation

    mutating func write<Buffer: RangeReplaceableContainer<HTTP2Frame> & ~Copyable>(
        buffer: inout Buffer
    ) async throws(any Error) where Buffer.Element: ~Copyable {
        var consumer = buffer.consumeAll()
        while true {
            let span = consumer.drainNext()
            if span.isEmpty { break }
            let frames = span.span
            for index in 0..<frames.count {
                self.continuation.yield(frames[index] as! HTTP2Frame)
            }
        }
    }

    consuming func finish<Buffer: RangeReplaceableContainer<HTTP2Frame> & ~Copyable>(
        buffer: inout Buffer,
        finalElement: consuming Void
    ) async throws(any Error) where Buffer.Element: ~Copyable {
        self.continuation.finish()
    }
}

/// The client side of an in-memory HTTP/2 connection.
@available(anyAppleOS 27.0, *)
final class TestFrameClient: @unchecked Sendable {
    private let toServer: AsyncStream<HTTP2Frame>.Continuation
    private var fromServer: AsyncStream<HTTP2Frame>.Iterator
    private var encoder = HPACKEncoder()
    private var decoder = HPACKDecoder()

    let serverReader: AsyncStream<HTTP2Frame>
    let serverWriter: AsyncStream<HTTP2Frame>.Continuation

    init() {
        let (toServerStream, toServer) = AsyncStream<HTTP2Frame>.makeStream()
        let (fromServerStream, fromServer) = AsyncStream<HTTP2Frame>.makeStream()
        self.toServer = toServer
        self.fromServer = fromServerStream.makeAsyncIterator()
        self.serverReader = toServerStream
        self.serverWriter = fromServer
    }

    func makeServerReader() -> TestFrameReader {
        TestFrameReader(iterator: self.serverReader.makeAsyncIterator())
    }

    func makeServerWriter() -> TestFrameWriter {
        TestFrameWriter(continuation: self.serverWriter)
    }

    func send(_ frame: HTTP2Frame) {
        self.toServer.yield(frame)
    }

    func sendSettings(_ settings: [HTTP2Setting] = []) {
        self.send(HTTP2Frame(streamID: .connectionStream, payload: .settings(.settings(settings))))
    }

    func sendRequest(id: UInt32, path: String = "/", endStream: Bool = true) {
        let headers = HPACKHeaders([
            (":method", "GET"), (":scheme", "https"), (":authority", "localhost"), (":path", path),
        ])
        let block = self.encoder.encode(headers)
        self.send(
            HTTP2Frame(
                streamID: HTTP2StreamID(id),
                payload: .headers(.init(headerBlock: block, endStream: endStream))
            )
        )
    }

    func close() {
        self.toServer.finish()
    }

    /// The next frame of the server, or `nil` once the server wrote its last frame.
    func nextFrame() async -> HTTP2Frame? {
        await self.fromServer.next()
    }

    func decode(_ block: [UInt8]) throws -> HPACKHeaders {
        try self.decoder.decode(block)
    }
}
