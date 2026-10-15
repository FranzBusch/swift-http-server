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
import BinaryParsingAsync
import BinarySerialization
import HTTP2StateMachine
import Testing

@testable import PlatformHTTPServer

@Suite
struct HTTPConnectionTests {
    @available(anyAppleOS 27.0, *)
    private static var frames: [HTTP2Frame] {
        [
            HTTP2Frame(
                streamID: .connectionStream,
                payload: .settings(.settings([HTTP2Setting(parameter: .maxConcurrentStreams, value: 50)]))
            ),
            HTTP2Frame(streamID: .connectionStream, payload: .settings(.ack)),
            HTTP2Frame(
                streamID: HTTP2StreamID(1),
                payload: .headers(.init(headerBlock: [0x82, 0x84, 0x87], endStream: false))
            ),
            HTTP2Frame(
                streamID: HTTP2StreamID(1),
                payload: .data(.init(data: Array(repeating: 9, count: 300), endStream: true))
            ),
        ]
    }

    /// The bytes of the connection preface followed by the frames.
    @available(anyAppleOS 27.0, *)
    private static func serializedClientStream() async throws -> [UInt8] {
        let pipe = TestPipe.make()
        let connection = HTTPConnection(reader: TestPipe.make().reader, writer: pipe.writer)
        try await connection.withHTTP2Frames { _, writer in
            var batch = UniqueArray<HTTP2Frame>()
            for frame in Self.frames {
                batch.append(frame)
            }
            try await writer.finish(buffer: &batch, finalElement: ())
        }

        var reader = pipe.reader
        var bytes = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
        var finished = false
        while !finished {
            try await reader.read { buffer, finalElement in
                for index in 0..<buffer.count {
                    bytes.append(buffer[index])
                }
                finished = finalElement != nil
            }
        }
        return bytes
    }

    @available(anyAppleOS 27.0, *)
    private static func readFrames(from chunks: [[UInt8]]) async throws -> [HTTP2Frame] {
        let (stream, continuation) = AsyncStream<[UInt8]>.makeStream()
        for chunk in chunks {
            continuation.yield(chunk)
        }
        continuation.finish()

        let connection = HTTPConnection(
            reader: TestByteReader(iterator: stream.makeAsyncIterator()),
            writer: TestPipe.make().writer
        )
        return try await connection.withHTTP2Frames { reader, _ in
            var reader = reader
            var frames: [HTTP2Frame] = []
            var finished = false
            while !finished {
                try await reader.read { buffer, finalElement in
                    for index in 0..<buffer.count {
                        frames.append(buffer[index])
                    }
                    finished = finalElement != nil
                }
            }
            return frames
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test("The frames that the writer serializes are the frames that the reader parses")
    func roundTrip() async throws {
        let bytes = try await Self.serializedClientStream()
        let parsed = try await Self.readFrames(from: [bytes])
        #expect(parsed == Self.frames)
    }

    @available(anyAppleOS 27.0, *)
    @Test("The reader parses the stream when it is split at every offset")
    func splitAtEveryOffset() async throws {
        let bytes = try await Self.serializedClientStream()
        for split in 1..<bytes.count {
            let parsed = try await Self.readFrames(from: [Array(bytes[..<split]), Array(bytes[split...])])
            #expect(parsed == Self.frames, "The split at \(split) changed the frames")
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test("The reader parses the stream when it arrives byte by byte")
    func byteByByte() async throws {
        let bytes = try await Self.serializedClientStream()
        let parsed = try await Self.readFrames(from: bytes.map { [$0] })
        #expect(parsed == Self.frames)
    }

    @available(anyAppleOS 27.0, *)
    @Test("A stream without the connection preface is rejected")
    func missingPreface() async throws {
        var bytes = try await Self.serializedClientStream()
        bytes[0] = UInt8(ascii: "G")
        await #expect(throws: (any Error).self) {
            _ = try await Self.readFrames(from: [bytes])
        }
    }
}
