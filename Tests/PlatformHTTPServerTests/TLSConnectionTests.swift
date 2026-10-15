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
import Testing

@testable import PlatformHTTPServer

@Suite
struct TLSConnectionTests {
    /// Reads everything until the end of the stream.
    @available(anyAppleOS 27.0, *)
    private static func readAll<Reader: AsyncReader & ~Copyable & ~Escapable>(
        _ reader: inout Reader
    ) async throws -> [UInt8] where Reader.ReadElement == UInt8, Reader.FinalElement == Void {
        var bytes: [UInt8] = []
        var finished = false
        while !finished {
            try await reader.read { buffer, finalElement in
                var index = buffer.startIndex
                while index != buffer.endIndex {
                    let span = buffer.nextSpan(after: &index)
                    for offset in 0..<span.count {
                        bytes.append(span[offset])
                    }
                }
                finished = finalElement != nil
            }
        }
        return bytes
    }

    @available(anyAppleOS 27.0, *)
    private static func write<Writer: AsyncWriter & ~Copyable & ~Escapable>(
        _ bytes: [UInt8],
        to writer: inout Writer
    ) async throws where Writer.WriteElement == UInt8, Writer.Buffer == UniqueArray<UInt8> {
        try await writer.write { buffer in
            buffer.append(copying: bytes.span)
        }
    }

    /// Runs a server and a client against each other and returns what each side received.
    ///
    /// The server reads the request until the client finishes, answers with `response` and finishes. The client
    /// writes `request`, finishes, and reads the response.
    @available(anyAppleOS 27.0, *)
    private static func exchange(
        request: [UInt8],
        response: [UInt8],
        chunkSize: Int = .max,
        clientALPN: [String] = ["h2"]
    ) async throws -> (received: [UInt8], answered: [UInt8], alpn: String?) {
        let configuration = try makeServerTLSConfiguration()
        let clientToServer = TestPipe.make(chunkSize: chunkSize)
        let serverToClient = TestPipe.make(chunkSize: chunkSize)

        return try await withThrowingTaskGroup(of: [UInt8]?.self) { group in
            group.addTask {
                let connection = try await TLSConnection.accept(
                    reader: clientToServer.reader,
                    writer: serverToClient.writer,
                    configuration: configuration
                )
                return try await connection.withSplit { reader, writer in
                    var reader = reader
                    var writer = writer
                    let received = try await Self.readAll(&reader)
                    try await Self.write(response, to: &writer)
                    try await writer.finish()
                    return received
                }
            }

            let (answered, alpn) = try await TestTLSClient.connect(
                reader: serverToClient.reader,
                writer: clientToServer.writer,
                alpnProtocols: clientALPN
            ) { reader, writer, alpn in
                var reader = reader
                var writer = writer
                try await Self.write(request, to: &writer)
                try await writer.finish()
                return (try await Self.readAll(&reader), alpn)
            }

            let received = try await group.next()!!
            return (received, answered, alpn)
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test("Application data flows in both directions after the handshake")
    func echo() async throws {
        let result = try await Self.exchange(request: Array("ping".utf8), response: Array("pong".utf8))
        #expect(result.received == Array("ping".utf8))
        #expect(result.answered == Array("pong".utf8))
        #expect(result.alpn == "h2")
    }

    @available(anyAppleOS 27.0, *)
    @Test("Data larger than a record is split into several records")
    func largeData() async throws {
        let request = (0..<100_000).map { UInt8(truncatingIfNeeded: $0) }
        let response = (0..<300_000).map { UInt8(truncatingIfNeeded: $0 &* 7) }
        let result = try await Self.exchange(request: request, response: response)
        #expect(result.received == request)
        #expect(result.answered == response)
    }

    @available(anyAppleOS 27.0, *)
    @Test("The handshake and the data survive a transport that delivers a few bytes at a time")
    func smallChunks() async throws {
        let request = (0..<5_000).map { UInt8(truncatingIfNeeded: $0) }
        let response = (0..<5_000).map { UInt8(truncatingIfNeeded: $0 &+ 1) }
        for chunkSize in [1, 7, 100] {
            let result = try await Self.exchange(request: request, response: response, chunkSize: chunkSize)
            #expect(result.received == request, "Chunk size \(chunkSize)")
            #expect(result.answered == response, "Chunk size \(chunkSize)")
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test("A client that offers other protocols gets no ALPN protocol")
    func alpnMismatch() async throws {
        let result = try await Self.exchange(request: [1], response: [2], clientALPN: ["http/1.1"])
        #expect(result.alpn == nil)
    }

    @available(anyAppleOS 27.0, *)
    @Test("A transport that ends during the handshake fails the handshake")
    func transportEndsDuringHandshake() async throws {
        let configuration = try makeServerTLSConfiguration()
        let (stream, continuation) = AsyncStream<[UInt8]>.makeStream()
        continuation.yield([0x16, 0x03, 0x01])
        continuation.finish()

        await #expect(throws: TLSError.self) {
            _ = try await TLSConnection.accept(
                reader: TestByteReader(iterator: stream.makeAsyncIterator()),
                writer: TestPipe.make().writer,
                configuration: configuration
            )
        }
    }
}
