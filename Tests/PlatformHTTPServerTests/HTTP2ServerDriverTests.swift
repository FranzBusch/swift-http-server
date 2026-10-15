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

import HTTP2StateMachine
import Synchronization
import Testing

@testable import PlatformHTTPServer

@Suite
struct HTTP2ServerDriverTests {
    /// Runs the driver on an in-memory connection and the test body as the client.
    @available(anyAppleOS 27.0, *)
    private func withDriver(
        configuration: HTTP2ServerConfiguration = .init(),
        handler: @escaping @Sendable (consuming HTTP2Stream) async -> Void,
        client body: @escaping @Sendable (TestFrameClient) async throws -> Void
    ) async throws {
        let client = TestFrameClient()
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await HTTP2ServerDriver(configuration: configuration).run(
                    reader: client.makeServerReader(),
                    writer: client.makeServerWriter(),
                    onStream: handler
                )
            }
            try await body(client)
            client.close()
            try await group.waitForAll()
        }
    }

    @available(anyAppleOS 27.0, *)
    private static func respond(with body: [UInt8]) -> @Sendable (consuming HTTP2Stream) async -> Void {
        { stream in
            var outbound = stream.outbound
            try? await outbound.send(
                .headers(HPACKHeaders([(":status", "200")]), endStream: false)
            )
            try? await outbound.send(.data(body, endStream: true))
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test("The server starts the connection with its SETTINGS and acknowledges the ones of the client")
    func settingsExchange() async throws {
        try await self.withDriver(handler: { _ in }) { client in
            let first = try #require(await client.nextFrame())
            guard case .settings(.settings(let settings)) = first.payload else {
                Issue.record("Expected SETTINGS, got \(first)")
                return
            }
            #expect(settings.contains { $0.parameter == .maxConcurrentStreams })

            client.sendSettings()
            let second = try #require(await client.nextFrame())
            #expect(second.payload == .settings(.ack))
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test("A request is answered with HEADERS and DATA on the same stream")
    func requestResponse() async throws {
        try await self.withDriver(handler: Self.respond(with: Array("hello".utf8))) { client in
            client.sendSettings()
            client.sendRequest(id: 1)

            var response: [HTTP2Frame] = []
            while response.count < 2, let frame = await client.nextFrame() {
                if frame.streamID.value == 1 { response.append(frame) }
            }
            try #require(response.count == 2)
            guard case .headers(let head) = response[0].payload else {
                Issue.record("Expected HEADERS, got \(response[0])")
                return
            }
            #expect(head.endStream == false)
            #expect(try client.decode(head.headerBlock).first(name: ":status") == "200")
            guard case .data(let data) = response[1].payload else {
                Issue.record("Expected DATA, got \(response[1])")
                return
            }
            #expect(data.data == Array("hello".utf8))
            #expect(data.endStream)
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test("A PING is answered with an acknowledgement carrying the same data")
    func ping() async throws {
        try await self.withDriver(handler: { _ in }) { client in
            client.sendSettings()
            let data = HTTP2PingData([1, 2, 3, 4, 5, 6, 7, 8])
            client.send(HTTP2Frame(streamID: .connectionStream, payload: .ping(data, ack: false)))

            while let frame = await client.nextFrame() {
                if case .ping(let echoed, let ack) = frame.payload {
                    #expect(ack)
                    #expect(echoed == data)
                    return
                }
            }
            Issue.record("The server did not acknowledge the PING")
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test("Many concurrent streams are all answered")
    func manyStreams() async throws {
        let streamCount = 50
        try await self.withDriver(
            configuration: .init(maxConcurrentStreams: 100),
            handler: Self.respond(with: Array("x".utf8))
        ) { client in
            client.sendSettings()
            for index in 0..<streamCount {
                client.sendRequest(id: UInt32(index * 2 + 1))
            }

            var finished = Set<UInt32>()
            while finished.count < streamCount, let frame = await client.nextFrame() {
                if case .data(let data) = frame.payload, data.endStream {
                    finished.insert(frame.streamID.value)
                }
            }
            #expect(finished.count == streamCount)
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test("A response larger than the flow control window waits for window updates")
    func flowControl() async throws {
        let size = 200_000
        try await self.withDriver(handler: Self.respond(with: [UInt8](repeating: 7, count: size))) { client in
            client.sendSettings()
            client.sendRequest(id: 1)

            var received = 0
            var sawEnd = false
            var largestFrame = 0
            var unacknowledged = 0
            while !sawEnd, let frame = await client.nextFrame() {
                guard case .data(let data) = frame.payload, frame.streamID.value == 1 else { continue }
                received += data.data.count
                largestFrame = max(largestFrame, data.data.count)
                unacknowledged += data.data.count
                sawEnd = data.endStream
                if unacknowledged >= 32768 {
                    let increment = UInt32(unacknowledged)
                    client.send(
                        HTTP2Frame(streamID: .connectionStream, payload: .windowUpdate(windowSizeIncrement: increment))
                    )
                    client.send(
                        HTTP2Frame(streamID: HTTP2StreamID(1), payload: .windowUpdate(windowSizeIncrement: increment))
                    )
                    unacknowledged = 0
                }
            }
            #expect(received == size)
            #expect(largestFrame <= 16384)
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test("The handler reads the request body")
    func requestBody() async throws {
        let echoed = Mutex<[UInt8]>([])
        try await self.withDriver(
            handler: { stream in
                var inbound = stream.inbound
                var outbound = stream.outbound
                var body: [UInt8] = []
                while let event = await inbound.next() {
                    if case .data(let bytes, _) = event { body += bytes }
                }
                echoed.withLock { $0 = body }
                try? await outbound.send(.headers(HPACKHeaders([(":status", "204")]), endStream: true))
            }
        ) { client in
            client.sendSettings()
            client.sendRequest(id: 1, endStream: false)
            client.send(
                HTTP2Frame(streamID: HTTP2StreamID(1), payload: .data(.init(data: [1, 2, 3], endStream: false)))
            )
            client.send(
                HTTP2Frame(streamID: HTTP2StreamID(1), payload: .data(.init(data: [4, 5], endStream: true)))
            )
            while let frame = await client.nextFrame() {
                if case .headers(let head) = frame.payload, head.endStream { break }
            }
        }
        #expect(echoed.withLock { $0 } == [1, 2, 3, 4, 5])
    }

    @available(anyAppleOS 27.0, *)
    @Test("The driver returns once the client closed the connection and the handlers returned")
    func clientCloses() async throws {
        try await self.withDriver(handler: { _ in }) { client in
            client.sendSettings()
        }
    }
}
