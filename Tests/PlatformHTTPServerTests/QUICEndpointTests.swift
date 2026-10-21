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
import Logging
import PlatformExecutors
import SwiftTLSStateMachine
import Testing

@testable import PlatformHTTPServer

/// Runs QUIC connections between a ``QUICServerEndpoint`` and a ``QUICClientEndpoint`` over UDP on the loopback
/// interface.
@Suite
struct QUICEndpointTests {
    /// Echoes every client-initiated bidirectional stream: the bytes come back once the stream finished.
    @available(anyAppleOS 27.0, *)
    private static func echo(_ connection: QUICConnection) async {
        try? await connection.withSplit { reader, writer in
            var reader = reader
            var writer = writer
            var received: [UInt64: [UInt8]] = [:]
            var ended = false
            while !ended {
                var responses = UniqueArray<QUICFrame>()
                ended = try await reader.read { frames, finalElement in
                    for index in frames.indices {
                        guard case .stream(let frame) = frames[index] else { continue }
                        received[frame.streamID, default: []].append(contentsOf: frame.data)
                        if frame.fin {
                            responses.append(
                                .stream(
                                    QUICStreamFrame(
                                        streamID: frame.streamID,
                                        offset: 0,
                                        data: received.removeValue(forKey: frame.streamID) ?? [],
                                        fin: true
                                    )
                                )
                            )
                        }
                    }
                    return finalElement != nil
                }
                if !responses.isEmpty {
                    try await writer.write(buffer: &responses)
                }
            }
        }
    }

    /// Sends requests on the given streams and collects the responses.
    @available(anyAppleOS 27.0, *)
    private static func exchange(
        _ connection: QUICConnection,
        requests: [UInt64: [UInt8]]
    ) async throws -> [UInt64: [UInt8]] {
        try await connection.withSplit { reader, writer in
            var reader = reader
            var writer = writer
            var frames = UniqueArray<QUICFrame>()
            for (streamID, body) in requests {
                frames.append(.stream(QUICStreamFrame(streamID: streamID, offset: 0, data: body, fin: true)))
            }
            try await writer.write(buffer: &frames)

            var responses: [UInt64: [UInt8]] = [:]
            var finished = Set<UInt64>()
            while finished.count < requests.count {
                let ended = try await reader.read { frames, finalElement in
                    for index in frames.indices {
                        guard case .stream(let frame) = frames[index] else { continue }
                        responses[frame.streamID, default: []].append(contentsOf: frame.data)
                        if frame.fin {
                            finished.insert(frame.streamID)
                        }
                    }
                    return finalElement != nil
                }
                if ended { break }
            }
            return responses
        }
    }

    @available(anyAppleOS 27.0, *)
    private static func withServer<Result: Sendable>(
        handler: @escaping @Sendable (QUICConnection) async -> Void,
        client: @escaping @Sendable (SocketAddress) async throws -> Result
    ) async throws -> Result {
        let tls = try makeServerTLSConfiguration(alpnProtocols: ["h3"]).makeHandshakeConfiguration()
        return try await PThreadTaskExecutor.withExecutor(name: "quic-test", poolSize: 1) { executor in
            try await withTaskExecutorPreference(executor) {
                try await withThrowingTaskGroup(of: Result?.self) { group in
                    let socket = try await UDPSocket.bind(to: .v4(.init(address: .loopback, port: 0)))
                    let address = try socket.localAddress
                    var box: UDPSocket? = consume socket
                    group.addTask {
                        let socket = box.take()!
                        do {
                            try await QUICServerEndpoint.run(
                                socket: socket,
                                configuration: .init(),
                                tlsConfiguration: tls,
                                logger: Logger(label: "quic-test"),
                                handler: handler
                            )
                        } catch {}
                        try? await socket.close()
                        return nil
                    }
                    let result = try await client(address)
                    group.cancelAll()
                    while try await group.next() != nil {}
                    return result
                }
            }
        }
    }

    @available(anyAppleOS 27.0, *)
    private static func connect<Result: Sendable>(
        to server: SocketAddress,
        body: @escaping @Sendable (QUICConnection) async throws -> Result
    ) async throws -> Result {
        let socket = try await UDPSocket.bind(to: .v4(.init(address: .loopback, port: 0)))
        let result: Swift.Result<Result, any Error>
        do {
            result = .success(
                try await QUICClientEndpoint.withConnection(
                    to: server,
                    socket: socket,
                    tlsConfiguration: ClientHandshakeConfiguration(serverName: "localhost", alpnProtocols: ["h3"]),
                    body: body
                )
            )
        } catch {
            result = .failure(error)
        }
        try await socket.close()
        return try result.get()
    }

    @available(anyAppleOS 27.0, *)
    @Test func streamsAreEchoedOverUDP() async throws {
        let requests: [UInt64: [UInt8]] = [
            0: Array("first".utf8),
            4: (0..<200_000).map { UInt8(truncatingIfNeeded: $0) },
            8: [],
        ]
        let responses = try await Self.withServer(handler: Self.echo) { address in
            try await Self.connect(to: address) { connection in
                #expect(connection.negotiatedALPN == "h3")
                return try await Self.exchange(connection, requests: requests)
            }
        }
        #expect(responses[0] == requests[0])
        #expect(responses[4] == requests[4])
        #expect(responses[8] ?? [] == [])
    }

    @available(anyAppleOS 27.0, *)
    @Test func severalConnectionsShareTheServerSocket() async throws {
        let counts = try await Self.withServer(handler: Self.echo) { address in
            try await withThrowingTaskGroup(of: Int.self) { group in
                for index in 0..<8 {
                    group.addTask {
                        try await Self.connect(to: address) { connection in
                            let body = Array(repeating: UInt8(index), count: 10_000 * (index + 1))
                            let responses = try await Self.exchange(connection, requests: [0: body])
                            #expect(responses[0] == body)
                            return responses[0]?.count ?? 0
                        }
                    }
                }
                var total = 0
                for try await count in group {
                    total += count
                }
                return total
            }
        }
        #expect(counts == (1...8).reduce(0) { $0 + 10_000 * $1 })
    }
}
