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
import BinaryParsing
import ContainersPreview
@_spi(PackageInternal) import HTTP3StateMachine
import HTTPAPIs
import HTTPTypes
import Logging
import PlatformExecutors
@_spi(PackageInternal) import QPACKStateMachine
import SwiftTLSStateMachine
import Testing

@testable import PlatformHTTPServer

/// Runs requests against a `PlatformHTTPServer` over UDP, QUIC and HTTP/3 on the loopback interface.
@Suite
struct HTTP3EndToEndTests {
    @available(anyAppleOS 27.0, *)
    struct Response: Sendable {
        var status: String?
        var headers: [HTTPField] = []
        var body: [UInt8] = []
        var trailers: [HTTPField]? = nil
    }

    @available(anyAppleOS 27.0, *)
    private static func withServer<Handler: HTTPServerRequestHandler, Result: Sendable>(
        handler: Handler,
        http2: Bool = true,
        client: @escaping @Sendable (Int) async throws -> Result
    ) async throws -> Result
    where
        Handler.RequestContext == PlatformHTTPRequestContext,
        Handler.Reader == PlatformHTTPRequestBodyReader,
        Handler.ResponseSender == PlatformHTTPResponseSender
    {
        let tls = try makeServerTLSConfiguration()
        let server = PlatformHTTPServer(
            configuration: .init(
                host: "127.0.0.1",
                port: 0,
                certificateChain: tls.certificateChain,
                privateKey: tls.privateKey,
                threadCount: 1,
                http2: http2 ? .init() : nil,
                http3: .init()
            ),
            logger: Logger(label: "http3-end-to-end-test")
        )

        return try await withThrowingTaskGroup(of: Result?.self) { group in
            group.addTask {
                try await server.serve(handler: handler)
                return nil
            }
            var ports = server.listeningPorts.makeAsyncIterator()
            let port = try #require(try await ports.next())

            let result = try await PThreadTaskExecutor.withExecutor(name: "http3-client", poolSize: 1) { executor in
                try await withTaskExecutorPreference(executor) {
                    try await client(port)
                }
            }
            group.cancelAll()
            _ = try? await group.next()
            return result
        }
    }

    /// Sends requests on one connection, each on its own stream, and returns the responses in the same order.
    @available(anyAppleOS 27.0, *)
    private static func requests(
        port: Int,
        count: Int = 1,
        method: String = "GET",
        path: String = "/",
        body: [UInt8] = []
    ) async throws -> [Response] {
        let socket = try await UDPSocket.bind(to: .v4(.init(address: .loopback, port: 0)))
        let result: Swift.Result<[Response], any Error>
        do {
            result = .success(
                try await QUICClientEndpoint.withConnection(
                    to: .v4(.init(address: .loopback, port: UInt16(port))),
                    socket: socket,
                    tlsConfiguration: ClientHandshakeConfiguration(serverName: "localhost", alpnProtocols: ["h3"])
                ) { connection in
                    try await Self.exchange(connection, count: count, method: method, path: path, body: body)
                }
            )
        } catch {
            result = .failure(error)
        }
        try await socket.close()
        return try result.get()
    }

    @available(anyAppleOS 27.0, *)
    private static func exchange(
        _ connection: QUICConnection,
        count: Int,
        method: String,
        path: String,
        body: [UInt8]
    ) async throws -> [Response] {
        #expect(connection.negotiatedALPN == "h3")
        return try await connection.withSplit { reader, writer in
            var reader = reader
            var writer = writer
            var frames = UniqueArray<QUICFrame>()
            for index in 0..<count {
                var bytes: [UInt8] = []
                HTTP3Wire.appendHeaders(
                    [
                        HTTPField(name: HTTPField.Name(parsed: ":method")!, value: method),
                        HTTPField(name: HTTPField.Name(parsed: ":scheme")!, value: "https"),
                        HTTPField(name: HTTPField.Name(parsed: ":authority")!, value: "localhost"),
                        HTTPField(name: HTTPField.Name(parsed: ":path")!, value: path),
                    ],
                    to: &bytes
                )
                if !body.isEmpty {
                    HTTP3Wire.appendData(body, to: &bytes)
                }
                frames.append(.stream(QUICStreamFrame(streamID: UInt64(index) * 4, offset: 0, data: bytes, fin: true)))
            }
            try await writer.write(buffer: &frames)

            var streams: [UInt64: [UInt8]] = [:]
            var finished = Set<UInt64>()
            while finished.count < count {
                let ended = try await reader.read { frames, finalElement in
                    for index in frames.indices {
                        guard case .stream(let frame) = frames[index], frame.streamID & 0x03 == 0 else { continue }
                        streams[frame.streamID, default: []].append(contentsOf: frame.data)
                        if frame.fin {
                            finished.insert(frame.streamID)
                        }
                    }
                    return finalElement != nil
                }
                if ended { break }
            }
            return try (0..<count).map { try Self.parseResponse(streams[UInt64($0) * 4] ?? []) }
        }
    }

    @available(anyAppleOS 27.0, *)
    private static func parseResponse(_ bytes: [UInt8]) throws -> Response {
        var response = Response()
        var frameDecoder = HTTP3FrameDecoder()
        var qpack = QPACKDecoder(dynamicTableMaxCapacity: 0)
        var input = ParserSpan(bytes.span.bytes)
        while let frame = try frameDecoder.decodeLast(buffer: &input, seenEOF: true) {
            switch frame {
            case .known(.headers(let headers)):
                let prefix = try #require(qpack.decodeFieldSectionPrefix(headers.fieldSection.prefix))
                guard
                    case .success(let fields, _) = qpack.decodeFieldSection(
                        prefix: prefix,
                        lines: headers.fieldSection.lines,
                        streamID: QUICStreamID(rawValue: 0)
                    )
                else {
                    Issue.record("A field section did not decode")
                    return response
                }
                if response.status == nil {
                    response.status = fields.first { $0.name.rawName == ":status" }?.value
                    response.headers = fields.filter { !$0.name.rawName.hasPrefix(":") }
                } else {
                    response.trailers = fields
                }
            case .known(.data(let data)):
                response.body.append(contentsOf: data.payload)
            default:
                break
            }
        }
        return response
    }

    @available(anyAppleOS 27.0, *)
    @Test("A request over UDP, QUIC and HTTP/3 reaches the handler and the response comes back")
    func helloWorld() async throws {
        let handler = HTTPServerClosureRequestHandler<
            PlatformHTTPRequestContext, PlatformHTTPRequestBodyReader, PlatformHTTPResponseSender
        > { request, _, reader, responseSender in
            var reader = reader
            var finished = false
            while !finished {
                finished = try await reader.read { _, finalElement in finalElement != nil }
            }
            var body = UniqueArray<UInt8>(copying: Array("Hello, \(request.path ?? "")".utf8))
            try await responseSender.sendAndFinish(
                HTTPResponse(status: .ok, headerFields: [.contentType: "text/plain"]),
                buffer: &body,
                trailer: nil
            )
        }

        let responses = try await Self.withServer(handler: handler) { port in
            try await Self.requests(port: port, path: "/world")
        }
        let response = try #require(responses.first)
        #expect(response.status == "200")
        #expect(response.headers.first { $0.name == .contentType }?.value == "text/plain")
        #expect(String(decoding: response.body, as: UTF8.self) == "Hello, /world")
    }

    @available(anyAppleOS 27.0, *)
    @Test("The handler reads the request body and answers with trailers")
    func requestBodyAndTrailers() async throws {
        let handler = HTTPServerClosureRequestHandler<
            PlatformHTTPRequestContext, PlatformHTTPRequestBodyReader, PlatformHTTPResponseSender
        > { _, _, reader, responseSender in
            var reader = reader
            var received = UniqueArray<UInt8>()
            var finished = false
            while !finished {
                finished = try await reader.read { buffer, finalElement in
                    received.append(copying: buffer.span)
                    return finalElement != nil
                }
            }
            try await responseSender.sendAndFinish(
                HTTPResponse(status: .ok),
                buffer: &received,
                trailer: [HTTPField.Name("server-timing")!: "done"]
            )
        }

        let payload = (0..<50_000).map { UInt8(truncatingIfNeeded: $0 &* 13) }
        let responses = try await Self.withServer(handler: handler) { port in
            try await Self.requests(port: port, method: "POST", body: payload)
        }
        let response = try #require(responses.first)
        #expect(response.status == "200")
        #expect(response.body == payload)
        #expect(response.trailers?.first { $0.name.rawName == "server-timing" }?.value == "done")
    }

    @available(anyAppleOS 27.0, *)
    @Test("Many requests share one connection")
    func concurrentRequests() async throws {
        let handler = HTTPServerClosureRequestHandler<
            PlatformHTTPRequestContext, PlatformHTTPRequestBodyReader, PlatformHTTPResponseSender
        > { request, _, _, responseSender in
            var body = UniqueArray<UInt8>(copying: Array(repeating: UInt8(ascii: "x"), count: 2048))
            try await responseSender.sendAndFinish(HTTPResponse(status: .ok), buffer: &body, trailer: nil)
        }
        let responses = try await Self.withServer(handler: handler) { port in
            try await Self.requests(port: port, count: 50)
        }
        #expect(responses.count == 50)
        #expect(responses.allSatisfy { $0.status == "200" && $0.body.count == 2048 })
    }

    @available(anyAppleOS 27.0, *)
    @Test("A server with HTTP/3 only serves over QUIC and does not listen on TCP")
    func http3Only() async throws {
        let handler = HTTPServerClosureRequestHandler<
            PlatformHTTPRequestContext, PlatformHTTPRequestBodyReader, PlatformHTTPResponseSender
        > { _, _, _, responseSender in
            var body = UniqueArray<UInt8>(copying: Array("only h3".utf8))
            try await responseSender.sendAndFinish(HTTPResponse(status: .ok), buffer: &body, trailer: nil)
        }
        let (responses, tcpRefused) = try await Self.withServer(handler: handler, http2: false) { port in
            let responses = try await Self.requests(port: port)
            var tcpRefused = false
            do {
                let connection = try await TCPConnection.connect(to: .v4(.init(address: .loopback, port: UInt16(port))))
                try await connection.close()
            } catch {
                tcpRefused = true
            }
            return (responses, tcpRefused)
        }
        #expect(responses.first?.status == "200")
        #expect(responses.first.map { String(decoding: $0.body, as: UTF8.self) } == "only h3")
        #expect(tcpRefused)
    }

    @available(anyAppleOS 27.0, *)
    @Test("A server without any HTTP version fails to start")
    func noHTTPVersion() async throws {
        let tls = try makeServerTLSConfiguration()
        let server = PlatformHTTPServer(
            configuration: .init(
                host: "127.0.0.1",
                port: 0,
                certificateChain: tls.certificateChain,
                privateKey: tls.privateKey,
                threadCount: 1,
                http2: nil,
                http3: nil
            ),
            logger: Logger(label: "http3-end-to-end-test")
        )
        let handler = HTTPServerClosureRequestHandler<
            PlatformHTTPRequestContext, PlatformHTTPRequestBodyReader, PlatformHTTPResponseSender
        > { _, _, _, _ in }
        await #expect {
            try await server.serve(handler: handler)
        } throws: { error in
            if case .noHTTPVersion = error as? PlatformHTTPServerError { return true }
            return false
        }
    }
}
