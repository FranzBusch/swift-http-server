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
import ContainersPreview
import HTTP2StateMachine
import HTTPAPIs
import HTTPTypes
import Logging
import PlatformExecutors
import Testing

@testable import PlatformHTTPServer

/// Runs requests against a `PlatformHTTPServer` over TCP, TLS and HTTP/2 on the loopback interface.
@Suite
struct PlatformHTTPServerEndToEndTests {
    @available(anyAppleOS 27.0, *)
    private struct Response {
        var status: String?
        var headers: HPACKHeaders
        var body: [UInt8]
        var trailers: HPACKHeaders?
    }

    /// Starts a server with `handler`, runs `client` against its port, and stops the server.
    @available(anyAppleOS 27.0, *)
    private static func withServer<Handler: HTTPServerRequestHandler, Result: Sendable>(
        handler: Handler,
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
                threadCount: 1
            ),
            logger: Logger(label: "end-to-end-test")
        )

        return try await withThrowingTaskGroup(of: Result?.self) { group in
            group.addTask {
                try await server.serve(handler: handler)
                return nil
            }
            var ports = server.listeningPorts.makeAsyncIterator()
            let port = try #require(try await ports.next())

            let result = try await PThreadTaskExecutor.withExecutor(name: "end-to-end-client", poolSize: 1) {
                executor in
                try await withTaskExecutorPreference(executor) {
                    try await client(port)
                }
            }
            group.cancelAll()
            _ = try? await group.next()
            return result
        }
    }

    /// Sends one request on a new connection and reads the response.
    @available(anyAppleOS 27.0, *)
    private static func request(
        port: Int,
        method: String = "GET",
        path: String = "/",
        body: [UInt8] = []
    ) async throws -> Response {
        let address = SocketAddress.v4(SocketAddress.V4(address: .loopback, port: UInt16(port)))
        let connection = try await TCPConnection.connect(to: address)
        let response: Response
        do {
            response = try await connection.withOwnedSplit { readHalf, writeHalf in
                try await TestTLSClient.connect(reader: readHalf, writer: writeHalf) { reader, writer, alpn in
                    #expect(alpn == "h2")
                    return try await Self.exchange(
                        reader: reader,
                        writer: writer,
                        method: method,
                        path: path,
                        body: body
                    )
                }
            }
        } catch {
            try? await connection.close()
            throw error
        }
        try await connection.close()
        return response
    }

    @available(anyAppleOS 27.0, *)
    private static func exchange<
        Reader: AsyncReader & Sendable & ~Copyable & ~Escapable,
        Writer: AsyncWriter & Sendable & ~Copyable & ~Escapable
    >(
        reader: consuming Reader,
        writer: consuming Writer,
        method: String,
        path: String,
        body: [UInt8]
    ) async throws -> Response
    where
        Reader.ReadElement == UInt8,
        Reader.FinalElement == Void,
        Writer.WriteElement == UInt8,
        Writer.FinalElement == Void
    {
        // The connection preface precedes the frames.
        var rawWriter = writer
        try await rawWriter.write { (buffer: inout Writer.Buffer) in
            buffer.append(copying: Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8).span)
        }
        var writer = SerializingAsyncWriter<Writer, HTTP2Frame>(downstream: rawWriter)
        var reader = ParsingAsyncReader<Reader, HTTP2Frame>(upstream: reader)

        var encoder = HPACKEncoder()
        var decoder = HPACKDecoder()
        let head = HPACKHeaders([
            (":method", method), (":scheme", "https"), (":authority", "localhost"), (":path", path),
        ])

        var frames = UniqueArray<HTTP2Frame>()
        frames.append(HTTP2Frame(streamID: .connectionStream, payload: .settings(.settings([]))))
        frames.append(
            HTTP2Frame(
                streamID: HTTP2StreamID(1),
                payload: .headers(.init(headerBlock: encoder.encode(head), endStream: body.isEmpty))
            )
        )
        if !body.isEmpty {
            frames.append(
                HTTP2Frame(streamID: HTTP2StreamID(1), payload: .data(.init(data: body, endStream: true)))
            )
        }
        try await writer.write(buffer: &frames)

        var response = Response(status: nil, headers: HPACKHeaders(), body: [], trailers: nil)
        var finished = false
        while !finished {
            try await reader.read { buffer, finalElement in
                for index in 0..<buffer.count {
                    let frame = buffer[index]
                    guard frame.streamID.value == 1 else { continue }
                    switch frame.payload {
                    case .headers(let payload):
                        let headers = try decoder.decode(payload.headerBlock)
                        if response.status == nil {
                            response.status = headers.first(name: ":status")
                            response.headers = headers
                        } else {
                            response.trailers = headers
                        }
                        finished = finished || payload.endStream
                    case .data(let payload):
                        response.body += payload.data
                        finished = finished || payload.endStream
                    case .rstStream(let code):
                        throw PlatformHTTPServerError.streamReset(code)
                    default:
                        break
                    }
                }
                if finalElement != nil {
                    finished = true
                }
            }
        }
        return response
    }

    @available(anyAppleOS 27.0, *)
    @Test("A request over TCP, TLS and HTTP/2 reaches the handler and the response comes back")
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

        let response = try await Self.withServer(handler: handler) { port in
            try await Self.request(port: port, path: "/world")
        }
        #expect(response.status == "200")
        #expect(response.headers.first(name: "content-type") == "text/plain")
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
        let response = try await Self.withServer(handler: handler) { port in
            try await Self.request(port: port, method: "POST", body: payload)
        }
        #expect(response.status == "200")
        #expect(response.body == payload)
        #expect(response.trailers?.first(name: "server-timing") == "done")
    }

    @available(anyAppleOS 27.0, *)
    @Test("A handler that throws resets only its stream")
    func throwingHandler() async throws {
        struct HandlerError: Error {}
        let handler = HTTPServerClosureRequestHandler<
            PlatformHTTPRequestContext, PlatformHTTPRequestBodyReader, PlatformHTTPResponseSender
        > { _, _, _, _ in
            throw HandlerError()
        }

        await #expect {
            _ = try await Self.withServer(handler: handler) { port in
                try await Self.request(port: port)
            }
        } throws: { error in
            // The client reads the reset as an error of the response reader, which wraps it.
            "\(error)".contains("streamReset(INTERNAL_ERROR)")
        }
    }
}
