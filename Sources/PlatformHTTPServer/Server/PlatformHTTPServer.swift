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
import HTTP2StateMachine
public import HTTPAPIs
import HTTPTypes
public import Logging
import PlatformExecutors
import SwiftTLSStateMachine

/// An HTTP server that serves HTTP/2 over TLS 1.3 without SwiftNIO.
///
/// The server accepts TCP connections with the executors of `swift-platform-executors`, performs the TLS handshake
/// with `swift-tls`, and runs HTTP/2 with the state machines of `swift-nio-http2`. Every layer is a reader and a
/// writer on top of the layer below: ``TLSConnection`` decrypts and encrypts the bytes of the TCP connection,
/// ``HTTPConnection`` parses them into frames and the ``HTTP2ServerDriver`` runs the streams, each in its own child
/// task.
///
/// ```swift
/// let server = PlatformHTTPServer(
///     configuration: .init(
///         host: "127.0.0.1",
///         port: 8443,
///         certificateChain: [certificate],
///         privateKey: privateKey
///     ),
///     logger: Logger(label: "server")
/// )
///
/// try await server.serve { request, context, reader, responseSender in
///     var body = UniqueArray<UInt8>(copying: "Hello".utf8)
///     try await responseSender.sendAndFinish(HTTPResponse(status: .ok), buffer: &body)
/// }
/// ```
@available(anyAppleOS 27.0, *)
public struct PlatformHTTPServer: HTTPServer {
    public typealias RequestContext = PlatformHTTPRequestContext
    public typealias Reader = PlatformHTTPRequestBodyReader
    public typealias ResponseSender = PlatformHTTPResponseSender

    private let configuration: PlatformHTTPServerConfiguration
    private let logger: Logger

    // One element, then the stream finishes. `AsyncThrowingStream` buffers that element, so a caller that arrives
    // after the bind still reads the port, and `finish(throwing:)` hands it the error that stopped the bind.
    private let listeningPortStream: AsyncThrowingStream<Int, any Error>
    private let listeningPortContinuation: AsyncThrowingStream<Int, any Error>.Continuation

    /// Creates a server.
    public init(configuration: PlatformHTTPServerConfiguration, logger: Logger) {
        self.configuration = configuration
        self.logger = logger
        (self.listeningPortStream, self.listeningPortContinuation) = AsyncThrowingStream.makeStream()
    }

    /// The port that the server listens on, as a sequence with one element.
    ///
    /// The element arrives when ``serve(handler:)`` is bound, and the sequence then finishes. A sequence that
    /// finishes without an element means that the server stopped before it was bound. Iterate it once.
    public var listeningPorts: AsyncThrowingStream<Int, any Error> {
        self.listeningPortStream
    }

    public func serve<Handler: HTTPServerRequestHandler>(handler: Handler) async throws
    where
        Handler.RequestContext == PlatformHTTPRequestContext,
        Handler.Reader == PlatformHTTPRequestBodyReader,
        Handler.ResponseSender == PlatformHTTPResponseSender
    {
        let configuration = self.configuration
        let logger = self.logger
        let portContinuation = self.listeningPortContinuation
        let tlsConfiguration = ServerTLSConfiguration(
            certificateChain: configuration.certificateChain,
            privateKey: configuration.privateKey,
            alpnProtocols: ["h2"]
        )
        // The connections only see this closure, not the handler type. The code of a connection then depends only
        // on concrete types, so the compiler specializes it instead of instantiating every layer at runtime.
        let onStream: @Sendable (consuming HTTP2Stream) async -> Void = { stream in
            await Self.handleStream(stream, handler: handler, logger: logger)
        }

        do {
            let address = try Self.socketAddress(host: configuration.host, port: configuration.port)
            try await PThreadTaskExecutor.withExecutor(
                name: "PlatformHTTPServer",
                poolSize: configuration.threadCount,
                ioBackend: try Self.ioBackend(for: configuration.ioBackend)
            ) { executor in
                try await withTaskExecutorPreference(executor) {
                    let listener = try await TCPListener.bind(to: address)
                    let boundPort = try listener.localAddress.port
                    logger.info(
                        "HTTP/2 server listening",
                        metadata: ["host": .string(configuration.host), "port": .stringConvertible(boundPort)]
                    )

                    // HTTP/3 binds the same port for UDP, so that the port that is reported serves both.
                    var udpSocket: UDPSocket? = nil
                    if configuration.http3 != nil {
                        let udpAddress = try Self.socketAddress(host: configuration.host, port: Int(boundPort))
                        udpSocket = try await UDPSocket.bind(to: udpAddress)
                        logger.info(
                            "HTTP/3 server listening",
                            metadata: ["host": .string(configuration.host), "port": .stringConvertible(boundPort)]
                        )
                    }
                    portContinuation.yield(Int(boundPort))

                    do {
                        try await withThrowingDiscardingTaskGroup { group in
                            if let http3 = configuration.http3, let socket = udpSocket.take() {
                                var box: UDPSocket? = consume socket
                                group.addTask {
                                    let socket = box.take()!
                                    let quicTLS = ServerTLSConfiguration(
                                        certificateChain: configuration.certificateChain,
                                        privateKey: configuration.privateKey,
                                        alpnProtocols: ["h3"]
                                    )
                                    do {
                                        try await Self.serveHTTP3(
                                            socket: socket,
                                            configuration: http3,
                                            tlsConfiguration: try quicTLS.makeHandshakeConfiguration(),
                                            onStream: onStream,
                                            logger: logger
                                        )
                                    } catch {
                                        try? await socket.close()
                                        throw error
                                    }
                                    try await socket.close()
                                }
                            }
                            while !Task.isCancelled {
                                let connection = try await listener.accept()
                                var box: TCPConnection? = consume connection
                                group.addTask {
                                    let connection = box.take()!
                                    await Self.handleConnection(
                                        connection,
                                        onStream: onStream,
                                        tlsConfiguration: tlsConfiguration,
                                        http2Configuration: configuration.http2,
                                        logger: logger
                                    )
                                }
                            }
                        }
                    } catch {
                        try? await listener.close()
                        throw error
                    }
                    try await listener.close()
                }
            }
        } catch {
            portContinuation.finish(throwing: error)
            throw error
        }
        portContinuation.finish()
    }

    // MARK: - Connections

    /// Runs TLS and HTTP/2 on an accepted connection and closes it afterwards.
    ///
    /// Errors are logged: one failing peer must not stop the server.
    private static func handleConnection(
        _ connection: consuming TCPConnection,
        onStream: @escaping @Sendable (consuming HTTP2Stream) async -> Void,
        tlsConfiguration: ServerTLSConfiguration,
        http2Configuration: HTTP2ServerConfiguration,
        logger: Logger
    ) async {
        do {
            try await connection.withOwnedSplit { readHalf, writeHalf in
                try await Self.serveConnection(
                    reader: readHalf,
                    writer: writeHalf,
                    onStream: onStream,
                    tlsConfiguration: tlsConfiguration,
                    http2Configuration: http2Configuration,
                    logger: logger
                )
            }
        } catch {
            logger.debug("Connection terminated", metadata: ["error": .string(String(describing: error))])
        }
        try? await connection.close()
    }

    /// Serves HTTP/2 over TLS on a pair of byte streams.
    static func serveConnection<
        Reader: AsyncReader & Sendable & ~Copyable & ~Escapable,
        Writer: AsyncWriter & Sendable & ~Copyable & ~Escapable
    >(
        reader: consuming Reader,
        writer: consuming Writer,
        onStream: @escaping @Sendable (consuming HTTP2Stream) async -> Void,
        tlsConfiguration: ServerTLSConfiguration,
        http2Configuration: HTTP2ServerConfiguration,
        logger: Logger
    ) async throws
    where
        Reader.ReadElement == UInt8,
        Reader.FinalElement == Void,
        Writer.WriteElement == UInt8,
        Writer.FinalElement == Void
    {
        let tls = try await TLSConnection.accept(
            reader: reader,
            writer: writer,
            configuration: tlsConfiguration
        )
        let negotiated = tls.negotiatedALPNProtocol
        logger.debug("TLS handshake complete", metadata: ["alpn": .string(negotiated ?? "<none>")])
        guard negotiated == "h2" else {
            logger.warning(
                "ALPN mismatch, closing the connection",
                metadata: ["negotiated": .string(negotiated ?? "<none>")]
            )
            throw PlatformHTTPServerError.alpnMismatch(negotiated)
        }

        try await tls.withSplit { tlsReader, tlsWriter in
            let connection = HTTPConnection(reader: tlsReader, writer: tlsWriter)
            try await connection.withHTTP2Frames { frameReader, frameWriter in
                try await HTTP2ServerDriver(configuration: http2Configuration).run(
                    reader: frameReader,
                    writer: frameWriter,
                    onStream: onStream
                )
            }
        }
    }

    // MARK: - HTTP/3

    /// Serves HTTP/3 over QUIC on a bound UDP socket until the task is cancelled.
    static func serveHTTP3(
        socket: borrowing UDPSocket,
        configuration: HTTP3ServerConfiguration,
        tlsConfiguration: ServerHandshakeConfiguration,
        onStream: @escaping @Sendable (consuming HTTP2Stream) async -> Void,
        logger: Logger
    ) async throws {
        try await QUICServerEndpoint.run(
            socket: socket,
            configuration: configuration.quic,
            tlsConfiguration: tlsConfiguration,
            logger: logger
        ) { connection in
            guard connection.negotiatedALPN == "h3" else {
                // H3_VERSION_FALLBACK is not right either; the handshake only offers h3.
                connection.close(applicationErrorCode: HTTP3ErrorCode.generalProtocolError.rawValue)
                return
            }
            do {
                try await HTTP3ServerDriver(configuration: configuration).run(
                    connection: HTTP3Connection(quic: connection),
                    onStream: onStream
                )
                connection.close(applicationErrorCode: HTTP3ErrorCode.noError.rawValue)
            } catch {
                logger.debug("HTTP/3 connection terminated", metadata: ["error": .string(String(describing: error))])
            }
        }
    }

    // MARK: - Streams

    /// Runs the handler for the request of a stream and finishes the exchange.
    ///
    /// An error of the handler becomes a RST_STREAM, so that the connection survives it.
    static func handleStream<Handler: HTTPServerRequestHandler>(
        _ stream: consuming HTTP2Stream,
        handler: Handler,
        logger: Logger
    ) async
    where
        Handler.RequestContext == PlatformHTTPRequestContext,
        Handler.Reader == PlatformHTTPRequestBodyReader,
        Handler.ResponseSender == PlatformHTTPResponseSender
    {
        let id = stream.id
        let requestHeaders = stream.requestHeaders
        let requestEndStream = stream.requestEndStream
        var outbound = stream.outbound
        let inbound = stream.inbound

        let request: HTTPRequest
        do {
            request = try HPACKBridge.parseRequest(from: requestHeaders)
        } catch {
            let code: HTTP2StateMachine.HTTP2ErrorCode =
                switch error {
                case .unsupportedConnect: .refusedStream
                default: .protocolError
                }
            try? await outbound.send(.reset(code))
            logger.debug("Malformed request", metadata: ["error": .string(String(describing: error))])
            return
        }

        let readerState = PlatformHTTPRequestBodyReader.State(finished: requestEndStream)
        // The state owns the outbound side, so that the stream can be reset after the handler returned.
        let senderState = PlatformHTTPResponseSender.State(outbound: outbound)
        let reader = PlatformHTTPRequestBodyReader(inbound: inbound, state: readerState)
        let sender = PlatformHTTPResponseSender(state: senderState)

        var handlerError: (any Error)? = nil
        do {
            try await handler.handle(
                request: request,
                requestContext: PlatformHTTPRequestContext(),
                reader: reader,
                responseSender: sender
            )
        } catch {
            handlerError = error
        }

        // At most one RST_STREAM per stream is valid. The precedence is: error of the handler, unfinished response,
        // unread request body (RFC 9113, section 8.1).
        if let handlerError {
            logger.error(
                "Handler threw",
                metadata: [
                    "stream-id": .stringConvertible(id.value),
                    "error": .string(String(describing: handlerError)),
                ]
            )
            if !senderState.finishedWriting {
                try? await senderState.send(.reset(.internalError))
            }
        } else if !senderState.finishedWriting {
            logger.warning(
                "Handler returned without finishing the response",
                metadata: ["stream-id": .stringConvertible(id.value)]
            )
            try? await senderState.send(.reset(.internalError))
        } else if !readerState.finishedReading {
            // The response is complete, but the client still sends the body. Tell it to stop.
            try? await senderState.send(.reset(.noError))
        }
    }

    // MARK: - Addresses

    /// Maps the configured I/O backend to the one of the executors.
    ///
    /// - Throws: ``PlatformHTTPServerError/unavailableIOBackend(_:)`` if the platform or the build does not have it.
    static func ioBackend(for backend: PlatformHTTPServerConfiguration.IOBackend) throws -> PThreadIOBackend {
        switch backend {
        case .platformDefault:
            return .platformDefault

        case .epoll:
            #if canImport(Glibc)
            return .epoll
            #else
            throw PlatformHTTPServerError.unavailableIOBackend(backend)
            #endif

        case .ioUring:
            #if canImport(Glibc) && IOUring
            return .ioUring
            #else
            throw PlatformHTTPServerError.unavailableIOBackend(backend)
            #endif
        }
    }

    static func socketAddress(host: String, port: Int) throws -> SocketAddress {
        guard let port = UInt16(exactly: port) else {
            throw PlatformHTTPServerError.invalidHost("port \(port)")
        }
        if host == "localhost" {
            return .v4(SocketAddress.V4(address: .loopback, port: port))
        }
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else {
            throw PlatformHTTPServerError.invalidHost(host)
        }
        var bytes: [UInt8] = []
        for part in parts {
            guard let byte = UInt8(part) else {
                throw PlatformHTTPServerError.invalidHost(host)
            }
            bytes.append(byte)
        }
        return .v4(SocketAddress.V4(address: IPv4Address(bytes[0], bytes[1], bytes[2], bytes[3]), port: port))
    }
}
