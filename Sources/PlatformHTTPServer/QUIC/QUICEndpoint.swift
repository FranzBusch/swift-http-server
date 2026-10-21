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

import BinaryParsing
import DequeModule
import Logging
import PlatformExecutors
import SwiftTLSStateMachine
import Synchronization

/// Finds the connection of a datagram by its destination connection ID.
@available(anyAppleOS 27.0, *)
final class QUICRoutingTable: Sendable {
    private let routes = Mutex<[QUICConnectionID: QUICConnectionInbox]>([:])

    init() {}

    func inbox(for id: QUICConnectionID) -> QUICConnectionInbox? {
        self.routes.withLock { $0[id] }
    }

    func add(_ ids: [QUICConnectionID], for inbox: QUICConnectionInbox) {
        self.routes.withLock { routes in
            for id in ids {
                routes[id] = inbox
            }
        }
    }

    func remove(_ ids: [QUICConnectionID]) {
        self.routes.withLock { routes in
            for id in ids {
                routes.removeValue(forKey: id)
            }
        }
    }

    var count: Int { self.routes.withLock { $0.count } }
}

/// Hands new connections from the receive loop to the task that runs them.
@available(anyAppleOS 27.0, *)
final class QUICAcceptQueue: Sendable {
    private struct State: ~Copyable {
        var cores = Deque<QUICConnectionCore>()
        var finished = false
        var waiter: UnsafeContinuation<QUICConnectionCore?, Never>? = nil
    }

    private let state = Mutex(State())

    init() {}

    func yield(_ core: QUICConnectionCore) {
        let waiter = self.state.withLock { state -> UnsafeContinuation<QUICConnectionCore?, Never>? in
            guard !state.finished else { return nil }
            if let waiter = state.waiter.take() {
                return waiter
            }
            state.cores.append(core)
            return nil
        }
        waiter?.resume(returning: core)
    }

    func finish() {
        let waiter = self.state.withLock { state in
            state.finished = true
            return state.waiter.take()
        }
        waiter?.resume(returning: nil)
    }

    func next() async -> QUICConnectionCore? {
        await withTaskCancellationHandler {
            await withUnsafeContinuation { (continuation: UnsafeContinuation<QUICConnectionCore?, Never>) in
                let ready = self.state.withLock { state -> QUICConnectionCore?? in
                    if let core = state.cores.popFirst() {
                        return .some(core)
                    }
                    if state.finished {
                        return .some(nil)
                    }
                    state.waiter = continuation
                    return nil
                }
                if let ready {
                    continuation.resume(returning: ready)
                }
            }
        } onCancel: {
            self.finish()
        }
    }
}

/// The server side of QUIC on one UDP socket.
///
/// The endpoint receives the datagrams of all connections on the socket and routes them by their destination
/// connection ID. A datagram with an Initial packet for an unknown connection ID starts a new connection, which runs
/// in its own child task: it performs the handshake and then calls the handler with the connection. All connections
/// send through one task that owns the sending half of the socket, and share one ``QUICTimerService``.
@available(anyAppleOS 27.0, *)
enum QUICServerEndpoint {
    /// The size of the receive buffer, the largest UDP payload.
    static var maximumDatagramSize: Int { 65527 }

    /// Serves QUIC until the task is cancelled or the socket fails.
    ///
    /// - Parameters:
    ///   - socket: A bound socket. It stays open; the caller closes it.
    ///   - configuration: The configuration of every connection.
    ///   - tlsConfiguration: The certificate and ALPN protocols of the handshake.
    ///   - handler: Runs a connection after its handshake. The connection ends when the handler returns.
    static func run(
        socket: borrowing UDPSocket,
        configuration: QUICConnectionConfiguration,
        tlsConfiguration: ServerHandshakeConfiguration,
        logger: Logger,
        handler: @escaping @Sendable (QUICConnection) async -> Void
    ) async throws {
        let routes = QUICRoutingTable()
        let timers = QUICTimerService()
        let output = QUICDatagramQueue()
        let accepted = QUICAcceptQueue()

        try await socket.withSplit { receiveHalf, sendHalf in
            _ = try await withConcurrently {
                defer {
                    accepted.finish()
                    output.finish()
                    timers.finish()
                }
                try await Self.receiveLoop(
                    &receiveHalf,
                    routes: routes,
                    timers: timers,
                    output: output,
                    accepted: accepted,
                    configuration: configuration,
                    tlsConfiguration: tlsConfiguration,
                    logger: logger
                )
            } _: {
                _ = try await withConcurrently {
                    try await Self.sendLoop(&sendHalf, output: output, logger: logger)
                } _: {
                    await Self.runConnections(
                        accepted: accepted,
                        routes: routes,
                        timers: timers,
                        logger: logger,
                        handler: handler
                    )
                }
            }
        }
    }

    private static func receiveLoop(
        _ receiveHalf: inout UDPSocket.ReceiveHalf,
        routes: QUICRoutingTable,
        timers: QUICTimerService,
        output: QUICDatagramQueue,
        accepted: QUICAcceptQueue,
        configuration: QUICConnectionConfiguration,
        tlsConfiguration: ServerHandshakeConfiguration,
        logger: Logger
    ) async throws {
        let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: Self.maximumDatagramSize, alignment: 16)
        defer { buffer.deallocate() }

        while !Task.isCancelled {
            var span = OutputRawSpan(buffer: buffer, initializedCount: 0)
            let (count, sender) = try await receiveHalf.receive(into: &span)
            _ = span.finalize(for: buffer)
            guard count > 0 else { continue }
            let bytes = Array(UnsafeRawBufferPointer(rebasing: buffer[0..<count]))
            logger.trace("Received a datagram", metadata: ["bytes": .stringConvertible(count), "peer": .string("\(sender)")])

            guard let destination = Self.destinationConnectionID(of: bytes, shortHeaderLength: configuration.connectionIDLength)
            else { continue }
            if let inbox = routes.inbox(for: destination) {
                inbox.yield(QUICReceivedDatagram(bytes: bytes, peer: sender))
                continue
            }
            Self.handleUnknown(
                bytes,
                from: sender,
                routes: routes,
                timers: timers,
                output: output,
                accepted: accepted,
                configuration: configuration,
                tlsConfiguration: tlsConfiguration,
                logger: logger
            )
        }
    }

    /// The destination connection ID of the first packet of a datagram, without parsing the rest.
    static func destinationConnectionID(of bytes: [UInt8], shortHeaderLength: Int) -> QUICConnectionID? {
        guard let first = bytes.first else { return nil }
        if first & 0x80 == 0 {
            guard bytes.count >= 1 + shortHeaderLength else { return nil }
            return QUICConnectionID(Array(bytes[1..<(1 + shortHeaderLength)]))
        }
        guard bytes.count >= 6 else { return nil }
        let length = Int(bytes[5])
        guard length <= QUICConnectionID.maximumLength, bytes.count >= 6 + length else { return nil }
        return QUICConnectionID(Array(bytes[6..<(6 + length)]))
    }

    /// Starts a connection for an Initial packet, answers an unknown version with Version Negotiation, and drops
    /// everything else.
    private static func handleUnknown(
        _ bytes: [UInt8],
        from sender: SocketAddress,
        routes: QUICRoutingTable,
        timers: QUICTimerService,
        output: QUICDatagramQueue,
        accepted: QUICAcceptQueue,
        configuration: QUICConnectionConfiguration,
        tlsConfiguration: ServerHandshakeConfiguration,
        logger: Logger
    ) {
        let raw = bytes.span.bytes
        var input = ParserSpan(raw)
        guard let packet = try? QUICProtectedPacket(parsing: &input, shortHeaderConnectionIDLength: configuration.connectionIDLength)
        else {
            logger.debug("Dropped a datagram that does not parse", metadata: ["bytes": .stringConvertible(bytes.count)])
            return
        }
        logger.debug("Datagram for an unknown connection", metadata: ["header": .string("\(packet.header)")])

        switch packet.header {
        case .long(let header) where header.type == .initial:
            // A client pads the datagram of its first Initial to 1200 bytes (RFC 9000, section 14.1).
            guard bytes.count >= 1200 else { return }
            let now = ContinuousClock.now
            let connection = QUICConnectionState(
                serverWithInitial: header,
                peer: sender,
                configuration: configuration,
                tlsConfiguration: tlsConfiguration,
                now: now
            )
            let ids = connection.connectionIDs
            let inbox = QUICConnectionInbox()
            let core = QUICConnectionCore(connection: connection, inbox: inbox, timers: timers, output: output)
            routes.add(ids, for: inbox)
            inbox.yield(QUICReceivedDatagram(bytes: bytes, peer: sender))
            accepted.yield(core)

        case .unsupportedVersion(_, let destination, let source):
            // Version Negotiation swaps the connection IDs of the client's packet (RFC 9000, section 17.2.1).
            guard bytes.count >= 1200 else { return }
            let packet = QUICVersionNegotiationPacket(
                destinationConnectionID: source,
                sourceConnectionID: destination,
                supportedVersions: [QUICVersion.version1]
            )
            var datagram = [UInt8](repeating: 0, count: packet.encodedLength)
            datagram.withUnsafeMutableBufferPointer { pointer in
                var output = OutputSpan<UInt8>(buffer: pointer, initializedCount: 0)
                packet.encode(into: &output)
                _ = output.finalize(for: pointer)
            }
            output.send(CollectionOfOne(QUICOutboundDatagram(bytes: datagram, peer: sender)))

        default:
            // Packets of a connection that is gone, or that is not ours. A stateless reset is not sent.
            break
        }
    }

    private static func sendLoop(
        _ sendHalf: inout UDPSocket.SendHalf,
        output: QUICDatagramQueue,
        logger: Logger
    ) async throws {
        while let batch = await output.next() {
            for datagram in batch {
                do {
                    try await sendHalf.send(from: datagram.bytes.span.bytes, to: datagram.peer)
                } catch {
                    // A datagram that cannot be sent is lost; QUIC recovers from it.
                    logger.debug("Sending a datagram failed", metadata: ["error": .string(String(describing: error))])
                }
            }
        }
    }

    private static func runConnections(
        accepted: QUICAcceptQueue,
        routes: QUICRoutingTable,
        timers: QUICTimerService,
        logger: Logger,
        handler: @escaping @Sendable (QUICConnection) async -> Void
    ) async {
        await withDiscardingTaskGroup { group in
            group.addTask {
                await timers.run()
            }
            while let core = await accepted.next() {
                group.addTask {
                    await Self.runConnection(core, routes: routes, logger: logger, handler: handler)
                }
            }
            timers.finish()
            group.cancelAll()
        }
    }

    private static func runConnection(
        _ core: QUICConnectionCore,
        routes: QUICRoutingTable,
        logger: Logger,
        handler: @escaping @Sendable (QUICConnection) async -> Void
    ) async {
        defer {
            let ids = core.withConnection { $0.connectionIDs }
            routes.remove(ids)
            core.inbox.finish()
            core.disarm()
        }
        let connection: QUICConnection
        do {
            connection = try await QUICConnection.accept(core)
        } catch {
            logger.debug("QUIC handshake failed", metadata: ["error": .string(String(describing: error))])
            return
        }
        await handler(connection)
        // A handler that returns without closing ends the connection without an error.
        connection.close(applicationErrorCode: 0)
    }
}

@available(anyAppleOS 27.0, *)
extension QUICConnectionCore {
    /// Stops the timer of a connection that ended.
    func disarm() {
        _ = try? self.update { (_, _) throws(QUICConnectionError) in }
    }
}

/// The client side of QUIC with one connection on its own UDP socket. Meant for tests.
@available(anyAppleOS 27.0, *)
enum QUICClientEndpoint {
    /// Ends the receive loop once the body returned, carrying its result.
    private struct Done: Error {
        var result: Result<any Sendable, any Error>
    }

    /// Connects to a server and runs the body with the connection once the handshake completed.
    ///
    /// The connection is closed with application error code 0 when the body returns.
    static func withConnection<Return: Sendable>(
        to server: SocketAddress,
        socket: borrowing UDPSocket,
        configuration: QUICConnectionConfiguration = .init(),
        tlsConfiguration: ClientHandshakeConfiguration,
        body: @escaping @Sendable (QUICConnection) async throws -> Return
    ) async throws -> Return {
        let timers = QUICTimerService()
        let output = QUICDatagramQueue()
        let inbox = QUICConnectionInbox()
        let connection = try QUICConnectionState(
            clientTo: server,
            configuration: configuration,
            tlsConfiguration: tlsConfiguration,
            now: .now
        )
        let core = QUICConnectionCore(connection: connection, inbox: inbox, timers: timers, output: output)
        // Flushes the ClientHello.
        core.disarm()

        do {
            try await socket.withSplit { receiveHalf, sendHalf in
                _ = try await withConcurrently { () async throws -> Void in
                    let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: 65527, alignment: 16)
                    defer { buffer.deallocate() }
                    while true {
                        var span = OutputRawSpan(buffer: buffer, initializedCount: 0)
                        let received = try await receiveHalf.receive(into: &span)
                        _ = span.finalize(for: buffer)
                        inbox.yield(
                            QUICReceivedDatagram(
                                bytes: Array(UnsafeRawBufferPointer(rebasing: buffer[0..<received.count])),
                                peer: received.sender
                            )
                        )
                    }
                } _: { () async throws -> Void in
                    _ = try await withConcurrently { () async throws -> Void in
                        while let batch = await output.next() {
                            for datagram in batch {
                                try? await sendHalf.send(from: datagram.bytes.span.bytes, to: datagram.peer)
                            }
                        }
                    } _: { () async throws -> Void in
                        let result: Result<any Sendable, any Error> = await withDiscardingTaskGroup { group in
                            group.addTask { await timers.run() }
                            let result: Result<any Sendable, any Error>
                            do {
                                let established = try await QUICConnection.accept(core)
                                result = .success(try await body(established))
                                established.close(applicationErrorCode: 0)
                            } catch {
                                result = .failure(error)
                            }
                            timers.finish()
                            return result
                        }
                        output.finish()
                        throw Done(result: result)
                    }
                }
            }
        } catch let done as Done {
            inbox.finish()
            return try done.result.get() as! Return
        }
        fatalError("The receive loop only ends with an error")
    }
}
