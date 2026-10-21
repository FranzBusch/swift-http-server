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
import DequeModule
import Synchronization

/// The shared part of a connection: its state machine and how it reaches the endpoint.
///
/// The reader and the writer of a connection use it from different tasks. Whoever changes the state flushes the
/// datagrams that became ready and re-arms the timer of the connection.
@available(anyAppleOS 27.0, *)
final class QUICConnectionCore: Sendable {
    private struct Shared: ~Copyable {
        var connection: QUICConnectionState
        var armedDeadline: ContinuousClock.Instant? = nil
        var capacityWaiter: UnsafeContinuation<Void, Never>? = nil
    }

    private let shared: Mutex<Shared>
    let inbox: QUICConnectionInbox
    private let timers: QUICTimerService
    private let output: QUICDatagramQueue

    /// The bytes queued on streams above which a writer waits until they are sent.
    static var sendBufferLimit: Int { 1024 * 1024 }

    init(
        connection: consuming QUICConnectionState,
        inbox: QUICConnectionInbox,
        timers: QUICTimerService,
        output: QUICDatagramQueue
    ) {
        self.shared = Mutex(Shared(connection: connection))
        self.inbox = inbox
        self.timers = timers
        self.output = output
    }

    /// Runs a change of the state and flushes what the change made ready.
    func update<Result>(
        _ body: (inout QUICConnectionState, ContinuousClock.Instant) throws(QUICConnectionError) -> Result
    ) throws(QUICConnectionError) -> Result {
        let now = ContinuousClock.now
        var datagrams: [QUICOutboundDatagram] = []
        let (result, deadline, rearm, waiter):
            (Swift.Result<Result, QUICConnectionError>, ContinuousClock.Instant?, Bool, UnsafeContinuation<Void, Never>?) =
                self.shared.withLock { shared in
                    let result: Swift.Result<Result, QUICConnectionError>
                    do throws(QUICConnectionError) {
                        result = .success(try body(&shared.connection, now))
                    } catch {
                        result = .failure(error)
                    }
                    shared.connection.makeDatagrams(now: now, into: &datagrams)
                    let deadline = shared.connection.nextDeadline
                    let rearm = deadline != shared.armedDeadline
                    shared.armedDeadline = deadline
                    var waiter: UnsafeContinuation<Void, Never>? = nil
                    if shared.connection.isClosed
                        || shared.connection.pendingStreamBytes < Self.sendBufferLimit / 2
                    {
                        waiter = shared.capacityWaiter.take()
                    }
                    return (result, deadline, rearm, waiter)
                }
        if !datagrams.isEmpty {
            self.output.send(datagrams)
        }
        if rearm {
            self.timers.schedule(self.inbox, at: deadline)
        }
        waiter?.resume()
        return try result.get()
    }

    /// Reads the state without changing it.
    func withConnection<Result>(_ body: (borrowing QUICConnectionState) -> Result) -> Result {
        self.shared.withLock { body($0.connection) }
    }

    /// Waits until the bytes queued on streams fall below half of ``sendBufferLimit``, or the connection closes.
    func waitForSendCapacity() async {
        await withUnsafeContinuation { (continuation: UnsafeContinuation<Void, Never>) in
            let ready = self.shared.withLock { shared -> Bool in
                if shared.connection.isClosed || shared.connection.pendingStreamBytes < Self.sendBufferLimit {
                    return true
                }
                shared.capacityWaiter = continuation
                return false
            }
            if ready {
                continuation.resume()
            }
        }
    }

    /// Processes the next event of the inbox.
    ///
    /// - Returns: `false` once the inbox finished.
    func processNextEvent() async -> Bool {
        guard let event = await self.inbox.next() else {
            return false
        }
        // The state machine reports failures through its error, not by throwing.
        _ = try? self.update { (connection, now) throws(QUICConnectionError) in
            switch event {
            case .datagrams(let datagrams):
                for datagram in datagrams {
                    connection.receive(datagram: datagram.bytes, from: datagram.peer, now: now)
                }
            case .timer:
                connection.handleTimeout(now: now)
            case .wakeUp:
                break
            }
        }
        return true
    }
}

/// A QUIC connection whose handshake completed.
///
/// ``QUICServerEndpoint`` accepts connections. A connection is split with ``withSplit(_:)`` into a
/// ``QUICFrameReader`` and a ``QUICFrameWriter`` that different tasks can use at the same time, like the halves of
/// a ``TLSConnection``.
///
/// The frames are those of the application: the reader returns STREAM frames with the bytes of each stream in order,
/// RESET_STREAM and STOP_SENDING. The writer takes STREAM frames (their offset is ignored, the bytes are appended to
/// the stream), RESET_STREAM, STOP_SENDING and an application CONNECTION_CLOSE. Acknowledgments, retransmissions,
/// flow control and the other frames of the transport are handled by the connection.
@available(anyAppleOS 27.0, *)
struct QUICConnection: Sendable {
    let core: QUICConnectionCore

    /// The negotiated ALPN protocol.
    let negotiatedALPN: String?

    init(core: QUICConnectionCore) {
        self.core = core
        self.negotiatedALPN = core.withConnection { $0.negotiatedALPN }
    }

    /// Runs the handshake of a new connection, whose first datagram is in the inbox.
    ///
    /// - Throws: ``QUICConnectionError`` if the handshake fails or the connection closes before it completes.
    static func accept(_ core: QUICConnectionCore) async throws(QUICConnectionError) -> QUICConnection {
        while true {
            let (complete, error) = core.withConnection { ($0.isHandshakeComplete, $0.error) }
            if let error {
                throw error
            }
            if complete {
                return QUICConnection(core: core)
            }
            guard await core.processNextEvent() else {
                throw QUICConnectionError(kind: .handshakeFailed, reason: "The connection was cancelled")
            }
        }
    }

    /// Splits the connection into a reader and a writer that can be used by different tasks.
    func withSplit<Return: ~Copyable, Failure: Error>(
        _ body: (consuming QUICFrameReader, consuming QUICFrameWriter) async throws(Failure) -> Return
    ) async throws(Failure) -> Return {
        try await body(QUICFrameReader(core: self.core), QUICFrameWriter(core: self.core))
    }

    /// Resets the sending direction of a stream.
    func reset(streamID: UInt64, applicationErrorCode: UInt64) {
        _ = try? self.core.update { (connection, _) throws(QUICConnectionError) in
            connection.reset(streamID: streamID, applicationErrorCode: applicationErrorCode)
        }
    }

    /// Asks the peer to stop sending on a stream.
    func stopSending(streamID: UInt64, applicationErrorCode: UInt64) {
        _ = try? self.core.update { (connection, _) throws(QUICConnectionError) in
            connection.stopSending(streamID: streamID, applicationErrorCode: applicationErrorCode)
        }
    }

    /// Closes the connection with an application error code.
    func close(applicationErrorCode: UInt64, reason: String = "") {
        _ = try? self.core.update { (connection, _) throws(QUICConnectionError) in
            connection.close(applicationErrorCode: applicationErrorCode, reason: reason)
        }
    }
}

/// Reads the application frames of a QUIC connection.
///
/// Reading also drives the connection: the reader processes the datagrams and the timers of the connection while it
/// waits for frames. The reader ends with the final element when the peer closes the connection without an error
/// (application error code 0 or H3_NO_ERROR is up to the protocol above), and throws the ``QUICConnectionError``
/// otherwise.
@available(anyAppleOS 27.0, *)
struct QUICFrameReader: AsyncReader, ~Copyable, Sendable {
    typealias ReadElement = QUICFrame
    typealias ReadFailure = any Error
    typealias Buffer = UniqueArray<QUICFrame>
    typealias FinalElement = Void

    private let core: QUICConnectionCore
    private var buffer = UniqueArray<QUICFrame>()

    init(core: QUICConnectionCore) {
        self.core = core
    }

    mutating func read<Return: ~Copyable, Failure: Error>(
        body: (inout UniqueArray<QUICFrame>, consuming Void?) async throws(Failure) -> Return
    ) async throws(EitherError<any Error, Failure>) -> Return {
        self.buffer.removeAll(keepingCapacity: true)
        var ended = false
        while true {
            let (events, error, closed) = self.core.withConnectionMutating()
            for event in events {
                self.buffer.append(event)
            }
            if !self.buffer.isEmpty {
                break
            }
            if closed {
                if let error, !Self.isGraceful(error) {
                    throw .first(error)
                }
                ended = true
                break
            }
            if !(await self.core.processNextEvent()) {
                ended = true
                break
            }
        }
        do throws(Failure) {
            return try await body(&self.buffer, ended ? () : nil)
        } catch {
            throw .second(error)
        }
    }

    /// Whether the connection ended without a failure: an application close of either side.
    private static func isGraceful(_ error: QUICConnectionError) -> Bool {
        switch error.kind {
        case .peerApplicationClose, .localApplicationClose: true
        default: false
        }
    }
}

@available(anyAppleOS 27.0, *)
extension QUICConnectionCore {
    /// Takes the events for the application and tells whether the connection is closed.
    fileprivate func withConnectionMutating() -> (Deque<QUICFrame>, QUICConnectionError?, Bool) {
        (try? self.update { (connection, _) throws(QUICConnectionError) in
            (connection.takeEvents(), connection.error, connection.isClosed)
        }) ?? ([], nil, true)
    }
}

/// Writes the application frames of a QUIC connection.
@available(anyAppleOS 27.0, *)
struct QUICFrameWriter: CallerAsyncWriter, ~Copyable, Sendable {
    typealias WriteElement = QUICFrame
    typealias WriteFailure = any Error
    typealias FinalElement = Void

    private let core: QUICConnectionCore

    init(core: QUICConnectionCore) {
        self.core = core
    }

    mutating func write<Buffer: RangeReplaceableContainer<QUICFrame> & ~Copyable>(
        buffer: inout Buffer
    ) async throws(any Error) where Buffer.Element: ~Copyable {
        let pending = try self.core.update { (connection, _) throws(QUICConnectionError) -> Int in
            var index = buffer.startIndex
            while index < buffer.endIndex {
                let span = buffer.nextSpan(after: &index)
                for position in span.indices {
                    try Self.apply(span[position], to: &connection)
                }
            }
            return connection.pendingStreamBytes
        }
        buffer.removeAll()
        if pending >= QUICConnectionCore.sendBufferLimit {
            await self.core.waitForSendCapacity()
        }
    }

    consuming func finish<Buffer: RangeReplaceableContainer<QUICFrame> & ~Copyable>(
        buffer: inout Buffer,
        finalElement: consuming Void
    ) async throws(any Error) where Buffer.Element: ~Copyable {
        try await self.write(buffer: &buffer)
    }

    private static func apply(_ frame: borrowing QUICFrame, to connection: inout QUICConnectionState) throws(QUICConnectionError) {
        switch frame {
        case .stream(let stream):
            try connection.send(streamID: stream.streamID, data: stream.data, fin: stream.fin)
        case .resetStream(let streamID, let code, _):
            connection.reset(streamID: streamID, applicationErrorCode: code)
        case .stopSending(let streamID, let code):
            connection.stopSending(streamID: streamID, applicationErrorCode: code)
        case .connectionClose(let close):
            if case .application(let code) = close.error {
                connection.close(
                    applicationErrorCode: code,
                    reason: String(decoding: close.reasonPhrase, as: UTF8.self)
                )
            }
        default:
            // The transport frames belong to the connection.
            break
        }
    }
}
