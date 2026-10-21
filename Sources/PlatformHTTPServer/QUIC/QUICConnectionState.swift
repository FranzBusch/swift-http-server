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
import PlatformExecutors
import SwiftTLSStateMachine

extension QUICTransportErrorCode: Error {}
extension QUICConnectionCloseFrame: Error {}

/// The configuration of a QUIC connection.
@available(anyAppleOS 27.0, *)
public struct QUICConnectionConfiguration: Sendable {
    /// The largest datagram that the connection sends once the handshake is done. Datagrams during the handshake
    /// have at most 1200 bytes. The path MTU is not discovered.
    public var maxDatagramSize: Int = 1350

    /// The time after which a connection without activity is closed silently (RFC 9000, section 10.1).
    public var idleTimeout: Duration = .seconds(30)

    /// The bytes that the peer may send on all streams before it receives a MAX_DATA frame.
    public var connectionReceiveWindow: UInt64 = 16 * 1024 * 1024

    /// The bytes that the peer may send on a stream before it receives a MAX_STREAM_DATA frame.
    public var streamReceiveWindow: UInt64 = 1024 * 1024

    /// The streams of each type that the peer may have open at the same time.
    public var maxConcurrentBidirectionalStreams: UInt64 = 128
    public var maxConcurrentUnidirectionalStreams: UInt64 = 16

    /// The longest time that the connection delays acknowledgments of 1-RTT packets.
    public var maxAckDelay: Duration = .milliseconds(25)

    /// The length of the connection IDs that this endpoint issues.
    public var connectionIDLength: Int = 8

    public init() {}
}

/// The reason why a QUIC connection ended.
@available(anyAppleOS 27.0, *)
public struct QUICConnectionError: Error, Hashable, Sendable, CustomStringConvertible {
    public enum Kind: Hashable, Sendable {
        /// This endpoint closed the connection because of a transport error.
        case localTransportError(code: UInt64)
        /// This endpoint's application closed the connection.
        case localApplicationClose(code: UInt64)
        /// The peer closed the connection because of a transport error.
        case peerTransportError(code: UInt64)
        /// The peer's application closed the connection.
        case peerApplicationClose(code: UInt64)
        /// The idle timeout expired.
        case idleTimeout
        /// The handshake failed or did not complete.
        case handshakeFailed
    }

    public var kind: Kind
    public var reason: String

    public var description: String { "\(self.kind): \(self.reason)" }
}

@available(anyAppleOS 27.0, *)
enum QUICRole: Sendable {
    case client
    case server
}

/// The state of one packet number space (RFC 9000, section 12.3).
@available(anyAppleOS 27.0, *)
struct QUICPacketSpace: Sendable {
    var readKeys: QUICPacketKeys? = nil
    var writeKeys: QUICPacketKeys? = nil
    var nextPacketNumber: UInt64 = 0
    var received = QUICReceivedPackets()
    var sent = Deque<QUICSentPacket>()
    var largestAcknowledged: UInt64? = nil
    var lossTime: ContinuousClock.Instant? = nil
    var lastAckElicitingSentAt: ContinuousClock.Instant? = nil
    var cryptoReceive = QUICReceiveBuffer()
    var cryptoSend = QUICSendBuffer()
    var cryptoRetransmits = Deque<(offset: UInt64, data: [UInt8])>()
    var probesPending = 0
    var discarded = false

    var hasAckElicitingInFlight: Bool {
        self.sent.contains { $0.isAckEliciting }
    }
}

/// One stream of a connection.
@available(anyAppleOS 27.0, *)
struct QUICStreamState: Sendable {
    /// The receiving direction, `nil` for a unidirectional stream that this endpoint opened.
    var receive: QUICReceiveBuffer?
    /// The offset up to which the peer may send, as last advertised.
    var receiveLimit: UInt64 = 0
    /// Whether the end of the receiving direction (FIN or reset) was delivered to the application.
    var receiveFinished = false

    /// The sending direction, `nil` for a unidirectional stream that the peer opened.
    var send: QUICSendBuffer?
    /// The offset up to which this endpoint may send, as the peer allows.
    var sendLimit: UInt64 = 0
    /// Whether the sending direction ended with a FIN or a RESET_STREAM.
    var sendFinished = false
    var isReset = false

    var isComplete: Bool {
        (self.receive == nil || self.receiveFinished) && (self.send == nil || self.sendFinished)
    }
}

/// A built packet before it is sealed.
@available(anyAppleOS 27.0, *)
private struct QUICPacketDraft {
    var space: QUICPacketNumberSpace
    var packetNumber: UInt64
    var packetNumberLength: Int
    var payload: [UInt8]
    var record: QUICSentPacket
}

/// The state machine of a QUIC connection, on either side (RFC 9000, RFC 9001, RFC 9002).
///
/// The state machine does not perform I/O and does not read a clock: datagrams and the current time go in with
/// ``receive(datagram:from:now:)`` and ``handleTimeout(now:)``, and ``makeDatagrams(now:into:)`` produces the
/// datagrams to send. The application exchanges stream data with it through ``send(streamID:data:fin:)`` and
/// ``takeEvents()``.
///
/// The application events are ``QUICFrame`` values: STREAM frames with the bytes of a stream in order and without
/// gaps or duplicates, RESET_STREAM and STOP_SENDING. Everything else is handled by the connection.
@available(anyAppleOS 27.0, *)
struct QUICConnectionState: ~Copyable {
    let role: QUICRole
    let configuration: QUICConnectionConfiguration

    private(set) var localConnectionID: QUICConnectionID
    private(set) var originalDestinationConnectionID: QUICConnectionID
    private(set) var peerConnectionID: QUICConnectionID
    private(set) var peerAddress: SocketAddress
    private var receivedFirstServerPacket = false

    private var spaces: [QUICPacketSpace] = [QUICPacketSpace(), QUICPacketSpace(), QUICPacketSpace()]

    // 1-RTT key updates (RFC 9001, section 6).
    private var keyPhase = false
    private var nextReadKeys: QUICPacketKeys? = nil

    private var serverHandshake: QUICServerHandshakeStateMachine?
    private var clientHandshake: QUICClientHandshakeStateMachine?
    private var pendingApplicationSecrets: QUICTrafficSecrets? = nil
    private(set) var isHandshakeComplete = false
    private(set) var isHandshakeConfirmed = false
    private(set) var negotiatedALPN: String? = nil
    private(set) var peerParameters: QUICTransportParameters? = nil
    private let localParameters: QUICTransportParameters

    // Address validation (RFC 9000, section 8.1).
    private var isAddressValidated: Bool
    private var bytesReceived = 0
    private var bytesSent = 0

    private var rtt = QUICRTTEstimator()
    private var congestion: QUICCongestionController
    private var probeTimeoutCount = 0
    private var idleDeadline: ContinuousClock.Instant
    private var ackElicitingSentSinceReceive = false

    // Streams and flow control.
    private var streams: [UInt64: QUICStreamState] = [:]
    private var sendOrder = Deque<UInt64>()
    private var streamRetransmits = Deque<QUICStreamFrame>()
    private var localMaxData: UInt64
    private var receivedData: UInt64 = 0
    private var deliveredData: UInt64 = 0
    private var peerMaxData: UInt64 = 0
    private var sentData: UInt64 = 0
    /// The streams that the peer opened, by type (index 0: bidirectional, 1: unidirectional).
    private var peerStreamsOpened: [UInt64] = [0, 0]
    private var peerStreamsClosed: [UInt64] = [0, 0]
    private var localMaxStreams: [UInt64]
    private var peerMaxStreams: [UInt64] = [0, 0]
    /// The streams that this endpoint opened, by type, so that a finished stream is not opened again.
    private var localStreamsOpened: [UInt64] = [0, 0]
    private var pendingControl = Deque<QUICRetransmittableFrame>()
    private var pendingPathResponses: [UInt64] = []

    private var events = Deque<QUICFrame>()

    private enum Lifecycle {
        case open
        /// A CONNECTION_CLOSE is queued and goes out with the next datagrams.
        case closing(QUICConnectionCloseFrame)
        case closed
    }
    private var lifecycle = Lifecycle.open
    private(set) var error: QUICConnectionError? = nil

    // MARK: - Creation

    /// Creates the server side of a connection from the first Initial packet of a client.
    ///
    /// - Parameters:
    ///   - initial: The long header of the first packet of the client's first datagram.
    ///   - transportParameters: Filled in with the connection IDs; the other values come from the configuration.
    init(
        serverWithInitial initial: QUICLongHeader,
        peer: SocketAddress,
        configuration: QUICConnectionConfiguration,
        tlsConfiguration: ServerHandshakeConfiguration,
        now: ContinuousClock.Instant
    ) {
        self.role = .server
        self.configuration = configuration
        self.localConnectionID = QUICConnectionID.random(length: configuration.connectionIDLength)
        self.originalDestinationConnectionID = initial.destinationConnectionID
        self.peerConnectionID = initial.sourceConnectionID
        self.peerAddress = peer
        self.isAddressValidated = false
        self.congestion = QUICCongestionController(maxDatagramSize: configuration.maxDatagramSize)
        self.idleDeadline = now + configuration.idleTimeout
        self.localMaxData = configuration.connectionReceiveWindow
        self.localMaxStreams = [
            configuration.maxConcurrentBidirectionalStreams, configuration.maxConcurrentUnidirectionalStreams,
        ]

        var parameters = Self.makeParameters(configuration)
        parameters.originalDestinationConnectionID = initial.destinationConnectionID
        parameters.initialSourceConnectionID = self.localConnectionID
        self.localParameters = parameters

        let keys = QUICPacketKeys.initial(destinationConnectionID: initial.destinationConnectionID)
        self.spaces[QUICPacketNumberSpace.initial.rawValue].readKeys = keys.client
        self.spaces[QUICPacketNumberSpace.initial.rawValue].writeKeys = keys.server
        self.serverHandshake = QUICServerHandshakeStateMachine(
            configuration: tlsConfiguration,
            transportParameters: parameters.encoded
        )
        self.clientHandshake = nil
    }

    /// Creates the client side of a connection and queues its ClientHello.
    init(
        clientTo peer: SocketAddress,
        configuration: QUICConnectionConfiguration,
        tlsConfiguration: ClientHandshakeConfiguration,
        now: ContinuousClock.Instant
    ) throws(QUICConnectionError) {
        self.role = .client
        self.configuration = configuration
        self.localConnectionID = QUICConnectionID.random(length: configuration.connectionIDLength)
        let destination = QUICConnectionID.random(length: 8)
        self.originalDestinationConnectionID = destination
        self.peerConnectionID = destination
        self.peerAddress = peer
        self.isAddressValidated = true
        self.congestion = QUICCongestionController(maxDatagramSize: configuration.maxDatagramSize)
        self.idleDeadline = now + configuration.idleTimeout
        self.localMaxData = configuration.connectionReceiveWindow
        self.localMaxStreams = [
            configuration.maxConcurrentBidirectionalStreams, configuration.maxConcurrentUnidirectionalStreams,
        ]

        var parameters = Self.makeParameters(configuration)
        parameters.initialSourceConnectionID = self.localConnectionID
        self.localParameters = parameters

        let keys = QUICPacketKeys.initial(destinationConnectionID: destination)
        self.spaces[QUICPacketNumberSpace.initial.rawValue].readKeys = keys.server
        self.spaces[QUICPacketNumberSpace.initial.rawValue].writeKeys = keys.client
        self.serverHandshake = nil
        var handshake = QUICClientHandshakeStateMachine(
            configuration: tlsConfiguration,
            transportParameters: parameters.encoded
        )
        let output: QUICHandshakeOutput
        do {
            output = try handshake.start()
        } catch {
            throw QUICConnectionError(kind: .handshakeFailed, reason: "\(error)")
        }
        self.clientHandshake = consume handshake
        self.spaces[QUICPacketNumberSpace.initial.rawValue].cryptoSend.append(output.initialData)
    }

    private static func makeParameters(_ configuration: QUICConnectionConfiguration) -> QUICTransportParameters {
        var parameters = QUICTransportParameters()
        parameters.maxIdleTimeout = UInt64(configuration.idleTimeout.components.seconds) * 1000
        parameters.maxUDPPayloadSize = 65527
        parameters.initialMaxData = configuration.connectionReceiveWindow
        parameters.initialMaxStreamDataBidiLocal = configuration.streamReceiveWindow
        parameters.initialMaxStreamDataBidiRemote = configuration.streamReceiveWindow
        parameters.initialMaxStreamDataUni = configuration.streamReceiveWindow
        parameters.initialMaxStreamsBidi = configuration.maxConcurrentBidirectionalStreams
        parameters.initialMaxStreamsUni = configuration.maxConcurrentUnidirectionalStreams
        parameters.maxAckDelay = UInt64(configuration.maxAckDelay.components.attoseconds / 1_000_000_000_000_000)
            + UInt64(configuration.maxAckDelay.components.seconds) * 1000
        parameters.disableActiveMigration = true
        return parameters
    }

    // MARK: - Queries

    /// Whether the connection ended. ``error`` tells why.
    var isClosed: Bool {
        if case .closed = self.lifecycle { return true }
        return false
    }

    /// The bytes that the application queued on streams and that were not sent yet.
    private(set) var pendingStreamBytes = 0

    /// The earliest time at which ``handleTimeout(now:)`` has to be called.
    var nextDeadline: ContinuousClock.Instant? {
        if self.isClosed { return nil }
        var deadline = self.idleDeadline
        if let recovery = self.recoveryDeadline {
            deadline = min(deadline, recovery)
        }
        for space in self.spaces where !space.discarded && space.writeKeys != nil {
            if let ack = space.received.ackDeadline {
                deadline = min(deadline, ack)
            }
        }
        return deadline
    }

    /// The state of recovery and flow control, for debugging.
    var debugSummary: String {
        let spaces = self.spaces.map {
            "sent=\($0.sent.count) eliciting=\($0.sent.filter(\.isAckEliciting).count) lossTime=\(String(describing: $0.lossTime)) probes=\($0.probesPending) discarded=\($0.discarded) ackDeadline=\(String(describing: $0.received.ackDeadline)) newPackets=\($0.received.hasNewPackets)"
        }
        return "inFlight=\(self.congestion.bytesInFlight) window=\(self.congestion.window) pto=\(self.probeTimeoutCount) "
            + "recovery=\(String(describing: self.recoveryDeadline)) amplification=\(self.isAmplificationLimited) "
            + "retransmits=\(self.streamRetransmits.count) order=\(self.sendOrder.count) pending=\(self.pendingStreamBytes) "
            + "sentData=\(self.sentData) peerMaxData=\(self.peerMaxData) streams=\(self.streams.count) spaces=\(spaces)"
    }

    /// The connection IDs under which the peer addresses this connection.
    var connectionIDs: [QUICConnectionID] {
        self.role == .server
            ? [self.localConnectionID, self.originalDestinationConnectionID] : [self.localConnectionID]
    }

    // MARK: - Application interface

    /// Takes the events for the application.
    mutating func takeEvents() -> Deque<QUICFrame> {
        var events = Deque<QUICFrame>()
        swap(&events, &self.events)
        return events
    }

    /// Whether a stream ID is one that this endpoint opens.
    private func isLocal(_ streamID: UInt64) -> Bool {
        (streamID & 0x01 == 0) == (self.role == .client)
    }

    private static func isBidirectional(_ streamID: UInt64) -> Bool {
        streamID & 0x02 == 0
    }

    /// Queues bytes on a stream, and opens the stream if this endpoint did not use it before.
    ///
    /// - Throws: ``QUICConnectionError`` if the connection is closed, or the stream cannot be sent on: it belongs
    ///   to the peer and is unidirectional, it was not opened by the peer, or the peer does not allow that many
    ///   streams.
    mutating func send(streamID: UInt64, data: [UInt8], fin: Bool) throws(QUICConnectionError) {
        if let error = self.error { throw error }
        guard case .open = self.lifecycle else {
            throw QUICConnectionError(kind: .localApplicationClose(code: 0), reason: "The connection is closing")
        }
        if self.streams[streamID] == nil {
            guard self.isLocal(streamID) else {
                // A stream of the peer that is gone: the response arrives after the peer reset it.
                return
            }
            let type = Self.isBidirectional(streamID) ? 0 : 1
            guard streamID >> 2 >= self.localStreamsOpened[type] else {
                throw QUICConnectionError(
                    kind: .localTransportError(code: QUICTransportErrorCode.streamStateError.rawValue),
                    reason: "Stream \(streamID) is finished"
                )
            }
            guard streamID >> 2 < self.peerMaxStreams[type] else {
                throw QUICConnectionError(
                    kind: .localTransportError(code: QUICTransportErrorCode.streamLimitError.rawValue),
                    reason: "The peer does not allow stream \(streamID) yet"
                )
            }
            // Opening a stream opens the lower streams of the same type too (RFC 9000, section 3.2).
            let base = streamID & 0x03
            for index in self.localStreamsOpened[type]...(streamID >> 2) {
                let id = index << 2 | base
                self.streams[id] = self.makeLocalStream(id)
            }
            self.localStreamsOpened[type] = (streamID >> 2) + 1
        }
        guard var stream = self.streams[streamID], var buffer = stream.send, !stream.isReset else {
            return
        }
        guard !buffer.finQueued else {
            throw QUICConnectionError(
                kind: .localTransportError(code: QUICTransportErrorCode.streamStateError.rawValue),
                reason: "Stream \(streamID) is finished"
            )
        }
        let wasPending = buffer.hasPending
        buffer.append(data)
        buffer.finQueued = fin
        self.pendingStreamBytes += data.count
        stream.send = buffer
        self.streams[streamID] = stream
        if !wasPending && buffer.hasPending {
            self.sendOrder.append(streamID)
        }
    }

    /// Resets the sending direction of a stream.
    mutating func reset(streamID: UInt64, applicationErrorCode: UInt64) {
        guard var stream = self.streams[streamID], var buffer = stream.send, !stream.isReset, !stream.sendFinished
        else { return }
        self.pendingStreamBytes -= buffer.pendingBytes
        buffer.discard()
        stream.send = buffer
        stream.isReset = true
        stream.sendFinished = true
        self.streams[streamID] = stream
        self.pendingControl.append(
            .resetStream(streamID: streamID, applicationErrorCode: applicationErrorCode, finalSize: buffer.nextOffset)
        )
        self.streamRetransmits.removeAll { $0.streamID == streamID }
        self.closeIfComplete(streamID)
    }

    /// Asks the peer to stop sending on a stream, and discards what it sends.
    mutating func stopSending(streamID: UInt64, applicationErrorCode: UInt64) {
        guard var stream = self.streams[streamID], stream.receive != nil, !stream.receiveFinished else { return }
        stream.receiveFinished = true
        self.streams[streamID] = stream
        self.pendingControl.append(.stopSending(streamID: streamID, applicationErrorCode: applicationErrorCode))
        self.closeIfComplete(streamID)
    }

    /// Closes the connection with an application error code (RFC 9000, section 10.2).
    mutating func close(applicationErrorCode: UInt64, reason: String) {
        self.closeLocally(
            QUICConnectionCloseFrame(error: .application(applicationErrorCode), reasonPhrase: Array(reason.utf8)),
            error: QUICConnectionError(kind: .localApplicationClose(code: applicationErrorCode), reason: reason)
        )
    }

    private func makeLocalStream(_ streamID: UInt64) -> QUICStreamState {
        let peer = self.peerParameters ?? QUICTransportParameters()
        var stream = QUICStreamState()
        stream.send = QUICSendBuffer()
        if Self.isBidirectional(streamID) {
            // The peer's limit for streams that this endpoint opened is its bidi_remote.
            stream.sendLimit = peer.initialMaxStreamDataBidiRemote
            stream.receive = QUICReceiveBuffer()
            stream.receiveLimit = self.configuration.streamReceiveWindow
        } else {
            stream.sendLimit = peer.initialMaxStreamDataUni
        }
        return stream
    }

    private func makePeerStream(_ streamID: UInt64) -> QUICStreamState {
        let peer = self.peerParameters ?? QUICTransportParameters()
        var stream = QUICStreamState()
        stream.receive = QUICReceiveBuffer()
        stream.receiveLimit = self.configuration.streamReceiveWindow
        if Self.isBidirectional(streamID) {
            stream.send = QUICSendBuffer()
            // The peer's limit for streams that it opened is its bidi_local.
            stream.sendLimit = peer.initialMaxStreamDataBidiLocal
        }
        return stream
    }

    /// Removes a stream whose directions both ended, and gives the peer credit for a new stream.
    private mutating func closeIfComplete(_ streamID: UInt64) {
        guard let stream = self.streams[streamID], stream.isComplete else { return }
        self.streams.removeValue(forKey: streamID)
        guard !self.isLocal(streamID) else { return }
        let type = Self.isBidirectional(streamID) ? 0 : 1
        self.peerStreamsClosed[type] += 1
        let limit =
            type == 0
            ? self.configuration.maxConcurrentBidirectionalStreams
            : self.configuration.maxConcurrentUnidirectionalStreams
        if self.localMaxStreams[type] - self.peerStreamsClosed[type] <= limit / 2 {
            self.localMaxStreams[type] = self.peerStreamsClosed[type] + limit
            self.pendingControl.append(.maxStreams(bidirectional: type == 0))
        }
    }

    // MARK: - Receiving

    /// Processes a datagram of the peer.
    mutating func receive(datagram: [UInt8], from peer: SocketAddress, now: ContinuousClock.Instant) {
        guard !self.isClosed else { return }
        var bytes = datagram
        let packets = bytes.withUnsafeBytes { raw in
            QUICProtectedPacket.split(
                datagram: RawSpan(_unsafeBytes: raw),
                shortHeaderConnectionIDLength: self.configuration.connectionIDLength
            ).packets
        }
        if self.role == .server && !self.isAddressValidated {
            self.bytesReceived += datagram.count
        }

        do throws(QUICConnectionCloseFrame) {
            for packet in packets {
                try self.receive(packet: packet, in: &bytes, now: now)
                if self.isClosed { return }
            }
        } catch {
            let code: QUICConnectionError.Kind =
                switch error.error {
                case .transport(let code, _): .localTransportError(code: code.rawValue)
                case .application(let code): .localApplicationClose(code: code)
                }
            self.closeLocally(
                error,
                error: QUICConnectionError(kind: code, reason: String(decoding: error.reasonPhrase, as: UTF8.self))
            )
        }
    }

    private static func failure(
        _ code: QUICTransportErrorCode,
        frameType: UInt64 = 0,
        _ reason: String
    ) -> QUICConnectionCloseFrame {
        QUICConnectionCloseFrame(error: .transport(code, frameType: frameType), reasonPhrase: Array(reason.utf8))
    }

    private mutating func receive(
        packet: QUICProtectedPacket,
        in datagram: inout [UInt8],
        now: ContinuousClock.Instant
    ) throws(QUICConnectionCloseFrame) {
        let space: QUICPacketNumberSpace
        let packetType: QUICPacketType
        switch packet.header {
        case .long(let header):
            guard header.version == QUICVersion.version1, let headerSpace = header.type.packetNumberSpace,
                header.type != .zeroRTT
            else { return }
            space = headerSpace
            packetType = header.type
            if self.role == .client && !self.receivedFirstServerPacket {
                // The server picks the connection ID that the client uses from now on (section 7.2).
                self.receivedFirstServerPacket = true
                self.peerConnectionID = header.sourceConnectionID
            }
        case .short:
            space = .applicationData
            packetType = .oneRTT
        case .retry, .versionNegotiation, .unsupportedVersion:
            return
        }

        let index = space.rawValue
        guard !self.spaces[index].discarded, let keys = self.spaces[index].readKeys else { return }
        if space == .applicationData && !self.isHandshakeComplete && self.role == .server {
            // A server must not process 1-RTT packets before the handshake completes (RFC 9001, section 5.7).
            return
        }

        // Open the packet in place.
        let opened: (header: QUICUnprotectedHeader, payload: Range<Int>)?
        opened = datagram.withUnsafeMutableBufferPointer { buffer -> (QUICUnprotectedHeader, Range<Int>)? in
            let slice = UnsafeMutableBufferPointer(rebasing: buffer[packet.range])
            var span = MutableSpan<UInt8>(_unsafeElements: slice)
            do {
                let header = try keys.removeHeaderProtection(
                    packet: &span,
                    packetNumberOffset: packet.packetNumberOffset,
                    largestReceived: self.spaces[index].received.largest
                )
                if space == .applicationData && header.keyPhase != self.keyPhase {
                    // The peer started a key update (RFC 9001, section 6.2).
                    let next = self.nextReadKeys ?? keys.nextGeneration()
                    let payload = try next.decryptPayload(packet: &span, header: header)
                    return (header, payload)
                }
                let payload = try keys.decryptPayload(packet: &span, header: header)
                return (header, payload)
            } catch {
                return nil
            }
        }
        guard let (header, payloadRange) = opened else {
            // Packets that cannot be decrypted are dropped (section 12.2).
            return
        }
        guard header.reservedBits == 0 else {
            throw Self.failure(.protocolViolation, "Reserved bits are set")
        }
        guard self.spaces[index].received.isNew(header.packetNumber) else { return }

        if space == .applicationData && header.keyPhase != self.keyPhase {
            self.updateKeys()
        }

        // The packet is authentic.
        self.idleDeadline = now + self.idleTimeout
        self.ackElicitingSentSinceReceive = false
        if self.role == .server && packetType == .handshake && !self.isAddressValidated {
            // A Handshake packet proves that the client received the server's Initial (section 8.1).
            self.isAddressValidated = true
        }
        if self.role == .server && packetType == .handshake {
            self.discard(.initial)
        }

        let start = packet.range.lowerBound
        let payload = Array(datagram[(start + payloadRange.lowerBound)..<(start + payloadRange.upperBound)])
        var isAckEliciting = false
        let raw = payload.span.bytes
        var input = ParserSpan(raw)
        guard !input.isEmpty else {
            throw Self.failure(.protocolViolation, "A packet without frames")
        }
        while !input.isEmpty {
            let frame: QUICFrame
            do {
                frame = try QUICFrame(parsing: &input)
            } catch {
                throw Self.failure(.frameEncodingError, "Invalid frame: \(error)")
            }
            guard frame.isAllowed(in: packetType) else {
                throw Self.failure(.protocolViolation, frameType: frame.frameType, "Frame not allowed in \(packetType)")
            }
            if frame.isAckEliciting {
                isAckEliciting = true
            }
            try self.handle(frame, in: space, now: now)
            if self.isClosed { return }
        }

        let maxAckDelay: Duration? = space == .applicationData ? self.configuration.maxAckDelay : nil
        self.spaces[index].received.insert(
            header.packetNumber,
            isAckEliciting: isAckEliciting,
            now: now,
            maxAckDelay: maxAckDelay
        )
    }

    private var idleTimeout: Duration {
        let peer = self.peerParameters?.maxIdleTimeout ?? 0
        guard peer > 0 else { return self.configuration.idleTimeout }
        return min(self.configuration.idleTimeout, .milliseconds(Int64(peer)))
    }

    /// Switches to the next generation of 1-RTT keys, in both directions.
    private mutating func updateKeys() {
        let index = QUICPacketNumberSpace.applicationData.rawValue
        guard let read = self.spaces[index].readKeys, let write = self.spaces[index].writeKeys else { return }
        self.spaces[index].readKeys = self.nextReadKeys ?? read.nextGeneration()
        self.spaces[index].writeKeys = write.nextGeneration()
        self.nextReadKeys = self.spaces[index].readKeys!.nextGeneration()
        self.keyPhase.toggle()
    }

    private mutating func handle(
        _ frame: QUICFrame,
        in space: QUICPacketNumberSpace,
        now: ContinuousClock.Instant
    ) throws(QUICConnectionCloseFrame) {
        switch frame {
        case .padding, .ping:
            break

        case .ack(let ack):
            try self.handleAck(ack, in: space, now: now)

        case .crypto(let offset, let data):
            try self.handleCrypto(offset: offset, data: data, in: space)

        case .stream(let stream):
            try self.handleStream(stream)

        case .resetStream(let streamID, let code, let finalSize):
            try self.checkPeerCanSend(on: streamID, frameType: frame.frameType)
            try self.openPeerStreams(upTo: streamID, frameType: frame.frameType)
            guard var stream = self.streams[streamID], var receive = stream.receive else { return }
            let before = receive.highestOffset
            do {
                try receive.reset(finalSize: finalSize)
            } catch {
                throw Self.failure(.finalSizeError, frameType: frame.frameType, "Final size changed")
            }
            guard finalSize <= stream.receiveLimit else {
                throw Self.failure(.flowControlError, frameType: frame.frameType, "Final size above the limit")
            }
            try self.countReceived(receive.highestOffset - before, frameType: frame.frameType)
            // The bytes that will never arrive count as consumed for the connection window.
            self.deliveredData += receive.highestOffset - receive.deliveredOffset
            stream.receive = receive
            if !stream.receiveFinished {
                stream.receiveFinished = true
                self.events.append(frame)
            }
            self.streams[streamID] = stream
            self.closeIfComplete(streamID)

        case .stopSending(let streamID, _):
            guard Self.isBidirectional(streamID) || self.isLocal(streamID) else {
                throw Self.failure(.streamStateError, frameType: frame.frameType, "STOP_SENDING on a receive stream")
            }
            if self.isLocal(streamID) && self.streams[streamID] == nil {
                if streamID >> 2 >= self.peerMaxStreams[Self.isBidirectional(streamID) ? 0 : 1] {
                    throw Self.failure(.streamStateError, frameType: frame.frameType, "STOP_SENDING on an idle stream")
                }
                return
            }
            try self.openPeerStreams(upTo: streamID, frameType: frame.frameType)
            if self.streams[streamID] != nil {
                self.events.append(frame)
            }

        case .newToken:
            throw Self.failure(.protocolViolation, frameType: frame.frameType, "A client must not send NEW_TOKEN")

        case .maxData(let maximum):
            self.peerMaxData = max(self.peerMaxData, maximum)

        case .maxStreamData(let streamID, let maximum):
            if !self.isLocal(streamID) && !Self.isBidirectional(streamID) {
                throw Self.failure(.streamStateError, frameType: frame.frameType, "MAX_STREAM_DATA on a receive stream")
            }
            try self.openPeerStreams(upTo: streamID, frameType: frame.frameType)
            if var stream = self.streams[streamID], stream.send != nil {
                stream.sendLimit = max(stream.sendLimit, maximum)
                self.streams[streamID] = stream
                if stream.send!.hasPending && !self.sendOrder.contains(streamID) {
                    self.sendOrder.append(streamID)
                }
            }

        case .maxStreams(let bidirectional, let maximum):
            guard maximum <= 1 << 60 else {
                throw Self.failure(.frameEncodingError, frameType: frame.frameType, "Stream limit above 2^60")
            }
            let type = bidirectional ? 0 : 1
            self.peerMaxStreams[type] = max(self.peerMaxStreams[type], maximum)

        case .dataBlocked, .streamDataBlocked, .streamsBlocked:
            break

        case .newConnectionID(let newID):
            guard self.peerConnectionID.length > 0 else {
                throw Self.failure(.protocolViolation, frameType: frame.frameType, "NEW_CONNECTION_ID with empty IDs")
            }
            // The connection does not migrate, so it keeps using the current connection ID.
            _ = newID

        case .retireConnectionID:
            break

        case .pathChallenge(let data):
            self.pendingPathResponses.append(data)

        case .pathResponse:
            break

        case .connectionClose(let close):
            let kind: QUICConnectionError.Kind =
                switch close.error {
                case .transport(let code, _): .peerTransportError(code: code.rawValue)
                case .application(let code): .peerApplicationClose(code: code)
                }
            // Draining: nothing more is sent (section 10.2.2).
            self.error = QUICConnectionError(kind: kind, reason: String(decoding: close.reasonPhrase, as: UTF8.self))
            self.lifecycle = .closed

        case .handshakeDone:
            guard self.role == .client else {
                throw Self.failure(.protocolViolation, frameType: frame.frameType, "A client must not send HANDSHAKE_DONE")
            }
            self.confirmHandshake()
        }
    }

    // MARK: Crypto

    private mutating func handleCrypto(
        offset: UInt64,
        data: [UInt8],
        in space: QUICPacketNumberSpace
    ) throws(QUICConnectionCloseFrame) {
        let index = space.rawValue
        do {
            try self.spaces[index].cryptoReceive.insert(offset: offset, data: data, fin: false)
        } catch {
            throw Self.failure(.protocolViolation, frameType: 0x06, "Invalid CRYPTO frame")
        }
        guard self.spaces[index].cryptoReceive.bufferedBytes <= 65536 else {
            throw Self.failure(.cryptoBufferExceeded, frameType: 0x06, "Too much buffered handshake data")
        }
        let level: QUICEncryptionLevel =
            switch space {
            case .initial: .initial
            case .handshake: .handshake
            case .applicationData: .application
            }
        while let bytes = self.spaces[index].cryptoReceive.takeContiguous() {
            let result: Result<QUICHandshakeOutput, HandshakeError>
            if self.serverHandshake != nil {
                var handshake = self.serverHandshake.take()!
                do throws(HandshakeError) {
                    result = .success(try handshake.receive(bytes.span, level: level))
                } catch {
                    result = .failure(error)
                }
                self.serverHandshake = consume handshake
            } else if self.clientHandshake != nil {
                var handshake = self.clientHandshake.take()!
                do throws(HandshakeError) {
                    result = .success(try handshake.receive(bytes.span, level: level))
                } catch {
                    result = .failure(error)
                }
                self.clientHandshake = consume handshake
            } else {
                return
            }
            let output: QUICHandshakeOutput
            do throws(HandshakeError) {
                output = try result.get()
            } catch {
                throw QUICConnectionCloseFrame(
                    error: .transport(.cryptoError(alert: error.alertDescription), frameType: 0x06),
                    reasonPhrase: Array("\(error)".utf8)
                )
            }
            try self.apply(output)
        }
    }

    private mutating func apply(_ output: QUICHandshakeOutput) throws(QUICConnectionCloseFrame) {
        self.spaces[QUICPacketNumberSpace.initial.rawValue].cryptoSend.append(output.initialData)
        self.spaces[QUICPacketNumberSpace.handshake.rawValue].cryptoSend.append(output.handshakeData)
        if let alpn = output.negotiatedALPN {
            self.negotiatedALPN = alpn
        }
        if let parameters = output.peerTransportParameters {
            try self.applyPeerParameters(parameters)
        }
        if let secrets = output.handshakeSecrets {
            let suite = QUICCipherSuite(tlsCipherSuite: secrets.cipherSuite.rawValue)!
            let client = QUICPacketKeys(secret: secrets.clientSecret, cipherSuite: suite)
            let server = QUICPacketKeys(secret: secrets.serverSecret, cipherSuite: suite)
            let index = QUICPacketNumberSpace.handshake.rawValue
            self.spaces[index].readKeys = self.role == .server ? client : server
            self.spaces[index].writeKeys = self.role == .server ? server : client
        }
        if let secrets = output.applicationSecrets {
            let suite = QUICCipherSuite(tlsCipherSuite: secrets.cipherSuite.rawValue)!
            let client = QUICPacketKeys(secret: secrets.clientSecret, cipherSuite: suite)
            let server = QUICPacketKeys(secret: secrets.serverSecret, cipherSuite: suite)
            let index = QUICPacketNumberSpace.applicationData.rawValue
            self.spaces[index].readKeys = self.role == .server ? client : server
            self.spaces[index].writeKeys = self.role == .server ? server : client
            self.nextReadKeys = self.spaces[index].readKeys!.nextGeneration()
        }
        if output.isHandshakeComplete {
            self.isHandshakeComplete = true
            if self.role == .server {
                // The handshake is confirmed for a server when it completes (RFC 9001, section 4.1.2).
                self.pendingControl.append(.handshakeDone)
                self.confirmHandshake()
            }
        }
    }

    private var maxDatagramSize: Int {
        let peer = Int(clamping: self.peerParameters?.maxUDPPayloadSize ?? 1200)
        return max(1200, min(self.configuration.maxDatagramSize, peer))
    }

    private mutating func confirmHandshake() {
        guard !self.isHandshakeConfirmed else { return }
        self.isHandshakeConfirmed = true
        self.discard(.initial)
        self.discard(.handshake)
    }

    private mutating func applyPeerParameters(_ bytes: [UInt8]) throws(QUICConnectionCloseFrame) {
        let parameters: QUICTransportParameters
        do {
            parameters = try QUICTransportParameters(parsing: bytes)
        } catch {
            throw Self.failure(.transportParameterError, error.reason)
        }
        if self.role == .server {
            guard parameters.originalDestinationConnectionID == nil, parameters.statelessResetToken == nil,
                parameters.retrySourceConnectionID == nil
            else {
                throw Self.failure(.transportParameterError, "A client sent a server-only parameter")
            }
        } else {
            guard parameters.originalDestinationConnectionID == self.originalDestinationConnectionID else {
                throw Self.failure(.transportParameterError, "original_destination_connection_id does not match")
            }
        }
        guard parameters.initialSourceConnectionID == self.peerConnectionID else {
            throw Self.failure(.transportParameterError, "initial_source_connection_id does not match")
        }
        self.peerParameters = parameters
        self.peerMaxData = parameters.initialMaxData
        self.peerMaxStreams = [parameters.initialMaxStreamsBidi, parameters.initialMaxStreamsUni]
    }

    /// Drops the keys and the state of a packet number space (RFC 9001, section 4.9).
    private mutating func discard(_ space: QUICPacketNumberSpace) {
        let index = space.rawValue
        guard !self.spaces[index].discarded else { return }
        for packet in self.spaces[index].sent where packet.isInFlight {
            self.congestion.discarded(bytes: packet.size)
        }
        self.spaces[index] = QUICPacketSpace()
        self.spaces[index].discarded = true
        self.probeTimeoutCount = 0
    }

    // MARK: Streams

    /// Checks that the peer may send on a stream.
    private func checkPeerCanSend(on streamID: UInt64, frameType: UInt64) throws(QUICConnectionCloseFrame) {
        if self.isLocal(streamID) {
            guard Self.isBidirectional(streamID) else {
                throw Self.failure(.streamStateError, frameType: frameType, "Data on a send-only stream")
            }
            guard self.streams[streamID] != nil || streamID >> 2 < self.peerMaxStreams[0] else {
                throw Self.failure(.streamStateError, frameType: frameType, "Data on a stream that is not open")
            }
        }
    }

    /// Opens the streams of the peer up to the given one, which opening it opens implicitly (section 3.2).
    private mutating func openPeerStreams(upTo streamID: UInt64, frameType: UInt64) throws(QUICConnectionCloseFrame) {
        guard !self.isLocal(streamID) else { return }
        let type = Self.isBidirectional(streamID) ? 0 : 1
        let index = streamID >> 2
        guard index >= self.peerStreamsOpened[type] else { return }
        guard index < self.localMaxStreams[type] else {
            throw Self.failure(.streamLimitError, frameType: frameType, "Stream \(streamID) is above the limit")
        }
        let base = streamID & 0x03
        for next in self.peerStreamsOpened[type]...index {
            let id = next << 2 | base
            self.streams[id] = self.makePeerStream(id)
        }
        self.peerStreamsOpened[type] = index + 1
    }

    private mutating func countReceived(_ bytes: UInt64, frameType: UInt64) throws(QUICConnectionCloseFrame) {
        self.receivedData += bytes
        guard self.receivedData <= self.localMaxData else {
            throw Self.failure(.flowControlError, frameType: frameType, "The connection window is exceeded")
        }
    }

    private mutating func handleStream(_ frame: QUICStreamFrame) throws(QUICConnectionCloseFrame) {
        let frameType: UInt64 = 0x08
        try self.checkPeerCanSend(on: frame.streamID, frameType: frameType)
        try self.openPeerStreams(upTo: frame.streamID, frameType: frameType)
        // A stream that was closed already: a retransmission, which is ignored.
        guard var stream = self.streams[frame.streamID], var receive = stream.receive else { return }
        let end = frame.offset + UInt64(frame.data.count)
        guard end <= stream.receiveLimit else {
            throw Self.failure(.flowControlError, frameType: frameType, "The window of stream \(frame.streamID) is exceeded")
        }
        let before = receive.highestOffset
        do {
            try receive.insert(offset: frame.offset, data: frame.data, fin: frame.fin)
        } catch {
            throw Self.failure(.finalSizeError, frameType: frameType, "Final size of stream \(frame.streamID) changed")
        }
        try self.countReceived(receive.highestOffset - before, frameType: frameType)

        if stream.receiveFinished {
            // The application stopped reading: the bytes count as consumed, so the connection window stays open.
            self.deliveredData += receive.highestOffset - before
        } else {
            // The application consumes the bytes as they are delivered, so the windows move with the delivery.
            let deliveredBefore = receive.deliveredOffset
            while let data = receive.takeContiguous() {
                let offset = receive.deliveredOffset - UInt64(data.count)
                self.events.append(
                    .stream(QUICStreamFrame(streamID: frame.streamID, offset: offset, data: data, fin: receive.isComplete))
                )
            }
            if receive.isComplete && receive.deliveredOffset == deliveredBefore && frame.data.isEmpty {
                // A FIN without bytes.
                self.events.append(
                    .stream(QUICStreamFrame(streamID: frame.streamID, offset: receive.deliveredOffset, data: [], fin: true))
                )
            }
            let delivered = receive.deliveredOffset - deliveredBefore
            self.deliveredData += delivered
            if receive.isComplete {
                stream.receiveFinished = true
            } else if stream.receiveLimit - receive.deliveredOffset < self.configuration.streamReceiveWindow / 2 {
                stream.receiveLimit = receive.deliveredOffset + self.configuration.streamReceiveWindow
                self.pendingControl.append(.maxStreamData(streamID: frame.streamID))
            }
            if self.localMaxData - self.deliveredData < self.configuration.connectionReceiveWindow / 2 {
                self.localMaxData = self.deliveredData + self.configuration.connectionReceiveWindow
                self.pendingControl.append(.maxData)
            }
        }
        stream.receive = receive
        self.streams[frame.streamID] = stream
        self.closeIfComplete(frame.streamID)
    }

    // MARK: Acknowledgments and loss

    private mutating func handleAck(
        _ ack: QUICAckFrame,
        in space: QUICPacketNumberSpace,
        now: ContinuousClock.Instant
    ) throws(QUICConnectionCloseFrame) {
        let index = space.rawValue
        guard ack.largestAcknowledged < self.spaces[index].nextPacketNumber else {
            throw Self.failure(.protocolViolation, frameType: 0x02, "ACK of a packet that was not sent")
        }
        let ranges = ack.acknowledgedRanges
        var newlyAcknowledged: [QUICSentPacket] = []
        self.spaces[index].sent.removeAll { packet in
            for range in ranges where range.contains(packet.packetNumber) {
                newlyAcknowledged.append(packet)
                return true
            }
            return false
        }
        guard !newlyAcknowledged.isEmpty else { return }

        let largest = self.spaces[index].largestAcknowledged.map { max($0, ack.largestAcknowledged) }
            ?? ack.largestAcknowledged
        self.spaces[index].largestAcknowledged = largest

        if let newest = newlyAcknowledged.last(where: { $0.packetNumber == ack.largestAcknowledged }),
            newlyAcknowledged.contains(where: { $0.isAckEliciting })
        {
            var ackDelay = Duration.zero
            if space == .applicationData {
                let exponent = self.peerParameters?.ackDelayExponent ?? 3
                ackDelay = .microseconds(Int64(clamping: ack.ackDelay << exponent))
                if self.isHandshakeConfirmed {
                    ackDelay = min(ackDelay, .milliseconds(Int64(self.peerParameters?.maxAckDelay ?? 25)))
                }
            }
            self.rtt.update(sample: now - newest.sentAt, ackDelay: ackDelay)
        }

        for packet in newlyAcknowledged {
            if packet.isInFlight {
                self.congestion.acknowledged(bytes: packet.size, sentAt: packet.sentAt)
            }
            if let largestAcknowledged = packet.largestAcknowledged {
                self.spaces[index].received.forget(upTo: largestAcknowledged)
            }
        }
        self.detectLostPackets(in: space, now: now)
        self.probeTimeoutCount = 0
    }

    /// Declares packets lost that were sent long enough before an acknowledged one (RFC 9002, section 6.1).
    private mutating func detectLostPackets(in space: QUICPacketNumberSpace, now: ContinuousClock.Instant) {
        let index = space.rawValue
        guard let largest = self.spaces[index].largestAcknowledged else { return }
        let lossDelay = self.rtt.lossDelay
        var lossTime: ContinuousClock.Instant? = nil
        var lost: [QUICSentPacket] = []
        self.spaces[index].sent.removeAll { packet in
            guard packet.packetNumber < largest else { return false }
            if largest - packet.packetNumber >= 3 || packet.sentAt + lossDelay <= now {
                lost.append(packet)
                return true
            }
            let time = packet.sentAt + lossDelay
            lossTime = lossTime.map { min($0, time) } ?? time
            return false
        }
        self.spaces[index].lossTime = lossTime
        for packet in lost {
            if packet.isInFlight {
                self.congestion.lost(bytes: packet.size, sentAt: packet.sentAt, now: now)
            }
            self.requeue(packet.frames, in: space)
        }
    }

    /// Queues the frames of a lost packet again.
    private mutating func requeue(_ frames: [QUICRetransmittableFrame], in space: QUICPacketNumberSpace) {
        for frame in frames {
            switch frame {
            case .crypto(let offset, let data):
                self.spaces[space.rawValue].cryptoRetransmits.append((offset, data))
            case .stream(let stream):
                if let state = self.streams[stream.streamID], state.isReset {
                    continue
                }
                self.streamRetransmits.append(stream)
            case .maxData, .maxStreamData, .maxStreams, .resetStream, .stopSending, .handshakeDone:
                self.pendingControl.append(frame)
            }
        }
    }

    /// The deadline of loss detection or of the probe timeout (RFC 9002, section 6.2 and appendix A.8).
    private var recoveryDeadline: ContinuousClock.Instant? {
        var earliestLoss: ContinuousClock.Instant? = nil
        for space in self.spaces where !space.discarded {
            if let time = space.lossTime {
                earliestLoss = earliestLoss.map { min($0, time) } ?? time
            }
        }
        if let earliestLoss {
            return earliestLoss
        }
        if self.isAmplificationLimited {
            return nil
        }
        return self.probeTimeout?.deadline
    }

    private var probeTimeout: (deadline: ContinuousClock.Instant, space: QUICPacketNumberSpace)? {
        var result: (ContinuousClock.Instant, QUICPacketNumberSpace)? = nil
        let backoff = 1 << min(self.probeTimeoutCount, 16)
        for space in QUICPacketNumberSpace.allCases {
            let state = self.spaces[space.rawValue]
            guard !state.discarded, let sentAt = state.lastAckElicitingSentAt, state.hasAckElicitingInFlight else {
                continue
            }
            var duration = self.rtt.probeTimeout
            if space == .applicationData {
                guard self.isHandshakeConfirmed else { continue }
                duration += .milliseconds(Int64(self.peerParameters?.maxAckDelay ?? 25))
            }
            let deadline = sentAt + duration * backoff
            if result == nil || deadline < result!.0 {
                result = (deadline, space)
            }
        }
        if result == nil && self.role == .client && !self.isHandshakeConfirmed {
            // A client arms the probe timeout until the handshake is confirmed, so that it can unblock a server
            // that hit the amplification limit.
            let space: QUICPacketNumberSpace = self.spaces[QUICPacketNumberSpace.handshake.rawValue].writeKeys != nil
                ? .handshake : .initial
            if let sentAt = self.spaces[space.rawValue].lastAckElicitingSentAt {
                result = (sentAt + self.rtt.probeTimeout * backoff, space)
            }
        }
        return result
    }

    private var isAmplificationLimited: Bool {
        self.role == .server && !self.isAddressValidated && self.bytesSent >= 3 * self.bytesReceived
    }

    /// Handles the deadlines that passed.
    mutating func handleTimeout(now: ContinuousClock.Instant) {
        guard !self.isClosed else { return }
        if now >= self.idleDeadline {
            self.error = QUICConnectionError(kind: .idleTimeout, reason: "No activity for \(self.idleTimeout)")
            self.lifecycle = .closed
            return
        }
        // Loss detection first, then the probe timeout (RFC 9002, appendix A.9).
        var lossSpace: QUICPacketNumberSpace? = nil
        for space in QUICPacketNumberSpace.allCases {
            if let time = self.spaces[space.rawValue].lossTime, time <= now {
                lossSpace = space
                break
            }
        }
        if let lossSpace {
            self.detectLostPackets(in: lossSpace, now: now)
            return
        }
        guard !self.isAmplificationLimited, let probe = self.probeTimeout, probe.deadline <= now else { return }
        self.probeTimeoutCount += 1
        let index = probe.space.rawValue
        self.spaces[index].probesPending = 2
        // Sends the oldest unacknowledged data again, which is what the peer is most likely missing.
        for packet in self.spaces[index].sent.prefix(2) where packet.isAckEliciting {
            self.requeue(packet.frames, in: probe.space)
        }
    }

    // MARK: - Sending

    private mutating func closeLocally(_ frame: QUICConnectionCloseFrame, error: QUICConnectionError) {
        guard case .open = self.lifecycle else { return }
        self.error = error
        self.lifecycle = .closing(frame)
    }

    /// Builds the datagrams that are ready to be sent and appends them to `datagrams`.
    mutating func makeDatagrams(now: ContinuousClock.Instant, into datagrams: inout [QUICOutboundDatagram]) {
        switch self.lifecycle {
        case .closed:
            return
        case .closing(let close):
            if let datagram = self.makeCloseDatagram(close) {
                datagrams.append(QUICOutboundDatagram(bytes: datagram, peer: self.peerAddress))
            }
            self.lifecycle = .closed
            return
        case .open:
            break
        }

        while true {
            let limit = self.isHandshakeComplete ? self.maxDatagramSize : 1200
            var budget = limit
            if self.role == .server && !self.isAddressValidated {
                budget = min(budget, 3 * self.bytesReceived - self.bytesSent)
                if budget < 64 { return }
            }
            var drafts: [QUICPacketDraft] = []
            var used = 0
            var containsAckElicitingInitial = false
            for space in QUICPacketNumberSpace.allCases {
                let index = space.rawValue
                guard !self.spaces[index].discarded, self.spaces[index].writeKeys != nil else { continue }
                let overhead = self.headerLength(space) + QUICPacketKeys.tagLength
                guard budget - used > overhead + 8 else { break }
                guard var draft = self.makeDraft(space, now: now, payloadBudget: budget - used - overhead) else {
                    continue
                }
                if space == .initial && draft.record.isAckEliciting {
                    containsAckElicitingInitial = true
                }
                // The sample of header protection needs 4 bytes of packet number and payload.
                while draft.packetNumberLength + draft.payload.count < 4 {
                    draft.payload.append(0)
                }
                used += self.headerLength(space, packetNumberLength: draft.packetNumberLength)
                    + draft.payload.count + QUICPacketKeys.tagLength
                drafts.append(draft)
                if space == .applicationData { break }
            }
            guard !drafts.isEmpty else { return }

            if (containsAckElicitingInitial || (self.role == .client && drafts.first?.space == .initial))
                && used < 1200
            {
                // Datagrams with ack-eliciting Initial packets are padded to 1200 bytes (section 14.1).
                drafts[drafts.count - 1].payload.append(contentsOf: repeatElement(0, count: 1200 - used))
                drafts[drafts.count - 1].record.isInFlight = true
                used = 1200
            }

            var datagram: [UInt8] = []
            datagram.reserveCapacity(used)
            for draft in drafts {
                self.seal(draft, into: &datagram, now: now)
            }
            if self.role == .server && !self.isAddressValidated {
                self.bytesSent += datagram.count
            }
            datagrams.append(QUICOutboundDatagram(bytes: datagram, peer: self.peerAddress))
        }
    }

    private func headerLength(_ space: QUICPacketNumberSpace, packetNumberLength: Int = 4) -> Int {
        switch space {
        case .initial:
            // An Initial of a server carries no token; one of a client neither (no Retry).
            QUICLongHeader(
                type: .initial,
                version: QUICVersion.version1,
                destinationConnectionID: self.peerConnectionID,
                sourceConnectionID: self.localConnectionID,
                token: []
            ).encodedLength(packetNumberLength: packetNumberLength)
        case .handshake:
            QUICLongHeader(
                type: .handshake,
                version: QUICVersion.version1,
                destinationConnectionID: self.peerConnectionID,
                sourceConnectionID: self.localConnectionID,
                token: []
            ).encodedLength(packetNumberLength: packetNumberLength)
        case .applicationData:
            1 + self.peerConnectionID.length + packetNumberLength
        }
    }

    /// Collects the frames of the next packet of a space, or returns `nil` if the space has nothing to send.
    private mutating func makeDraft(
        _ space: QUICPacketNumberSpace,
        now: ContinuousClock.Instant,
        payloadBudget: Int
    ) -> QUICPacketDraft? {
        let index = space.rawValue
        var frames: [QUICFrame] = []
        var record = QUICSentPacket(
            packetNumber: self.spaces[index].nextPacketNumber,
            sentAt: now,
            size: 0,
            isAckEliciting: false,
            isInFlight: false,
            frames: [],
            largestAcknowledged: nil
        )
        var remaining = payloadBudget

        func add(_ frame: QUICFrame, retransmit: QUICRetransmittableFrame?) {
            frames.append(frame)
            remaining -= frame.encodedLength()
            if frame.isAckEliciting {
                record.isAckEliciting = true
                record.isInFlight = true
            }
            if let retransmit {
                record.frames.append(retransmit)
            }
        }

        // Probes and data may exceed the congestion window only for probes.
        let isProbe = self.spaces[index].probesPending > 0
        var congestionAvailable = isProbe ? Int.max : self.congestion.available

        // ACK: when it is due, or with anything else that goes out anyway.
        let received = self.spaces[index].received
        let ackDue =
            received.hasNewPackets
            && (received.ackDeadline.map { $0 <= now } ?? false || received.unacknowledgedAckEliciting >= 2)

        // Control frames of the application space.
        var control: [(QUICFrame, QUICRetransmittableFrame?)] = []
        if space == .applicationData {
            while let data = self.pendingPathResponses.first {
                control.append((.pathResponse(data), nil))
                self.pendingPathResponses.removeFirst()
            }
            while let frame = self.pendingControl.first {
                guard let wire = self.wireFrame(for: frame) else {
                    self.pendingControl.removeFirst()
                    continue
                }
                guard wire.encodedLength() <= remaining - control.reduce(0, { $0 + $1.0.encodedLength() }) - 64 else {
                    break
                }
                control.append((wire, frame))
                self.pendingControl.removeFirst()
            }
        }

        let hasCrypto =
            !self.spaces[index].cryptoRetransmits.isEmpty || self.spaces[index].cryptoSend.hasPending
        let hasStreams = space == .applicationData && (!self.streamRetransmits.isEmpty || !self.sendOrder.isEmpty)
        guard ackDue || !control.isEmpty || hasCrypto || hasStreams || isProbe else { return nil }

        if received.hasNewPackets,
            let ack = self.spaces[index].received.makeAckFrame(
                now: now,
                ackDelayExponent: space == .applicationData ? self.localParameters.ackDelayExponent : 3
            )
        {
            add(.ack(ack), retransmit: nil)
            record.largestAcknowledged = ack.largestAcknowledged
        }
        for (frame, retransmit) in control {
            add(frame, retransmit: retransmit)
        }

        // CRYPTO: retransmissions first.
        while remaining > 24, let (offset, data) = self.spaces[index].cryptoRetransmits.first {
            let room = remaining - 1 - QUICVariableLengthInteger.encodedLength(offset) - 4
            if data.count <= room {
                self.spaces[index].cryptoRetransmits.removeFirst()
                add(.crypto(offset: offset, data: data), retransmit: .crypto(offset: offset, data: data))
            } else {
                let head = Array(data[0..<room])
                self.spaces[index].cryptoRetransmits[0] = (offset + UInt64(room), Array(data[room...]))
                add(.crypto(offset: offset, data: head), retransmit: .crypto(offset: offset, data: head))
            }
        }
        while remaining > 24 && self.spaces[index].cryptoSend.hasPending {
            let offset = self.spaces[index].cryptoSend.nextOffset
            let room = remaining - 1 - QUICVariableLengthInteger.encodedLength(offset) - 4
            let (start, data, _) = self.spaces[index].cryptoSend.take(maximum: room)
            add(.crypto(offset: start, data: data), retransmit: .crypto(offset: start, data: data))
        }

        // STREAM: retransmissions first, then new data, round robin over the streams.
        if space == .applicationData {
            while remaining > 32 && congestionAvailable > remaining, let frame = self.streamRetransmits.first {
                let overhead = 1 + 8 + 8 + 4
                if frame.data.count + overhead <= remaining {
                    self.streamRetransmits.removeFirst()
                    add(.stream(frame), retransmit: .stream(frame))
                } else {
                    let room = remaining - overhead
                    let head = QUICStreamFrame(
                        streamID: frame.streamID,
                        offset: frame.offset,
                        data: Array(frame.data[0..<room]),
                        fin: false
                    )
                    self.streamRetransmits[0] = QUICStreamFrame(
                        streamID: frame.streamID,
                        offset: frame.offset + UInt64(room),
                        data: Array(frame.data[room...]),
                        fin: frame.fin
                    )
                    add(.stream(head), retransmit: .stream(head))
                }
            }
            var visited = 0
            let candidates = self.sendOrder.count
            while remaining > 32 && congestionAvailable > remaining && visited < candidates,
                let streamID = self.sendOrder.first
            {
                visited += 1
                self.sendOrder.removeFirst()
                guard var stream = self.streams[streamID], var buffer = stream.send, buffer.hasPending else {
                    continue
                }
                let overhead =
                    1 + QUICVariableLengthInteger.encodedLength(streamID)
                    + QUICVariableLengthInteger.encodedLength(buffer.nextOffset) + 4
                let streamCredit = Int(clamping: stream.sendLimit - buffer.nextOffset)
                let connectionCredit = Int(clamping: self.peerMaxData - self.sentData)
                let maximum = min(remaining - overhead, streamCredit, connectionCredit)
                if maximum <= 0 && buffer.pendingBytes > 0 {
                    // Blocked by flow control; MAX_STREAM_DATA or MAX_DATA puts it back into the order.
                    continue
                }
                let (offset, data, fin) = buffer.take(maximum: max(0, maximum))
                self.sentData += UInt64(data.count)
                self.pendingStreamBytes -= data.count
                if fin {
                    stream.sendFinished = true
                }
                stream.send = buffer
                self.streams[streamID] = stream
                let frame = QUICStreamFrame(streamID: streamID, offset: offset, data: data, fin: fin)
                add(.stream(frame), retransmit: .stream(frame))
                congestionAvailable -= data.count
                if buffer.hasPending {
                    self.sendOrder.append(streamID)
                }
                if fin {
                    self.closeIfComplete(streamID)
                }
            }
        }

        if isProbe && !record.isAckEliciting {
            add(.ping, retransmit: nil)
        }
        if isProbe {
            self.spaces[index].probesPending -= 1
        }
        if frames.isEmpty || (!record.isAckEliciting && !ackDue && control.isEmpty) {
            // An ACK alone that is not due yet waits for the next packet.
            self.spaces[index].received = received
            return nil
        }

        var payload = [UInt8](repeating: 0, count: payloadBudget - remaining)
        let written = payload.withUnsafeMutableBufferPointer { buffer in
            var output = OutputSpan<UInt8>(buffer: buffer, initializedCount: 0)
            for frame in frames {
                frame.encode(into: &output)
            }
            return output.finalize(for: buffer)
        }
        payload.removeLast(payload.count - written)

        let packetNumber = self.spaces[index].nextPacketNumber
        self.spaces[index].nextPacketNumber += 1
        let packetNumberLength = QUICPacketNumber.encodedLength(
            of: packetNumber,
            largestAcknowledged: self.spaces[index].largestAcknowledged
        )
        return QUICPacketDraft(
            space: space,
            packetNumber: packetNumber,
            packetNumberLength: packetNumberLength,
            payload: payload,
            record: record
        )
    }

    /// The frame to send for a queued control frame, with the current values, or `nil` if it is obsolete.
    private func wireFrame(for frame: QUICRetransmittableFrame) -> QUICFrame? {
        switch frame {
        case .maxData:
            return .maxData(self.localMaxData)
        case .maxStreamData(let streamID):
            guard let stream = self.streams[streamID], stream.receive != nil, !stream.receiveFinished else {
                return nil
            }
            return .maxStreamData(streamID: streamID, maximum: stream.receiveLimit)
        case .maxStreams(let bidirectional):
            return .maxStreams(bidirectional: bidirectional, maximum: self.localMaxStreams[bidirectional ? 0 : 1])
        case .resetStream(let streamID, let code, let finalSize):
            return .resetStream(streamID: streamID, applicationErrorCode: code, finalSize: finalSize)
        case .stopSending(let streamID, let code):
            return .stopSending(streamID: streamID, applicationErrorCode: code)
        case .handshakeDone:
            return .handshakeDone
        case .crypto, .stream:
            return nil
        }
    }

    /// Writes the header, encrypts the packet and records it as sent.
    private mutating func seal(_ draft: QUICPacketDraft, into datagram: inout [UInt8], now: ContinuousClock.Instant) {
        let index = draft.space.rawValue
        let keys = self.spaces[index].writeKeys!
        let headerLength = self.headerLength(draft.space, packetNumberLength: draft.packetNumberLength)
        let packetLength = headerLength + draft.payload.count + QUICPacketKeys.tagLength
        let start = datagram.count
        datagram.append(contentsOf: repeatElement(0, count: packetLength))
        datagram.withUnsafeMutableBufferPointer { buffer in
            let packet = UnsafeMutableBufferPointer(rebasing: buffer[start..<(start + packetLength)])
            var output = OutputSpan<UInt8>(buffer: packet, initializedCount: 0)
            switch draft.space {
            case .initial, .handshake:
                QUICLongHeader(
                    type: draft.space == .initial ? .initial : .handshake,
                    version: QUICVersion.version1,
                    destinationConnectionID: self.peerConnectionID,
                    sourceConnectionID: self.localConnectionID,
                    token: []
                ).encode(
                    into: &output,
                    packetNumber: draft.packetNumber,
                    packetNumberLength: draft.packetNumberLength,
                    length: draft.packetNumberLength + draft.payload.count + QUICPacketKeys.tagLength
                )
            case .applicationData:
                QUICShortHeader(
                    destinationConnectionID: self.peerConnectionID,
                    spinBit: false,
                    keyPhase: self.keyPhase
                ).encode(into: &output, packetNumber: draft.packetNumber, packetNumberLength: draft.packetNumberLength)
            }
            output.appendQUICBytes(draft.payload)
            for _ in 0..<QUICPacketKeys.tagLength {
                output.append(0)
            }
            _ = output.finalize(for: packet)
            var span = MutableSpan<UInt8>(_unsafeElements: packet)
            // Cannot fail: the payload has at least 4 bytes with the packet number.
            try! keys.seal(
                packet: &span,
                packetNumberOffset: headerLength - draft.packetNumberLength,
                packetNumberLength: draft.packetNumberLength,
                packetNumber: draft.packetNumber
            )
        }

        var record = draft.record
        record.size = packetLength
        if record.isAckEliciting || record.isInFlight {
            self.congestion.sent(bytes: packetLength)
            record.isInFlight = true
        }
        if record.isAckEliciting {
            self.spaces[index].lastAckElicitingSentAt = now
            if !self.ackElicitingSentSinceReceive {
                // Sending the first ack-eliciting packet after receiving restarts the idle timer (section 10.1).
                self.ackElicitingSentSinceReceive = true
                self.idleDeadline = now + self.idleTimeout
            }
        }
        if record.isInFlight || record.largestAcknowledged != nil {
            self.spaces[index].sent.append(record)
        }
        if self.role == .client && draft.space == .handshake {
            // A client discards its Initial keys when it first sends a Handshake packet (RFC 9001, section 4.9.1).
            self.discard(.initial)
        }
    }

    /// A datagram with CONNECTION_CLOSE in every space that the peer may be able to read.
    private mutating func makeCloseDatagram(_ close: QUICConnectionCloseFrame) -> [UInt8]? {
        var datagram: [UInt8] = []
        let now = ContinuousClock.now
        for space in QUICPacketNumberSpace.allCases {
            let index = space.rawValue
            guard !self.spaces[index].discarded, self.spaces[index].writeKeys != nil else { continue }
            if space == .applicationData && !self.isHandshakeComplete { continue }
            var frame = close
            if space != .applicationData, case .application = close.error {
                // An application close before the handshake is complete goes out as APPLICATION_ERROR (10.2.3).
                frame = QUICConnectionCloseFrame(error: .transport(.applicationError, frameType: 0), reasonPhrase: [])
            }
            var payload = [UInt8](repeating: 0, count: QUICFrame.connectionClose(frame).encodedLength())
            payload.withUnsafeMutableBufferPointer { buffer in
                var output = OutputSpan<UInt8>(buffer: buffer, initializedCount: 0)
                QUICFrame.connectionClose(frame).encode(into: &output)
                _ = output.finalize(for: buffer)
            }
            while payload.count < 4 { payload.append(0) }
            let packetNumber = self.spaces[index].nextPacketNumber
            self.spaces[index].nextPacketNumber += 1
            let draft = QUICPacketDraft(
                space: space,
                packetNumber: packetNumber,
                packetNumberLength: 4,
                payload: payload,
                record: QUICSentPacket(
                    packetNumber: packetNumber,
                    sentAt: now,
                    size: 0,
                    isAckEliciting: false,
                    isInFlight: false,
                    frames: [],
                    largestAcknowledged: nil
                )
            )
            self.seal(draft, into: &datagram, now: now)
        }
        return datagram.isEmpty ? nil : datagram
    }
}

// The state owns its values uniquely, and the handshake state machines of swift-tls only lack the annotation.
@available(anyAppleOS 27.0, *)
extension QUICConnectionState: @unchecked Sendable {}
