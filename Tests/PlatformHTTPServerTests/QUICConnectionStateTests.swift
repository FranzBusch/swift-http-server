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

import DequeModule
import PlatformExecutors
import SwiftTLSStateMachine
import Testing

@testable import PlatformHTTPServer

/// The two sides of a connection.
@available(anyAppleOS 27.0, *)
private struct QUICTestPair: ~Copyable {
    var client: QUICConnectionState
    var server: QUICConnectionState
}

/// Runs a client and a server ``QUICConnectionState`` against each other over a simulated network.
@available(anyAppleOS 27.0, *)
private struct QUICTestNetwork {
    static let clientAddress = SocketAddress.v4(.init(address: .loopback, port: 50000))
    static let serverAddress = SocketAddress.v4(.init(address: .loopback, port: 443))

    var now = ContinuousClock.now
    /// The datagrams in flight, with the time at which they arrive.
    var toServer = Deque<(at: ContinuousClock.Instant, bytes: [UInt8])>()
    var toClient = Deque<(at: ContinuousClock.Instant, bytes: [UInt8])>()
    var oneWayDelay: Duration = .milliseconds(5)
    var sentDatagrams = 0
    /// Decides for every datagram, by its number, whether the network drops it.
    var drop: (Int) -> Bool = { _ in false }
    var serverEvents: [QUICFrame] = []
    var clientEvents: [QUICFrame] = []

    mutating func transmit(_ datagrams: [QUICOutboundDatagram], toServer: Bool) {
        for datagram in datagrams {
            self.sentDatagrams += 1
            if self.drop(self.sentDatagrams) { continue }
            if toServer {
                self.toServer.append((self.now + self.oneWayDelay, datagram.bytes))
            } else {
                self.toClient.append((self.now + self.oneWayDelay, datagram.bytes))
            }
        }
    }

    /// Starts a connection and returns both sides.
    mutating func connect(
        configuration: QUICConnectionConfiguration = .init()
    ) throws -> QUICTestPair {
        var client = try QUICConnectionState(
            clientTo: Self.serverAddress,
            configuration: configuration,
            tlsConfiguration: ClientHandshakeConfiguration(serverName: "localhost", alpnProtocols: ["h3"]),
            now: self.now
        )
        var datagrams: [QUICOutboundDatagram] = []
        while true {
            client.makeDatagrams(now: self.now, into: &datagrams)
            if let first = datagrams.first {
                let packets = first.bytes.withUnsafeBytes {
                    QUICProtectedPacket.split(datagram: RawSpan(_unsafeBytes: $0), shortHeaderConnectionIDLength: 8)
                }
                guard case .long(let header) = packets.packets.first?.header else {
                    throw QUICConnectionError(kind: .handshakeFailed, reason: "No Initial")
                }
                let server = QUICConnectionState(
                    serverWithInitial: header,
                    peer: Self.clientAddress,
                    configuration: configuration,
                    tlsConfiguration: try makeServerTLSConfiguration(alpnProtocols: ["h3"]).makeHandshakeConfiguration(),
                    now: self.now
                )
                self.transmit(datagrams, toServer: true)
                return QUICTestPair(client: client, server: server)
            }
            throw QUICConnectionError(kind: .handshakeFailed, reason: "The client sent nothing")
        }
    }

    /// Advances the simulation until `done` holds or the time limit passes.
    mutating func run(
        _ pair: inout QUICTestPair,
        for limit: Duration = .seconds(20),
        until done: (borrowing QUICTestPair, _ serverEvents: [QUICFrame], _ clientEvents: [QUICFrame]) -> Bool
    ) -> Bool {
        let end = self.now + limit
        while self.now < end {
            if done(pair, self.serverEvents, self.clientEvents) { return true }
            while let first = self.toServer.first, first.at <= self.now {
                self.toServer.removeFirst()
                pair.server.receive(datagram: first.bytes, from: Self.clientAddress, now: self.now)
            }
            while let first = self.toClient.first, first.at <= self.now {
                self.toClient.removeFirst()
                pair.client.receive(datagram: first.bytes, from: Self.serverAddress, now: self.now)
            }
            if let deadline = pair.server.nextDeadline, deadline <= self.now {
                pair.server.handleTimeout(now: self.now)
            }
            if let deadline = pair.client.nextDeadline, deadline <= self.now {
                pair.client.handleTimeout(now: self.now)
            }
            self.serverEvents.append(contentsOf: pair.server.takeEvents())
            self.clientEvents.append(contentsOf: pair.client.takeEvents())
            var datagrams: [QUICOutboundDatagram] = []
            pair.server.makeDatagrams(now: self.now, into: &datagrams)
            self.transmit(datagrams, toClient: true)
            datagrams.removeAll()
            pair.client.makeDatagrams(now: self.now, into: &datagrams)
            self.transmit(datagrams, toServer: true)
            if pair.server.isClosed && pair.client.isClosed { return done(pair, self.serverEvents, self.clientEvents) }
            self.now += .milliseconds(1)
        }
        return done(pair, self.serverEvents, self.clientEvents)
    }

    mutating func transmit(_ datagrams: [QUICOutboundDatagram], toClient: Bool) {
        self.transmit(datagrams, toServer: !toClient)
    }

    /// The bytes of a stream in the events, and whether they ended with a FIN.
    static func streamBytes(_ events: [QUICFrame], streamID: UInt64) -> (bytes: [UInt8], fin: Bool) {
        var bytes: [UInt8] = []
        var fin = false
        for event in events {
            if case .stream(let frame) = event, frame.streamID == streamID {
                #expect(frame.offset == UInt64(bytes.count), "Stream bytes arrive in order")
                bytes.append(contentsOf: frame.data)
                fin = fin || frame.fin
            }
        }
        return (bytes, fin)
    }
}

/// A reproducible random number generator (SplitMix64).
private struct QUICTestRandom: RandomNumberGenerator {
    var state: UInt64

    init(seed: UInt64) {
        self.state = seed
    }

    mutating func next() -> UInt64 {
        self.state &+= 0x9e37_79b9_7f4a_7c15
        var z = self.state
        z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
        z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
        return z ^ (z >> 31)
    }
}

@Suite
struct QUICConnectionStateTests {
    @available(anyAppleOS 27.0, *)
    @Test func handshakeCompletesAndAStreamCarriesARequestAndAResponse() throws {
        var network = QUICTestNetwork()
        var pair = try network.connect()
        let connected = network.run(&pair) { pair, _, _ in
            pair.client.isHandshakeConfirmed && pair.server.isHandshakeConfirmed
        }
        #expect(connected)
        let value1 = pair.server.negotiatedALPN
        #expect(value1 == "h3")
        let value2 = pair.client.negotiatedALPN
        #expect(value2 == "h3")

        try pair.client.send(streamID: 0, data: Array("GET /".utf8), fin: true)
        let requested = network.run(&pair) { _, serverEvents, _ in
            QUICTestNetwork.streamBytes(serverEvents, streamID: 0).fin
        }
        #expect(requested)
        #expect(QUICTestNetwork.streamBytes(network.serverEvents, streamID: 0).bytes == Array("GET /".utf8))

        try pair.server.send(streamID: 0, data: Array("Hello".utf8), fin: true)
        let responded = network.run(&pair) { _, _, clientEvents in
            QUICTestNetwork.streamBytes(clientEvents, streamID: 0).fin
        }
        #expect(responded)
        #expect(QUICTestNetwork.streamBytes(network.clientEvents, streamID: 0).bytes == Array("Hello".utf8))
        let value3 = pair.server.isClosed
        #expect(!value3)
        let value4 = pair.client.isClosed
        #expect(!value4)
    }

    @available(anyAppleOS 27.0, *)
    @Test(arguments: [10, 20, 30])
    func handshakeAndTransferSurviveLoss(percent: Int) throws {
        var network = QUICTestNetwork()
        // A deterministic pattern such as every third datagram can hit the same kind of packet every time, for
        // example every ACK. A seeded generator drops at random but reproducibly.
        var generator = QUICTestRandom(seed: UInt64(percent))
        network.drop = { _ in Int(generator.next() % 100) < percent }
        var pair = try network.connect()
        let connected = network.run(&pair) { pair, _, _ in
            pair.client.isHandshakeConfirmed && pair.server.isHandshakeConfirmed
        }
        #expect(connected)

        let body = (0..<300_000).map { UInt8(truncatingIfNeeded: $0 &* 31) }
        try pair.client.send(streamID: 0, data: [1, 2, 3], fin: true)
        let requested = network.run(&pair) { _, serverEvents, _ in
            QUICTestNetwork.streamBytes(serverEvents, streamID: 0).fin
        }
        #expect(requested)
        try pair.server.send(streamID: 0, data: body, fin: true)
        let done = network.run(&pair, for: .seconds(120)) { _, _, clientEvents in
            QUICTestNetwork.streamBytes(clientEvents, streamID: 0).fin
        }
        #expect(done)
        #expect(QUICTestNetwork.streamBytes(network.clientEvents, streamID: 0).bytes == body)
        #expect(QUICTestNetwork.streamBytes(network.serverEvents, streamID: 0).bytes == [1, 2, 3])
    }

    /// Moves far more bytes than the windows, so that MAX_DATA and MAX_STREAM_DATA have to keep the transfer going.
    @available(anyAppleOS 27.0, *)
    @Test func flowControlWindowsMoveWithTheData() throws {
        var configuration = QUICConnectionConfiguration()
        configuration.connectionReceiveWindow = 64 * 1024
        configuration.streamReceiveWindow = 16 * 1024
        var network = QUICTestNetwork()
        network.oneWayDelay = .milliseconds(1)
        var pair = try network.connect(configuration: configuration)
        _ = network.run(&pair) { pair, _, _ in
            pair.client.isHandshakeConfirmed && pair.server.isHandshakeConfirmed
        }

        let body = (0..<2_000_000).map { UInt8(truncatingIfNeeded: $0) }
        try pair.server.send(streamID: 3, data: body, fin: true)
        try pair.client.send(streamID: 2, data: body, fin: true)
        let done = network.run(&pair, for: .seconds(120)) { _, serverEvents, clientEvents in
            QUICTestNetwork.streamBytes(clientEvents, streamID: 3).fin
                && QUICTestNetwork.streamBytes(serverEvents, streamID: 2).fin
        }
        #expect(done)
        #expect(QUICTestNetwork.streamBytes(network.clientEvents, streamID: 3).bytes == body)
        #expect(QUICTestNetwork.streamBytes(network.serverEvents, streamID: 2).bytes == body)
        let value5 = pair.server.isClosed
        #expect(!value5)
    }

    /// Opens many more streams than the limit allows at a time; MAX_STREAMS lets the client continue.
    @available(anyAppleOS 27.0, *)
    @Test func streamLimitIsReplenished() throws {
        var configuration = QUICConnectionConfiguration()
        configuration.maxConcurrentBidirectionalStreams = 4
        var network = QUICTestNetwork()
        var pair = try network.connect(configuration: configuration)
        _ = network.run(&pair) { pair, _, _ in
            pair.client.isHandshakeConfirmed && pair.server.isHandshakeConfirmed
        }

        var answered = 0
        var nextStream: UInt64 = 0
        let total = 20
        while answered < total {
            // Open what the limit allows.
            while nextStream < UInt64(total) {
                do {
                    try pair.client.send(streamID: nextStream * 4, data: [UInt8(nextStream)], fin: true)
                    nextStream += 1
                } catch {
                    break
                }
            }
            _ = network.run(&pair, for: .milliseconds(50)) { _, _, _ in false }
            for event in network.serverEvents {
                if case .stream(let frame) = event, frame.fin {
                    try pair.server.send(streamID: frame.streamID, data: frame.data, fin: true)
                }
            }
            network.serverEvents.removeAll()
            _ = network.run(&pair, for: .milliseconds(50)) { _, _, _ in false }
            answered = network.clientEvents.filter { if case .stream(let frame) = $0 { frame.fin } else { false } }.count
            if network.now > ContinuousClock.now + .seconds(60) { break }
        }
        #expect(answered == total)
    }

    @available(anyAppleOS 27.0, *)
    @Test func applicationCloseReachesThePeer() throws {
        var network = QUICTestNetwork()
        var pair = try network.connect()
        _ = network.run(&pair) { pair, _, _ in
            pair.client.isHandshakeConfirmed && pair.server.isHandshakeConfirmed
        }
        pair.server.close(applicationErrorCode: 0x100, reason: "bye")
        let closed = network.run(&pair) { pair, _, _ in pair.client.isClosed }
        #expect(closed)
        let value6 = pair.client.error?.kind
        #expect(value6 == .peerApplicationClose(code: 0x100))
        let value7 = pair.server.error?.kind
        #expect(value7 == .localApplicationClose(code: 0x100))
    }

    @available(anyAppleOS 27.0, *)
    @Test func transportParametersRoundTrip() throws {
        var parameters = QUICTransportParameters()
        parameters.originalDestinationConnectionID = QUICConnectionID([1, 2, 3, 4])
        parameters.initialSourceConnectionID = QUICConnectionID([5, 6, 7, 8, 9])
        parameters.statelessResetToken = QUICStatelessResetToken(high: 1, low: 2)
        parameters.maxIdleTimeout = 30_000
        parameters.initialMaxData = (1 << 62) - 1
        parameters.initialMaxStreamDataBidiLocal = 1
        parameters.initialMaxStreamDataBidiRemote = 2
        parameters.initialMaxStreamDataUni = 3
        parameters.initialMaxStreamsBidi = 100
        parameters.initialMaxStreamsUni = 3
        parameters.maxAckDelay = 10
        parameters.ackDelayExponent = 5
        parameters.disableActiveMigration = true
        parameters.activeConnectionIDLimit = 4
        parameters.maxUDPPayloadSize = 1500
        #expect(try QUICTransportParameters(parsing: parameters.encoded) == parameters)

        // A duplicate parameter is an error.
        var duplicate = parameters.encoded
        duplicate.append(contentsOf: [0x04, 0x01, 0x05])
        #expect(throws: QUICTransportParameterError.self) {
            try QUICTransportParameters(parsing: duplicate)
        }
        // Unknown parameters are skipped.
        var unknown = parameters.encoded
        unknown.append(contentsOf: [0x40, 0x99, 0x02, 0xaa, 0xbb])
        #expect(try QUICTransportParameters(parsing: unknown) == parameters)
    }
}
