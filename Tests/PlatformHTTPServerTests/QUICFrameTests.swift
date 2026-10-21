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
import Testing

@testable import PlatformHTTPServer

@Suite
struct QUICFrameTests {
    @available(anyAppleOS 27.0, *)
    private static var maximum: UInt64 { QUICVariableLengthInteger.maximum }

    /// One frame of every type, with small and with extreme values.
    @available(anyAppleOS 27.0, *)
    private static var frames: [QUICFrame] {
        let max = Self.maximum
        return [
            .padding(count: 1),
            .padding(count: 17),
            .ping,
            .ack(QUICAckFrame(largestAcknowledged: 0, ackDelay: 0, firstRange: 0)),
            .ack(QUICAckFrame(acknowledging: [100...110, 90...95, 0...10], ackDelay: 25)),
            .ack(
                QUICAckFrame(
                    largestAcknowledged: max,
                    ackDelay: max,
                    firstRange: max,
                    ecnCounts: .init(ect0: 1, ect1: max, ce: 0)
                )
            ),
            .resetStream(streamID: 0, applicationErrorCode: 0, finalSize: 0),
            .resetStream(streamID: max, applicationErrorCode: max, finalSize: max),
            .stopSending(streamID: 4, applicationErrorCode: 0x10c),
            .crypto(offset: 0, data: []),
            .crypto(offset: 1234, data: Array(0..<200)),
            .crypto(offset: max - 3, data: [1, 2, 3]),
            .newToken([0xde, 0xad]),
            .stream(QUICStreamFrame(streamID: 0, data: [])),
            .stream(QUICStreamFrame(streamID: 0, data: [], fin: true)),
            .stream(QUICStreamFrame(streamID: 4, offset: 70000, data: Array(repeating: 7, count: 300), fin: true)),
            .stream(QUICStreamFrame(streamID: max, offset: max - 1, data: [9])),
            .maxData(0),
            .maxData(max),
            .maxStreamData(streamID: 8, maximum: max),
            .maxStreams(bidirectional: true, maximum: 100),
            .maxStreams(bidirectional: false, maximum: 1 << 60),
            .dataBlocked(limit: max),
            .streamDataBlocked(streamID: 3, limit: 65536),
            .streamsBlocked(bidirectional: true, limit: 0),
            .streamsBlocked(bidirectional: false, limit: 1 << 60),
            .newConnectionID(
                QUICNewConnectionIDFrame(
                    sequenceNumber: 1,
                    retirePriorTo: 0,
                    connectionID: QUICConnectionID([1, 2, 3, 4, 5, 6, 7, 8]),
                    statelessResetToken: QUICStatelessResetToken(high: 0x0102_0304_0506_0708, low: max)
                )
            ),
            .newConnectionID(
                QUICNewConnectionIDFrame(
                    sequenceNumber: max,
                    retirePriorTo: max,
                    connectionID: QUICConnectionID(Array(0..<20)),
                    statelessResetToken: QUICStatelessResetToken(high: 0, low: 0)
                )
            ),
            .retireConnectionID(sequenceNumber: 7),
            .pathChallenge(0x0123_4567_89ab_cdef),
            .pathResponse(.max),
            .connectionClose(QUICConnectionCloseFrame(error: .transport(.protocolViolation, frameType: 0x08))),
            .connectionClose(
                QUICConnectionCloseFrame(
                    error: .transport(.cryptoError(alert: 120), frameType: 0x06),
                    reasonPhrase: Array("no application protocol".utf8)
                )
            ),
            .connectionClose(QUICConnectionCloseFrame(error: .application(max), reasonPhrase: [0x41])),
            .handshakeDone,
        ]
    }

    @available(anyAppleOS 27.0, *)
    private static func encode(_ frame: QUICFrame, omittingStreamLength: Bool = false) -> [UInt8] {
        quicEncode(count: frame.encodedLength(omittingStreamLength: omittingStreamLength)) {
            frame.encode(into: &$0, omittingStreamLength: omittingStreamLength)
        }
    }

    @available(anyAppleOS 27.0, *)
    private static func parseAll(_ bytes: [UInt8]) throws -> [QUICFrame] {
        try quicParse(bytes) { input throws(ParsingError) in
            var frames: [QUICFrame] = []
            while !input.isEmpty {
                frames.append(try QUICFrame(parsing: &input))
            }
            return frames
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test func everyFrameRoundTrips() throws {
        for frame in Self.frames {
            let bytes = Self.encode(frame)
            #expect(try Self.parseAll(bytes) == [frame], "\(frame)")
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test func severalFramesInOneBufferParse() throws {
        // Padding is coalesced, so a run of padding frames comes back as one. Keep them apart with other frames.
        var bytes: [UInt8] = []
        for frame in Self.frames {
            bytes += Self.encode(frame)
            bytes += Self.encode(.ping)
        }
        let expected = Self.frames.flatMap { [$0, QUICFrame.ping] }
        #expect(try Self.parseAll(bytes) == expected)
    }

    @available(anyAppleOS 27.0, *)
    @Test func consecutivePaddingIsOneFrame() throws {
        let bytes = [UInt8](repeating: 0, count: 50) + Self.encode(.ping) + [0, 0]
        #expect(try Self.parseAll(bytes) == [.padding(count: 50), .ping, .padding(count: 2)])
    }

    @available(anyAppleOS 27.0, *)
    @Test func aStreamFrameWithoutLengthTakesTheRest() throws {
        let frame = QUICFrame.stream(QUICStreamFrame(streamID: 4, offset: 10, data: [1, 2, 3], fin: true))
        let bytes = Self.encode(frame, omittingStreamLength: true)
        #expect(bytes.count == frame.encodedLength() - 1)
        #expect(bytes[0] == 0x0d)
        #expect(try Self.parseAll(bytes) == [frame])
    }

    @available(anyAppleOS 27.0, *)
    @Test func truncatedFramesThrow() {
        for frame in Self.frames {
            if case .padding = frame { continue }
            if case .stream = frame { continue }
            let bytes = Self.encode(frame)
            for count in 0..<bytes.count {
                #expect(throws: ParsingError.self, "\(frame) truncated to \(count) bytes") {
                    try Array(bytes.prefix(count)).withParserSpan { input throws(ParsingError) in
                        _ = try QUICFrame(parsing: &input)
                    }
                }
            }
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test func truncatedStreamFramesWithLengthThrow() {
        let frame = QUICFrame.stream(QUICStreamFrame(streamID: 4, offset: 70000, data: [1, 2, 3, 4]))
        let bytes = Self.encode(frame)
        for count in 0..<bytes.count {
            #expect(throws: ParsingError.self) {
                try Array(bytes.prefix(count)).withParserSpan { input throws(ParsingError) in
                    _ = try QUICFrame(parsing: &input)
                }
            }
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test(arguments: [
        // Unknown frame type.
        "1f",
        // ACK whose first range goes below 0.
        "02 05 00 00 06",
        // ACK whose second range goes below 0.
        "02 05 00 01 01 00 03",
        // ACK with more ranges than bytes.
        "02 05 00 3f 00",
        // CRYPTO beyond 2^62 - 1.
        "06 ffffffffffffffff 01 00",
        // Empty NEW_TOKEN.
        "07 00",
        // STREAM beyond 2^62 - 1.
        "0e 00 ffffffffffffffff 01 00",
        // MAX_STREAMS above 2^60.
        "12 d000000000000001",
        // STREAMS_BLOCKED above 2^60.
        "17 d000000000000001",
        // NEW_CONNECTION_ID with a connection ID of 0 and of 21 bytes.
        "18 01 00 00 00000000000000000000000000000000",
        "18 01 00 15 000000000000000000000000000000000000000000 00000000000000000000000000000000",
        // NEW_CONNECTION_ID with Retire Prior To above the sequence number.
        "18 01 02 01 aa 00000000000000000000000000000000",
    ])
    func invalidFramesThrow(hex: String) {
        #expect(throws: ParsingError.self) {
            _ = try Self.parseAll(quicHex(hex))
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test func ackRangesConvertToPacketNumbers() throws {
        let ranges: [ClosedRange<UInt64>] = [100...110, 90...95, 88...88, 0...10]
        let ack = QUICAckFrame(acknowledging: ranges, ackDelay: 0)
        #expect(ack.largestAcknowledged == 110)
        #expect(ack.firstRange == 10)
        #expect(ack.ranges == [.init(gap: 3, length: 5), .init(gap: 0, length: 0), .init(gap: 76, length: 10)])
        #expect(ack.acknowledgedRanges == ranges)
    }

    @available(anyAppleOS 27.0, *)
    @Test func framesAreAllowedInTheirPacketTypes() {
        let crypto = QUICFrame.crypto(offset: 0, data: [1])
        #expect(crypto.isAllowed(in: .initial) && crypto.isAllowed(in: .handshake) && crypto.isAllowed(in: .oneRTT))
        #expect(!crypto.isAllowed(in: .zeroRTT))
        let stream = QUICFrame.stream(QUICStreamFrame(streamID: 0, data: [1]))
        #expect(!stream.isAllowed(in: .initial) && !stream.isAllowed(in: .handshake))
        #expect(stream.isAllowed(in: .zeroRTT) && stream.isAllowed(in: .oneRTT))
        #expect(QUICFrame.handshakeDone.isAllowed(in: .oneRTT) && !QUICFrame.handshakeDone.isAllowed(in: .zeroRTT))
        let transportClose = QUICFrame.connectionClose(.init(error: .transport(.noError, frameType: 0)))
        let applicationClose = QUICFrame.connectionClose(.init(error: .application(0)))
        #expect(transportClose.isAllowed(in: .initial) && !applicationClose.isAllowed(in: .initial))
        #expect(!QUICFrame.ping.isAllowed(in: .retry))
        #expect(!QUICFrame.padding(count: 1).isAckEliciting && QUICFrame.ping.isAckEliciting)
        #expect(!transportClose.isAckEliciting)
        #expect(!QUICFrame.ack(QUICAckFrame(largestAcknowledged: 0, ackDelay: 0, firstRange: 0)).isAckEliciting)
    }
}
