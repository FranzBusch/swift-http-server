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
struct QUICPacketHeaderTests {
    // MARK: - Packet numbers

    /// The examples of RFC 9000, appendix A.2.
    @available(anyAppleOS 27.0, *)
    @Test func packetNumberLengthsOfTheRFC() {
        #expect(QUICPacketNumber.encodedLength(of: 0xac5c02, largestAcknowledged: 0xabe8b3) == 2)
        #expect(QUICPacketNumber.encodedLength(of: 0xace8fe, largestAcknowledged: 0xabe8b3) == 3)
        #expect(QUICPacketNumber.encodedLength(of: 0, largestAcknowledged: nil) == 1)
        #expect(QUICPacketNumber.encodedLength(of: 1 << 40, largestAcknowledged: 0) == 4)
    }

    /// The example of RFC 9000, appendix A.3.
    @available(anyAppleOS 27.0, *)
    @Test func packetNumberDecodingOfTheRFC() {
        #expect(QUICPacketNumber.decode(truncated: 0x9b32, length: 2, largestReceived: 0xa82f30ea) == 0xa82f9b32)
    }

    @available(anyAppleOS 27.0, *)
    @Test func packetNumbersRoundTripAroundTheWindow() {
        for largest: UInt64 in [0, 1, 127, 128, 255, 256, 65535, 0xabe8b3, 0xa82f30ea] {
            for distance: UInt64 in [1, 2, 100, 127, 1000] {
                let packetNumber = largest + distance
                let length = QUICPacketNumber.encodedLength(of: packetNumber, largestAcknowledged: largest)
                let truncated = QUICPacketNumber.truncate(packetNumber, toLength: length)
                let decoded = QUICPacketNumber.decode(truncated: truncated, length: length, largestReceived: largest)
                #expect(decoded == packetNumber, "\(packetNumber) after \(largest)")
            }
        }
        // A reordered packet below the largest decodes too.
        #expect(QUICPacketNumber.decode(truncated: 0xfe, length: 1, largestReceived: 0x101) == 0xfe)
        #expect(QUICPacketNumber.decode(truncated: 0x00, length: 1, largestReceived: nil) == 0)
    }

    // MARK: - Headers

    @available(anyAppleOS 27.0, *)
    private static func longPacket(
        _ header: QUICLongHeader,
        packetNumber: UInt64,
        packetNumberLength: Int,
        payload: [UInt8]
    ) -> [UInt8] {
        let headerLength = header.encodedLength(packetNumberLength: packetNumberLength)
        return quicEncode(count: headerLength + payload.count) { output in
            header.encode(
                into: &output,
                packetNumber: packetNumber,
                packetNumberLength: packetNumberLength,
                length: packetNumberLength + payload.count
            )
            output.appendQUICBytes(payload)
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test func coalescedPacketsSplit() throws {
        let destination = QUICConnectionID([1, 2, 3, 4, 5, 6, 7, 8])
        let source = QUICConnectionID([9, 10, 11, 12])
        let initial = QUICLongHeader(
            type: .initial,
            destinationConnectionID: destination,
            sourceConnectionID: source,
            token: [0xaa, 0xbb]
        )
        let handshake = QUICLongHeader(type: .handshake, destinationConnectionID: destination, sourceConnectionID: source)
        let short = QUICShortHeader(destinationConnectionID: destination, spinBit: true, keyPhase: true)

        let first = Self.longPacket(initial, packetNumber: 0x1234, packetNumberLength: 2, payload: Array(0..<40))
        let second = Self.longPacket(handshake, packetNumber: 7, packetNumberLength: 1, payload: Array(0..<30))
        let third = quicEncode(count: short.encodedLength(packetNumberLength: 4) + 25) { output in
            short.encode(into: &output, packetNumber: 0x0102_0304, packetNumberLength: 4)
            output.appendQUICBytes(Array(repeating: 0x55, count: 25))
        }
        #expect(first[0] == 0xc1)
        #expect(second[0] == 0xe0)
        #expect(third[0] == 0x67)

        let datagram = first + second + third
        let (packets, invalid) = datagram.withUnsafeBytes { bytes in
            QUICProtectedPacket.split(
                datagram: RawSpan(_unsafeBytes: bytes),
                shortHeaderConnectionIDLength: 8
            )
        }
        #expect(!invalid)
        #expect(packets.count == 3)
        #expect(packets[0].header == .long(initial))
        #expect(packets[0].range == 0..<first.count)
        #expect(packets[0].packetNumberOffset == first.count - 40 - 2)
        #expect(packets[1].header == .long(handshake))
        #expect(packets[1].range == first.count..<(first.count + second.count))
        #expect(packets[1].packetNumberOffset == second.count - 30 - 1)
        #expect(packets[2].header == .short(destinationConnectionID: destination))
        #expect(packets[2].range == (first.count + second.count)..<datagram.count)
        #expect(packets[2].packetNumberOffset == 9)
    }

    @available(anyAppleOS 27.0, *)
    @Test func aLengthBeyondTheDatagramIsInvalid() {
        let header = QUICLongHeader(
            type: .handshake,
            destinationConnectionID: QUICConnectionID([1]),
            sourceConnectionID: .empty
        )
        var packet = Self.longPacket(header, packetNumber: 1, packetNumberLength: 1, payload: Array(0..<20))
        packet.removeLast()
        let (packets, invalid) = packet.withUnsafeBytes { bytes in
            QUICProtectedPacket.split(datagram: RawSpan(_unsafeBytes: bytes), shortHeaderConnectionIDLength: 1)
        }
        #expect(packets.isEmpty)
        #expect(invalid)
    }

    @available(anyAppleOS 27.0, *)
    @Test func truncatedLongHeadersThrow() {
        let header = QUICLongHeader(
            type: .initial,
            destinationConnectionID: QUICConnectionID(Array(0..<8)),
            sourceConnectionID: QUICConnectionID(Array(0..<8)),
            token: [1, 2, 3]
        )
        let packet = Self.longPacket(header, packetNumber: 1, packetNumberLength: 1, payload: Array(0..<20))
        for count in 0..<packet.count {
            #expect(throws: ParsingError.self) {
                try Array(packet.prefix(count)).withParserSpan { input throws(ParsingError) in
                    _ = try QUICProtectedPacket(parsing: &input, shortHeaderConnectionIDLength: 8)
                }
            }
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test func versionNegotiationRoundTrips() throws {
        let negotiation = QUICVersionNegotiationPacket(
            destinationConnectionID: Array(0..<30),
            sourceConnectionID: [7],
            supportedVersions: [QUICVersion.version1, 0x6b33_43cf]
        )
        let bytes = quicEncode(count: negotiation.encodedLength) { negotiation.encode(into: &$0) }
        let packet = try quicParse(bytes) { input throws(ParsingError) in
            try QUICProtectedPacket(parsing: &input, shortHeaderConnectionIDLength: 8)
        }
        #expect(packet.header == .versionNegotiation(negotiation))
        #expect(packet.header.destinationConnectionID == nil)
    }

    @available(anyAppleOS 27.0, *)
    @Test func anUnknownVersionKeepsTheConnectionIDs() throws {
        // A long header of version 0x1a2a3a4a with a connection ID longer than version 1 allows.
        let bytes: [UInt8] = [0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 25] + [UInt8](repeating: 1, count: 25) + [2, 9, 9] + Array(repeating: 0, count: 50)
        let packet = try quicParse(bytes) { input throws(ParsingError) in
            try QUICProtectedPacket(parsing: &input, shortHeaderConnectionIDLength: 8)
        }
        #expect(
            packet.header
                == .unsupportedVersion(
                    version: 0x1a2a_3a4a,
                    destinationConnectionID: Array(repeating: 1, count: 25),
                    sourceConnectionID: [9, 9]
                )
        )
        #expect(packet.range == 0..<bytes.count)
    }

    @available(anyAppleOS 27.0, *)
    @Test func retryParses() throws {
        let bytes: [UInt8] = [0xf0, 0, 0, 0, 1, 2, 0xaa, 0xbb, 1, 0xcc] + [5, 6, 7] + Array(repeating: 0xee, count: 16)
        let packet = try quicParse(bytes) { input throws(ParsingError) in
            try QUICProtectedPacket(parsing: &input, shortHeaderConnectionIDLength: 8)
        }
        #expect(
            packet.header
                == .retry(
                    QUICRetryPacket(
                        version: 1,
                        destinationConnectionID: QUICConnectionID([0xaa, 0xbb]),
                        sourceConnectionID: QUICConnectionID([0xcc]),
                        token: [5, 6, 7],
                        integrityTag: Array(repeating: 0xee, count: 16)
                    )
                )
        )
    }

    @available(anyAppleOS 27.0, *)
    @Test func aCleanFixedBitIsInvalid() {
        #expect(throws: ParsingError.self) {
            try [UInt8]([0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9]).withParserSpan { input throws(ParsingError) in
                _ = try QUICProtectedPacket(parsing: &input, shortHeaderConnectionIDLength: 8)
            }
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test func connectionIDsCompareByValue() {
        let a = QUICConnectionID(Array(0..<20))
        let b = QUICConnectionID(Array(0..<20))
        let c = QUICConnectionID(Array(0..<19))
        #expect(a == b && a.hashValue == b.hashValue)
        #expect(a != c)
        #expect(a.bytes == Array(0..<20))
        #expect(QUICConnectionID([0x0a, 0xff]).description == "0aff")
        #expect(QUICConnectionID.random(length: 8).length == 8)
    }
}
