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

/// The QUIC versions that the codec knows.
@available(anyAppleOS 27.0, *)
enum QUICVersion {
    /// QUIC version 1 (RFC 9000).
    static var version1: UInt32 { 0x0000_0001 }

    /// The version field of a Version Negotiation packet.
    static var negotiation: UInt32 { 0 }
}

/// The header of a long header packet of QUIC version 1: Initial, 0-RTT or Handshake (RFC 9000, section 17.2).
///
/// The packet number and the low bits of the first byte are protected, so they are not part of the parsed header.
/// Header protection removes them, see ``QUICPacketKeys``.
@available(anyAppleOS 27.0, *)
struct QUICLongHeader: Equatable, Sendable {
    /// `.initial`, `.zeroRTT` or `.handshake`.
    var type: QUICPacketType

    var version: UInt32
    var destinationConnectionID: QUICConnectionID
    var sourceConnectionID: QUICConnectionID

    /// The token of an Initial packet, empty for the other types.
    var token: [UInt8]

    init(
        type: QUICPacketType,
        version: UInt32 = QUICVersion.version1,
        destinationConnectionID: QUICConnectionID,
        sourceConnectionID: QUICConnectionID,
        token: [UInt8] = []
    ) {
        precondition(type == .initial || type == .zeroRTT || type == .handshake, "Not a long header with a payload")
        self.type = type
        self.version = version
        self.destinationConnectionID = destinationConnectionID
        self.sourceConnectionID = sourceConnectionID
        self.token = token
    }

    /// The two bits of the type in the first byte.
    fileprivate static func typeBits(_ type: QUICPacketType) -> UInt8 {
        switch type {
        case .initial: 0x00
        case .zeroRTT: 0x01
        case .handshake: 0x02
        case .retry: 0x03
        case .oneRTT: preconditionFailure("1-RTT packets have a short header")
        }
    }

    /// The number of bytes from the first byte to the end of the packet number.
    ///
    /// - Parameters:
    ///   - packetNumberLength: 1 to 4.
    ///   - lengthFieldLength: The number of bytes of the Length field, 1, 2, 4 or 8. A fixed length lets the packet
    ///     assembler write the header before it knows the size of the payload.
    func encodedLength(packetNumberLength: Int, lengthFieldLength: Int = 2) -> Int {
        var length = 1 + 4 + 1 + self.destinationConnectionID.length + 1 + self.sourceConnectionID.length
        if self.type == .initial {
            length += QUICVariableLengthInteger.encodedLength(UInt64(self.token.count)) + self.token.count
        }
        return length + lengthFieldLength + packetNumberLength
    }

    /// Appends the header with the unprotected packet number.
    ///
    /// - Parameters:
    ///   - output: Receives ``encodedLength(packetNumberLength:lengthFieldLength:)`` bytes.
    ///   - packetNumber: The full packet number. Its least significant `packetNumberLength` bytes are written.
    ///   - packetNumberLength: 1 to 4.
    ///   - length: The value of the Length field: the bytes of the packet number, the payload and the AEAD tag.
    ///   - lengthFieldLength: The number of bytes of the Length field.
    func encode(
        into output: inout OutputSpan<UInt8>,
        packetNumber: UInt64,
        packetNumberLength: Int,
        length: Int,
        lengthFieldLength: Int = 2
    ) {
        precondition((1...4).contains(packetNumberLength), "A packet number has 1 to 4 bytes")
        output.append(0xc0 | Self.typeBits(self.type) << 4 | UInt8(packetNumberLength - 1))
        Self.appendVersion(self.version, to: &output)
        output.append(UInt8(self.destinationConnectionID.length))
        self.destinationConnectionID.encode(into: &output)
        output.append(UInt8(self.sourceConnectionID.length))
        self.sourceConnectionID.encode(into: &output)
        if self.type == .initial {
            QUICVariableLengthInteger.encode(UInt64(self.token.count), into: &output)
            output.appendQUICBytes(self.token)
        }
        QUICVariableLengthInteger.encode(UInt64(length), length: lengthFieldLength, into: &output)
        QUICShortHeader.appendPacketNumber(packetNumber, length: packetNumberLength, to: &output)
    }

    fileprivate static func appendVersion(_ version: UInt32, to output: inout OutputSpan<UInt8>) {
        output.append(UInt8(truncatingIfNeeded: version >> 24))
        output.append(UInt8(truncatingIfNeeded: version >> 16))
        output.append(UInt8(truncatingIfNeeded: version >> 8))
        output.append(UInt8(truncatingIfNeeded: version))
    }
}

/// The header of a 1-RTT packet (RFC 9000, section 17.3.1).
///
/// The connection ID has no length on the wire: the receiver knows the length of the connection IDs it issued.
@available(anyAppleOS 27.0, *)
struct QUICShortHeader: Equatable, Sendable {
    var destinationConnectionID: QUICConnectionID

    /// The latency spin bit (section 17.4).
    var spinBit: Bool

    /// The key phase, which flips with every key update (RFC 9001, section 6).
    var keyPhase: Bool

    init(destinationConnectionID: QUICConnectionID, spinBit: Bool = false, keyPhase: Bool = false) {
        self.destinationConnectionID = destinationConnectionID
        self.spinBit = spinBit
        self.keyPhase = keyPhase
    }

    /// The number of bytes from the first byte to the end of the packet number.
    func encodedLength(packetNumberLength: Int) -> Int {
        1 + self.destinationConnectionID.length + packetNumberLength
    }

    /// Appends the header with the unprotected packet number.
    func encode(into output: inout OutputSpan<UInt8>, packetNumber: UInt64, packetNumberLength: Int) {
        precondition((1...4).contains(packetNumberLength), "A packet number has 1 to 4 bytes")
        var first: UInt8 = 0x40 | UInt8(packetNumberLength - 1)
        if self.spinBit { first |= 0x20 }
        if self.keyPhase { first |= 0x04 }
        output.append(first)
        self.destinationConnectionID.encode(into: &output)
        Self.appendPacketNumber(packetNumber, length: packetNumberLength, to: &output)
    }

    fileprivate static func appendPacketNumber(_ packetNumber: UInt64, length: Int, to output: inout OutputSpan<UInt8>) {
        for index in stride(from: length - 1, through: 0, by: -1) {
            output.append(UInt8(truncatingIfNeeded: packetNumber >> UInt64(8 * index)))
        }
    }
}

/// A Retry packet (RFC 9000, section 17.2.5).
@available(anyAppleOS 27.0, *)
struct QUICRetryPacket: Equatable, Sendable {
    var version: UInt32
    var destinationConnectionID: QUICConnectionID
    var sourceConnectionID: QUICConnectionID
    var token: [UInt8]

    /// The 16 byte Retry Integrity Tag (RFC 9001, section 5.8).
    var integrityTag: [UInt8]
}

/// A Version Negotiation packet (RFC 9000, section 17.2.1).
///
/// The connection IDs can be up to 255 bytes, because they are those of a packet whose version the server does not
/// know.
@available(anyAppleOS 27.0, *)
struct QUICVersionNegotiationPacket: Equatable, Sendable {
    var destinationConnectionID: [UInt8]
    var sourceConnectionID: [UInt8]
    var supportedVersions: [UInt32]

    init(destinationConnectionID: [UInt8], sourceConnectionID: [UInt8], supportedVersions: [UInt32]) {
        self.destinationConnectionID = destinationConnectionID
        self.sourceConnectionID = sourceConnectionID
        self.supportedVersions = supportedVersions
    }

    /// The number of bytes of ``encode(into:)``.
    var encodedLength: Int {
        1 + 4 + 1 + self.destinationConnectionID.count + 1 + self.sourceConnectionID.count
            + 4 * self.supportedVersions.count
    }

    /// Appends the packet.
    func encode(into output: inout OutputSpan<UInt8>) {
        // The bits after the header form are unused; setting the second one makes the packet look like a QUIC v1
        // long header packet, as recommended by section 17.2.1.
        output.append(0xc0)
        QUICLongHeader.appendVersion(QUICVersion.negotiation, to: &output)
        output.append(UInt8(self.destinationConnectionID.count))
        output.appendQUICBytes(self.destinationConnectionID)
        output.append(UInt8(self.sourceConnectionID.count))
        output.appendQUICBytes(self.sourceConnectionID)
        for version in self.supportedVersions {
            QUICLongHeader.appendVersion(version, to: &output)
        }
    }
}

/// The parsed header of a packet in a datagram.
@available(anyAppleOS 27.0, *)
enum QUICPacketHeader: Equatable, Sendable {
    /// An Initial, 0-RTT or Handshake packet.
    case long(QUICLongHeader)

    /// A 1-RTT packet. The key phase and the spin bit are protected and only known after header protection is
    /// removed.
    case short(destinationConnectionID: QUICConnectionID)

    case retry(QUICRetryPacket)

    case versionNegotiation(QUICVersionNegotiationPacket)

    /// A long header packet of a version other than 1. Only the version independent fields are parsed (RFC 8999),
    /// so that the server can answer with a Version Negotiation packet.
    case unsupportedVersion(version: UInt32, destinationConnectionID: [UInt8], sourceConnectionID: [UInt8])

    /// The packet type, or `nil` for Version Negotiation and unsupported versions.
    var packetType: QUICPacketType? {
        switch self {
        case .long(let header): header.type
        case .short: .oneRTT
        case .retry: .retry
        case .versionNegotiation, .unsupportedVersion: nil
        }
    }

    /// The destination connection ID, or `nil` if it is not a connection ID of version 1.
    var destinationConnectionID: QUICConnectionID? {
        switch self {
        case .long(let header): header.destinationConnectionID
        case .short(let id): id
        case .retry(let packet): packet.destinationConnectionID
        case .versionNegotiation(let packet):
            packet.destinationConnectionID.count <= QUICConnectionID.maximumLength
                ? QUICConnectionID(packet.destinationConnectionID) : nil
        case .unsupportedVersion(_, let id, _):
            id.count <= QUICConnectionID.maximumLength ? QUICConnectionID(id) : nil
        }
    }
}

/// A packet of a datagram, before its protection is removed.
@available(anyAppleOS 27.0, *)
struct QUICProtectedPacket: Equatable, Sendable {
    var header: QUICPacketHeader

    /// The bytes of the packet within the datagram.
    var range: Range<Int>

    /// The offset of the packet number from the start of the packet, for the packet types that have one.
    var packetNumberOffset: Int

    /// Parses the next packet of a datagram.
    ///
    /// A datagram can carry several coalesced long header packets, each ending where its Length field says, and at
    /// most one short header packet, which takes the rest of the datagram (RFC 9000, section 12.2). Call this until
    /// the datagram is empty. If a packet fails to parse, the rest of the datagram cannot be parsed either.
    ///
    /// - Parameters:
    ///   - input: The rest of the datagram. Positions in `range` are those of `input`.
    ///   - shortHeaderConnectionIDLength: The length of the connection IDs that this endpoint issued, which short
    ///     headers carry without a length.
    init(parsing input: inout ParserSpan, shortHeaderConnectionIDLength: Int) throws(ParsingError) {
        let start = input.startPosition
        let first = try UInt8(parsing: &input)

        guard first & 0x80 != 0 else {
            // Short header.
            guard first & 0x40 != 0 else {
                throw ParsingError(userError: QUICPacketError.fixedBitNotSet)
            }
            let id = try QUICConnectionID(parsing: &input, length: shortHeaderConnectionIDLength)
            self.header = .short(destinationConnectionID: id)
            self.packetNumberOffset = input.startPosition - start
            _ = input.extractRemaining()
            self.range = start..<input.startPosition
            return
        }

        let version = try UInt32(parsingBigEndian: &input)
        let destinationLength = Int(try UInt8(parsing: &input))
        let destination = try [UInt8](parsing: &input, byteCount: destinationLength)
        let sourceLength = Int(try UInt8(parsing: &input))
        let source = try [UInt8](parsing: &input, byteCount: sourceLength)

        if version == QUICVersion.negotiation {
            var versions: [UInt32] = []
            guard input.count % 4 == 0 else {
                throw ParsingError(userError: QUICPacketError.invalidVersionNegotiation)
            }
            while !input.isEmpty {
                versions.append(try UInt32(parsingBigEndian: &input))
            }
            self.header = .versionNegotiation(
                QUICVersionNegotiationPacket(
                    destinationConnectionID: destination,
                    sourceConnectionID: source,
                    supportedVersions: versions
                )
            )
            self.packetNumberOffset = 0
            self.range = start..<input.startPosition
            return
        }

        guard version == QUICVersion.version1 else {
            self.header = .unsupportedVersion(
                version: version,
                destinationConnectionID: destination,
                sourceConnectionID: source
            )
            self.packetNumberOffset = 0
            _ = input.extractRemaining()
            self.range = start..<input.startPosition
            return
        }

        guard first & 0x40 != 0 else {
            throw ParsingError(userError: QUICPacketError.fixedBitNotSet)
        }
        guard destination.count <= QUICConnectionID.maximumLength, source.count <= QUICConnectionID.maximumLength
        else {
            throw ParsingError(userError: QUICFrameError.invalidConnectionIDLength(max(destination.count, source.count)))
        }
        let destinationID = QUICConnectionID(destination)
        let sourceID = QUICConnectionID(source)

        let type: QUICPacketType =
            switch (first >> 4) & 0x03 {
            case 0x00: .initial
            case 0x01: .zeroRTT
            case 0x02: .handshake
            default: .retry
            }

        if type == .retry {
            guard input.count >= 16 else {
                throw ParsingError(userError: QUICPacketError.packetTooShort)
            }
            let token = try [UInt8](parsing: &input, byteCount: input.count - 16)
            let tag = try [UInt8](parsing: &input, byteCount: 16)
            self.header = .retry(
                QUICRetryPacket(
                    version: version,
                    destinationConnectionID: destinationID,
                    sourceConnectionID: sourceID,
                    token: token,
                    integrityTag: tag
                )
            )
            self.packetNumberOffset = 0
            self.range = start..<input.startPosition
            return
        }

        var token: [UInt8] = []
        if type == .initial {
            let tokenLength = try QUICVariableLengthInteger.decode(parsing: &input)
            guard tokenLength <= UInt64(input.count) else {
                throw ParsingError(userError: QUICPacketError.packetTooShort)
            }
            token = try [UInt8](parsing: &input, byteCount: Int(tokenLength))
        }
        let length = try QUICVariableLengthInteger.decode(parsing: &input)
        guard length <= UInt64(input.count) else {
            throw ParsingError(userError: QUICPacketError.packetTooShort)
        }
        self.header = .long(
            QUICLongHeader(
                type: type,
                version: version,
                destinationConnectionID: destinationID,
                sourceConnectionID: sourceID,
                token: token
            )
        )
        self.packetNumberOffset = input.startPosition - start
        try input.seek(toRelativeOffset: Int(length))
        self.range = start..<input.startPosition
    }

    /// Splits a datagram into its packets.
    ///
    /// Stops at the first packet that does not parse: the receiver drops the rest (RFC 9000, section 12.2).
    ///
    /// - Returns: The packets that parsed, and whether the datagram had bytes that did not.
    static func split(
        datagram: RawSpan,
        shortHeaderConnectionIDLength: Int
    ) -> (packets: [QUICProtectedPacket], remainderIsInvalid: Bool) {
        var input = ParserSpan(datagram)
        var packets: [QUICProtectedPacket] = []
        while !input.isEmpty {
            do {
                packets.append(
                    try QUICProtectedPacket(parsing: &input, shortHeaderConnectionIDLength: shortHeaderConnectionIDLength)
                )
            } catch {
                return (packets, true)
            }
        }
        return (packets, false)
    }
}

/// A packet that cannot be parsed.
@available(anyAppleOS 27.0, *)
enum QUICPacketError: Error, Hashable, Sendable {
    /// The fixed bit of a version 1 packet is 0.
    case fixedBitNotSet

    /// The packet is shorter than its header says.
    case packetTooShort

    /// The list of versions of a Version Negotiation packet is not a multiple of 4 bytes.
    case invalidVersionNegotiation

    /// Header protection could not be removed or the AEAD did not authenticate the packet.
    case decryptionFailed

    /// The packet has too few bytes after the packet number for the sample of header protection.
    case sampleTooShort
}
