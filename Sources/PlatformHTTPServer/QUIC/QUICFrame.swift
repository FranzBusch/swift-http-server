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

/// A frame in the payload of a QUIC packet (RFC 9000, section 19).
///
/// Parse the frames of a decrypted payload one after the other with ``init(parsing:)`` until the payload is empty.
/// Encoding is two step, so that a packet assembler can decide what fits before it writes: ``encodedLength(omittingStreamLength:)``
/// gives the exact size of ``encode(into:omittingStreamLength:)``.
@available(anyAppleOS 27.0, *)
enum QUICFrame: Equatable, Sendable {
    /// PADDING (0x00). Consecutive padding bytes are parsed into one frame.
    case padding(count: Int)

    /// PING (0x01).
    case ping

    /// ACK (0x02) or, with ECN counts, ACK_ECN (0x03).
    case ack(QUICAckFrame)

    /// RESET_STREAM (0x04).
    case resetStream(streamID: UInt64, applicationErrorCode: UInt64, finalSize: UInt64)

    /// STOP_SENDING (0x05).
    case stopSending(streamID: UInt64, applicationErrorCode: UInt64)

    /// CRYPTO (0x06): bytes of the TLS handshake at an offset of the crypto stream of the packet number space.
    case crypto(offset: UInt64, data: [UInt8])

    /// NEW_TOKEN (0x07).
    case newToken([UInt8])

    /// STREAM (0x08 to 0x0f).
    case stream(QUICStreamFrame)

    /// MAX_DATA (0x10).
    case maxData(UInt64)

    /// MAX_STREAM_DATA (0x11).
    case maxStreamData(streamID: UInt64, maximum: UInt64)

    /// MAX_STREAMS (0x12 for bidirectional, 0x13 for unidirectional streams).
    case maxStreams(bidirectional: Bool, maximum: UInt64)

    /// DATA_BLOCKED (0x14).
    case dataBlocked(limit: UInt64)

    /// STREAM_DATA_BLOCKED (0x15).
    case streamDataBlocked(streamID: UInt64, limit: UInt64)

    /// STREAMS_BLOCKED (0x16 for bidirectional, 0x17 for unidirectional streams).
    case streamsBlocked(bidirectional: Bool, limit: UInt64)

    /// NEW_CONNECTION_ID (0x18).
    case newConnectionID(QUICNewConnectionIDFrame)

    /// RETIRE_CONNECTION_ID (0x19).
    case retireConnectionID(sequenceNumber: UInt64)

    /// PATH_CHALLENGE (0x1a) with its 8 bytes of data.
    case pathChallenge(UInt64)

    /// PATH_RESPONSE (0x1b) with the 8 bytes of data of the challenge.
    case pathResponse(UInt64)

    /// CONNECTION_CLOSE (0x1c for transport errors, 0x1d for errors of the application).
    case connectionClose(QUICConnectionCloseFrame)

    /// HANDSHAKE_DONE (0x1e).
    case handshakeDone
}

/// The payload of an ACK or ACK_ECN frame (RFC 9000, section 19.3).
@available(anyAppleOS 27.0, *)
struct QUICAckFrame: Equatable, Sendable {
    /// A range of packets below the previous one: `gap` unacknowledged packets followed by `length` + 1 acknowledged
    /// packets, each minus one as on the wire.
    struct Range: Equatable, Sendable {
        var gap: UInt64
        var length: UInt64

        init(gap: UInt64, length: UInt64) {
            self.gap = gap
            self.length = length
        }
    }

    /// The counts of the ECN codepoints of the received packets.
    struct ECNCounts: Equatable, Sendable {
        var ect0: UInt64
        var ect1: UInt64
        var ce: UInt64

        init(ect0: UInt64, ect1: UInt64, ce: UInt64) {
            self.ect0 = ect0
            self.ect1 = ect1
            self.ce = ce
        }
    }

    /// The largest packet number that is acknowledged.
    var largestAcknowledged: UInt64

    /// The encoded delay of the acknowledgment, in microseconds shifted right by the `ack_delay_exponent`.
    var ackDelay: UInt64

    /// The number of packets before the largest that are acknowledged too.
    var firstRange: UInt64

    /// The further ranges, from high to low packet numbers.
    var ranges: [Range]

    /// The ECN counts of an ACK_ECN frame, or `nil` for an ACK frame.
    var ecnCounts: ECNCounts?

    init(
        largestAcknowledged: UInt64,
        ackDelay: UInt64,
        firstRange: UInt64,
        ranges: [Range] = [],
        ecnCounts: ECNCounts? = nil
    ) {
        self.largestAcknowledged = largestAcknowledged
        self.ackDelay = ackDelay
        self.firstRange = firstRange
        self.ranges = ranges
        self.ecnCounts = ecnCounts
    }

    /// Creates the frame that acknowledges the given ranges of packet numbers.
    ///
    /// - Parameters:
    ///   - acknowledged: The acknowledged packet numbers, from high to low, with at least one unacknowledged packet
    ///     between two ranges. There has to be at least one range.
    ///   - ackDelay: The encoded delay of the acknowledgment.
    ///   - ecnCounts: The ECN counts, if any.
    init(acknowledging acknowledged: [ClosedRange<UInt64>], ackDelay: UInt64, ecnCounts: ECNCounts? = nil) {
        precondition(!acknowledged.isEmpty, "An ACK frame acknowledges at least one packet")
        let first = acknowledged[0]
        self.largestAcknowledged = first.upperBound
        self.ackDelay = ackDelay
        self.firstRange = first.upperBound - first.lowerBound
        var ranges: [Range] = []
        ranges.reserveCapacity(acknowledged.count - 1)
        var smallest = first.lowerBound
        for range in acknowledged.dropFirst() {
            precondition(range.upperBound + 2 <= smallest, "The ranges of an ACK frame are descending and apart")
            ranges.append(Range(gap: smallest - range.upperBound - 2, length: range.upperBound - range.lowerBound))
            smallest = range.lowerBound
        }
        self.ranges = ranges
        self.ecnCounts = ecnCounts
    }

    /// The acknowledged packet numbers, from high to low.
    ///
    /// The ranges are valid: parsing rejects frames whose ranges go below packet number 0.
    var acknowledgedRanges: [ClosedRange<UInt64>] {
        var result: [ClosedRange<UInt64>] = []
        result.reserveCapacity(self.ranges.count + 1)
        var smallest = self.largestAcknowledged - self.firstRange
        result.append(smallest...self.largestAcknowledged)
        for range in self.ranges {
            let largest = smallest - range.gap - 2
            smallest = largest - range.length
            result.append(smallest...largest)
        }
        return result
    }
}

/// The payload of a STREAM frame (RFC 9000, section 19.8).
@available(anyAppleOS 27.0, *)
struct QUICStreamFrame: Equatable, Sendable {
    var streamID: UInt64

    /// The offset of the first byte of `data` in the stream.
    var offset: UInt64

    var data: [UInt8]

    /// Whether the frame ends the stream.
    var fin: Bool

    init(streamID: UInt64, offset: UInt64 = 0, data: [UInt8], fin: Bool = false) {
        self.streamID = streamID
        self.offset = offset
        self.data = data
        self.fin = fin
    }
}

/// The payload of a NEW_CONNECTION_ID frame (RFC 9000, section 19.15).
@available(anyAppleOS 27.0, *)
struct QUICNewConnectionIDFrame: Equatable, Sendable {
    var sequenceNumber: UInt64
    var retirePriorTo: UInt64

    /// The new connection ID, of 1 to 20 bytes.
    var connectionID: QUICConnectionID

    var statelessResetToken: QUICStatelessResetToken

    init(
        sequenceNumber: UInt64,
        retirePriorTo: UInt64,
        connectionID: QUICConnectionID,
        statelessResetToken: QUICStatelessResetToken
    ) {
        self.sequenceNumber = sequenceNumber
        self.retirePriorTo = retirePriorTo
        self.connectionID = connectionID
        self.statelessResetToken = statelessResetToken
    }
}

/// The payload of a CONNECTION_CLOSE frame (RFC 9000, section 19.19).
@available(anyAppleOS 27.0, *)
struct QUICConnectionCloseFrame: Equatable, Sendable {
    /// The reason of the close.
    enum Error: Equatable, Sendable {
        /// An error of the transport (type 0x1c), with the type of the frame that caused it, or 0 if unknown.
        case transport(QUICTransportErrorCode, frameType: UInt64)

        /// An error of the application (type 0x1d).
        case application(UInt64)
    }

    var error: Error

    /// The reason in UTF-8, for diagnostics.
    var reasonPhrase: [UInt8]

    init(error: Error, reasonPhrase: [UInt8] = []) {
        self.error = error
        self.reasonPhrase = reasonPhrase
    }
}

// MARK: - Properties

@available(anyAppleOS 27.0, *)
extension QUICFrame {
    /// The frame type on the wire.
    var frameType: UInt64 {
        switch self {
        case .padding: 0x00
        case .ping: 0x01
        case .ack(let ack): ack.ecnCounts == nil ? 0x02 : 0x03
        case .resetStream: 0x04
        case .stopSending: 0x05
        case .crypto: 0x06
        case .newToken: 0x07
        case .stream(let stream): 0x08 | (stream.offset != 0 ? 0x04 : 0) | 0x02 | (stream.fin ? 0x01 : 0)
        case .maxData: 0x10
        case .maxStreamData: 0x11
        case .maxStreams(let bidirectional, _): bidirectional ? 0x12 : 0x13
        case .dataBlocked: 0x14
        case .streamDataBlocked: 0x15
        case .streamsBlocked(let bidirectional, _): bidirectional ? 0x16 : 0x17
        case .newConnectionID: 0x18
        case .retireConnectionID: 0x19
        case .pathChallenge: 0x1a
        case .pathResponse: 0x1b
        case .connectionClose(let close):
            switch close.error {
            case .transport: 0x1c
            case .application: 0x1d
            }
        case .handshakeDone: 0x1e
        }
    }

    /// Whether a packet with this frame has to be acknowledged (RFC 9002, section 2).
    ///
    /// All frames except ACK, PADDING and CONNECTION_CLOSE are ack-eliciting.
    var isAckEliciting: Bool {
        switch self {
        case .ack, .padding, .connectionClose: false
        default: true
        }
    }

    /// Whether the frame may be sent in a packet of the given type (RFC 9000, section 12.4, table 3).
    func isAllowed(in packetType: QUICPacketType) -> Bool {
        switch packetType {
        case .retry:
            return false
        case .initial, .handshake:
            switch self {
            case .padding, .ping, .ack, .crypto:
                return true
            case .connectionClose(let close):
                if case .transport = close.error { return true }
                return false
            default:
                return false
            }
        case .zeroRTT:
            switch self {
            case .ack, .crypto, .newToken, .pathResponse, .handshakeDone:
                return false
            default:
                return true
            }
        case .oneRTT:
            return true
        }
    }
}

// MARK: - Parsing

@available(anyAppleOS 27.0, *)
extension QUICFrame {
    /// Parses one frame.
    ///
    /// - Throws: A `ParsingError` if the bytes end within the frame, or with a ``QUICFrameError`` as its user error
    ///   if the frame is invalid. Both are frame encoding errors of the connection.
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        let type = try QUICVariableLengthInteger.decode(parsing: &input)
        switch type {
        case 0x00:
            // Padding comes in runs, so read the run at once.
            let bytes = input.bytes
            var count = 0
            while count < bytes.byteCount && bytes.unsafeLoad(fromByteOffset: count, as: UInt8.self) == 0 {
                count += 1
            }
            try input.seek(toRelativeOffset: count)
            self = .padding(count: count + 1)

        case 0x01:
            self = .ping

        case 0x02, 0x03:
            self = .ack(try QUICAckFrame(parsing: &input, withECN: type == 0x03))

        case 0x04:
            let streamID = try Self.varint(&input)
            let code = try Self.varint(&input)
            let finalSize = try Self.varint(&input)
            self = .resetStream(streamID: streamID, applicationErrorCode: code, finalSize: finalSize)

        case 0x05:
            let streamID = try Self.varint(&input)
            let code = try Self.varint(&input)
            self = .stopSending(streamID: streamID, applicationErrorCode: code)

        case 0x06:
            let offset = try Self.varint(&input)
            let length = try Self.varint(&input)
            guard offset <= QUICVariableLengthInteger.maximum - length else {
                throw Self.invalid(type, "The crypto data ends beyond 2^62 - 1")
            }
            self = .crypto(offset: offset, data: try Self.bytes(&input, count: length))

        case 0x07:
            let length = try Self.varint(&input)
            guard length > 0 else {
                throw Self.invalid(type, "Empty token")
            }
            self = .newToken(try Self.bytes(&input, count: length))

        case 0x08...0x0f:
            let streamID = try Self.varint(&input)
            let offset = (type & 0x04) != 0 ? try Self.varint(&input) : 0
            let data: [UInt8]
            if (type & 0x02) != 0 {
                data = try Self.bytes(&input, count: try Self.varint(&input))
            } else {
                data = [UInt8](parsingRemainingBytes: &input)
            }
            guard offset <= QUICVariableLengthInteger.maximum - UInt64(data.count) else {
                throw Self.invalid(type, "The stream data ends beyond 2^62 - 1")
            }
            self = .stream(QUICStreamFrame(streamID: streamID, offset: offset, data: data, fin: (type & 0x01) != 0))

        case 0x10:
            self = .maxData(try Self.varint(&input))

        case 0x11:
            let streamID = try Self.varint(&input)
            self = .maxStreamData(streamID: streamID, maximum: try Self.varint(&input))

        case 0x12, 0x13:
            let maximum = try Self.varint(&input)
            guard maximum <= 1 << 60 else {
                throw Self.invalid(type, "More than 2^60 streams")
            }
            self = .maxStreams(bidirectional: type == 0x12, maximum: maximum)

        case 0x14:
            self = .dataBlocked(limit: try Self.varint(&input))

        case 0x15:
            let streamID = try Self.varint(&input)
            self = .streamDataBlocked(streamID: streamID, limit: try Self.varint(&input))

        case 0x16, 0x17:
            let limit = try Self.varint(&input)
            guard limit <= 1 << 60 else {
                throw Self.invalid(type, "More than 2^60 streams")
            }
            self = .streamsBlocked(bidirectional: type == 0x16, limit: limit)

        case 0x18:
            let sequenceNumber = try Self.varint(&input)
            let retirePriorTo = try Self.varint(&input)
            guard retirePriorTo <= sequenceNumber else {
                throw Self.invalid(type, "Retire Prior To is larger than the sequence number")
            }
            let length = Int(try UInt8(parsing: &input))
            guard (1...QUICConnectionID.maximumLength).contains(length) else {
                throw ParsingError(userError: QUICFrameError.invalidConnectionIDLength(length))
            }
            let connectionID = try QUICConnectionID(parsing: &input, length: length)
            let token = try QUICStatelessResetToken(parsing: &input)
            self = .newConnectionID(
                QUICNewConnectionIDFrame(
                    sequenceNumber: sequenceNumber,
                    retirePriorTo: retirePriorTo,
                    connectionID: connectionID,
                    statelessResetToken: token
                )
            )

        case 0x19:
            self = .retireConnectionID(sequenceNumber: try Self.varint(&input))

        case 0x1a:
            self = .pathChallenge(try UInt64(parsingBigEndian: &input))

        case 0x1b:
            self = .pathResponse(try UInt64(parsingBigEndian: &input))

        case 0x1c, 0x1d:
            let code = try Self.varint(&input)
            let error: QUICConnectionCloseFrame.Error
            if type == 0x1c {
                error = .transport(QUICTransportErrorCode(rawValue: code), frameType: try Self.varint(&input))
            } else {
                error = .application(code)
            }
            let reasonPhrase = try Self.bytes(&input, count: try Self.varint(&input))
            self = .connectionClose(QUICConnectionCloseFrame(error: error, reasonPhrase: reasonPhrase))

        case 0x1e:
            self = .handshakeDone

        default:
            throw ParsingError(userError: QUICFrameError.unknownFrameType(type))
        }
    }

    private static func varint(_ input: inout ParserSpan) throws(ParsingError) -> UInt64 {
        try QUICVariableLengthInteger.decode(parsing: &input)
    }

    private static func bytes(_ input: inout ParserSpan, count: UInt64) throws(ParsingError) -> [UInt8] {
        // A count beyond the remaining bytes fails before anything is allocated.
        guard count <= UInt64(input.count) else {
            throw ParsingError(userError: QUICFrameError.invalidFrame(type: 0, reason: "Length beyond the packet"))
        }
        return try [UInt8](parsing: &input, byteCount: Int(count))
    }

    private static func invalid(_ type: UInt64, _ reason: String) -> ParsingError {
        ParsingError(userError: QUICFrameError.invalidFrame(type: type, reason: reason))
    }
}

@available(anyAppleOS 27.0, *)
extension QUICAckFrame {
    init(parsing input: inout ParserSpan, withECN: Bool) throws(ParsingError) {
        let type: UInt64 = withECN ? 0x03 : 0x02
        self.largestAcknowledged = try QUICVariableLengthInteger.decode(parsing: &input)
        self.ackDelay = try QUICVariableLengthInteger.decode(parsing: &input)
        let rangeCount = try QUICVariableLengthInteger.decode(parsing: &input)
        self.firstRange = try QUICVariableLengthInteger.decode(parsing: &input)
        guard self.firstRange <= self.largestAcknowledged else {
            throw ParsingError(
                userError: QUICFrameError.invalidFrame(type: type, reason: "The first ACK range goes below 0")
            )
        }
        // Every range takes at least 2 bytes, which bounds the count before anything is allocated.
        guard rangeCount <= UInt64(input.count / 2) else {
            throw ParsingError(userError: QUICFrameError.invalidFrame(type: type, reason: "Too many ACK ranges"))
        }
        var smallest = self.largestAcknowledged - self.firstRange
        var ranges: [Range] = []
        ranges.reserveCapacity(Int(rangeCount))
        for _ in 0..<rangeCount {
            let gap = try QUICVariableLengthInteger.decode(parsing: &input)
            let length = try QUICVariableLengthInteger.decode(parsing: &input)
            // The largest packet of the range is smallest - gap - 2, its smallest that minus length.
            guard smallest >= 2, gap <= smallest - 2, length <= smallest - 2 - gap else {
                throw ParsingError(
                    userError: QUICFrameError.invalidFrame(type: type, reason: "An ACK range goes below 0")
                )
            }
            smallest = smallest - 2 - gap - length
            ranges.append(Range(gap: gap, length: length))
        }
        self.ranges = ranges
        if withECN {
            self.ecnCounts = ECNCounts(
                ect0: try QUICVariableLengthInteger.decode(parsing: &input),
                ect1: try QUICVariableLengthInteger.decode(parsing: &input),
                ce: try QUICVariableLengthInteger.decode(parsing: &input)
            )
        } else {
            self.ecnCounts = nil
        }
    }
}

// MARK: - Encoding

@available(anyAppleOS 27.0, *)
extension QUICFrame {
    /// The number of bytes of ``encode(into:omittingStreamLength:)``.
    ///
    /// - Parameter omittingStreamLength: Whether a STREAM frame is encoded without its length, which is only valid
    ///   for the last frame of a packet. Other frames ignore it.
    func encodedLength(omittingStreamLength: Bool = false) -> Int {
        typealias V = QUICVariableLengthInteger
        switch self {
        case .padding(let count):
            return count
        case .ping, .handshakeDone:
            return 1
        case .ack(let ack):
            var length = 1 + V.encodedLength(ack.largestAcknowledged) + V.encodedLength(ack.ackDelay)
            length += V.encodedLength(UInt64(ack.ranges.count)) + V.encodedLength(ack.firstRange)
            for range in ack.ranges {
                length += V.encodedLength(range.gap) + V.encodedLength(range.length)
            }
            if let ecn = ack.ecnCounts {
                length += V.encodedLength(ecn.ect0) + V.encodedLength(ecn.ect1) + V.encodedLength(ecn.ce)
            }
            return length
        case .resetStream(let streamID, let code, let finalSize):
            return 1 + V.encodedLength(streamID) + V.encodedLength(code) + V.encodedLength(finalSize)
        case .stopSending(let streamID, let code):
            return 1 + V.encodedLength(streamID) + V.encodedLength(code)
        case .crypto(let offset, let data):
            return 1 + V.encodedLength(offset) + V.encodedLength(UInt64(data.count)) + data.count
        case .newToken(let token):
            return 1 + V.encodedLength(UInt64(token.count)) + token.count
        case .stream(let stream):
            var length = 1 + V.encodedLength(stream.streamID) + stream.data.count
            if stream.offset != 0 {
                length += V.encodedLength(stream.offset)
            }
            if !omittingStreamLength {
                length += V.encodedLength(UInt64(stream.data.count))
            }
            return length
        case .maxData(let value), .dataBlocked(let value), .retireConnectionID(let value):
            return 1 + V.encodedLength(value)
        case .maxStreams(_, let value), .streamsBlocked(_, let value):
            return 1 + V.encodedLength(value)
        case .maxStreamData(let streamID, let value), .streamDataBlocked(let streamID, let value):
            return 1 + V.encodedLength(streamID) + V.encodedLength(value)
        case .newConnectionID(let frame):
            return 1 + V.encodedLength(frame.sequenceNumber) + V.encodedLength(frame.retirePriorTo) + 1
                + frame.connectionID.length + 16
        case .pathChallenge, .pathResponse:
            return 1 + 8
        case .connectionClose(let close):
            var length = 1 + V.encodedLength(UInt64(close.reasonPhrase.count)) + close.reasonPhrase.count
            switch close.error {
            case .transport(let code, let frameType):
                length += V.encodedLength(code.rawValue) + V.encodedLength(frameType)
            case .application(let code):
                length += V.encodedLength(code)
            }
            return length
        }
    }

    /// Appends the frame.
    ///
    /// - Parameters:
    ///   - output: Receives exactly ``encodedLength(omittingStreamLength:)`` bytes.
    ///   - omittingStreamLength: Whether a STREAM frame is encoded without its length, so that its data extends to the
    ///     end of the packet. Only valid for the last frame of a packet. Other frames ignore it.
    func encode(into output: inout OutputSpan<UInt8>, omittingStreamLength: Bool = false) {
        typealias V = QUICVariableLengthInteger
        switch self {
        case .padding(let count):
            for _ in 0..<count {
                output.append(0)
            }
        case .ping, .handshakeDone:
            output.append(UInt8(self.frameType))
        case .ack(let ack):
            output.append(UInt8(self.frameType))
            V.encode(ack.largestAcknowledged, into: &output)
            V.encode(ack.ackDelay, into: &output)
            V.encode(UInt64(ack.ranges.count), into: &output)
            V.encode(ack.firstRange, into: &output)
            for range in ack.ranges {
                V.encode(range.gap, into: &output)
                V.encode(range.length, into: &output)
            }
            if let ecn = ack.ecnCounts {
                V.encode(ecn.ect0, into: &output)
                V.encode(ecn.ect1, into: &output)
                V.encode(ecn.ce, into: &output)
            }
        case .resetStream(let streamID, let code, let finalSize):
            output.append(0x04)
            V.encode(streamID, into: &output)
            V.encode(code, into: &output)
            V.encode(finalSize, into: &output)
        case .stopSending(let streamID, let code):
            output.append(0x05)
            V.encode(streamID, into: &output)
            V.encode(code, into: &output)
        case .crypto(let offset, let data):
            output.append(0x06)
            V.encode(offset, into: &output)
            V.encode(UInt64(data.count), into: &output)
            Self.append(data, to: &output)
        case .newToken(let token):
            output.append(0x07)
            V.encode(UInt64(token.count), into: &output)
            Self.append(token, to: &output)
        case .stream(let stream):
            var type: UInt8 = 0x08
            if stream.offset != 0 { type |= 0x04 }
            if !omittingStreamLength { type |= 0x02 }
            if stream.fin { type |= 0x01 }
            output.append(type)
            V.encode(stream.streamID, into: &output)
            if stream.offset != 0 {
                V.encode(stream.offset, into: &output)
            }
            if !omittingStreamLength {
                V.encode(UInt64(stream.data.count), into: &output)
            }
            Self.append(stream.data, to: &output)
        case .maxData(let value), .dataBlocked(let value), .retireConnectionID(let value):
            output.append(UInt8(self.frameType))
            V.encode(value, into: &output)
        case .maxStreams(_, let value), .streamsBlocked(_, let value):
            output.append(UInt8(self.frameType))
            V.encode(value, into: &output)
        case .maxStreamData(let streamID, let value), .streamDataBlocked(let streamID, let value):
            output.append(UInt8(self.frameType))
            V.encode(streamID, into: &output)
            V.encode(value, into: &output)
        case .newConnectionID(let frame):
            output.append(0x18)
            V.encode(frame.sequenceNumber, into: &output)
            V.encode(frame.retirePriorTo, into: &output)
            output.append(UInt8(frame.connectionID.length))
            frame.connectionID.encode(into: &output)
            frame.statelessResetToken.encode(into: &output)
        case .pathChallenge(let data), .pathResponse(let data):
            output.append(UInt8(self.frameType))
            for shift in stride(from: 56, through: 0, by: -8) {
                output.append(UInt8(truncatingIfNeeded: data >> UInt64(shift)))
            }
        case .connectionClose(let close):
            output.append(UInt8(self.frameType))
            switch close.error {
            case .transport(let code, let frameType):
                V.encode(code.rawValue, into: &output)
                V.encode(frameType, into: &output)
            case .application(let code):
                V.encode(code, into: &output)
            }
            V.encode(UInt64(close.reasonPhrase.count), into: &output)
            Self.append(close.reasonPhrase, to: &output)
        }
    }

    private static func append(_ bytes: [UInt8], to output: inout OutputSpan<UInt8>) {
        output.appendQUICBytes(bytes)
    }
}
