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

/// The transport parameters that an endpoint declares in the handshake (RFC 9000, section 18).
///
/// Parameters that are absent have their default values. Unknown parameters are ignored when parsing.
@available(anyAppleOS 27.0, *)
struct QUICTransportParameters: Equatable, Sendable {
    /// The destination connection ID of the first Initial packet of the client. Only servers send it.
    var originalDestinationConnectionID: QUICConnectionID? = nil

    /// The idle timeout in milliseconds, 0 for none.
    var maxIdleTimeout: UInt64 = 0

    /// The stateless reset token. Only servers send it.
    var statelessResetToken: QUICStatelessResetToken? = nil

    /// The largest UDP payload that the endpoint is willing to receive.
    var maxUDPPayloadSize: UInt64 = 65527

    var initialMaxData: UInt64 = 0
    var initialMaxStreamDataBidiLocal: UInt64 = 0
    var initialMaxStreamDataBidiRemote: UInt64 = 0
    var initialMaxStreamDataUni: UInt64 = 0
    var initialMaxStreamsBidi: UInt64 = 0
    var initialMaxStreamsUni: UInt64 = 0

    /// The exponent with which the ACK Delay field of ACK frames is scaled.
    var ackDelayExponent: UInt64 = 3

    /// The maximum time in milliseconds that the endpoint delays acknowledgments.
    var maxAckDelay: UInt64 = 25

    var disableActiveMigration: Bool = false

    var activeConnectionIDLimit: UInt64 = 2

    /// The source connection ID of the first Initial packet that the endpoint sent.
    var initialSourceConnectionID: QUICConnectionID? = nil

    /// The source connection ID of the Retry packet. Only servers send it, after a Retry.
    var retrySourceConnectionID: QUICConnectionID? = nil

    init() {}

    private enum ID {
        static var originalDestinationConnectionID: UInt64 { 0x00 }
        static var maxIdleTimeout: UInt64 { 0x01 }
        static var statelessResetToken: UInt64 { 0x02 }
        static var maxUDPPayloadSize: UInt64 { 0x03 }
        static var initialMaxData: UInt64 { 0x04 }
        static var initialMaxStreamDataBidiLocal: UInt64 { 0x05 }
        static var initialMaxStreamDataBidiRemote: UInt64 { 0x06 }
        static var initialMaxStreamDataUni: UInt64 { 0x07 }
        static var initialMaxStreamsBidi: UInt64 { 0x08 }
        static var initialMaxStreamsUni: UInt64 { 0x09 }
        static var ackDelayExponent: UInt64 { 0x0a }
        static var maxAckDelay: UInt64 { 0x0b }
        static var disableActiveMigration: UInt64 { 0x0c }
        static var activeConnectionIDLimit: UInt64 { 0x0e }
        static var initialSourceConnectionID: UInt64 { 0x0f }
        static var retrySourceConnectionID: UInt64 { 0x10 }
    }

    /// Parses the parameters that a peer sent.
    ///
    /// - Throws: ``QUICTransportErrorCode/transportParameterError`` for duplicate, malformed or invalid parameters.
    init(parsing bytes: [UInt8]) throws(QUICTransportParameterError) {
        var seen = Set<UInt64>()
        let raw = bytes.span.bytes
        var input = ParserSpan(raw)
        do throws(ParsingError) {
                while !input.isEmpty {
                    let id = try QUICVariableLengthInteger.decode(parsing: &input)
                    let length = Int(try QUICVariableLengthInteger.decode(parsing: &input))
                    var value = try input.sliceSpan(byteCount: length)
                    guard seen.insert(id).inserted else {
                        throw ParsingError(userError: QUICTransportParameterError(reason: "Duplicate parameter \(id)"))
                    }
                    func integer(_ value: inout ParserSpan) throws(ParsingError) -> UInt64 {
                        let integer = try QUICVariableLengthInteger.decode(parsing: &value)
                        guard value.isEmpty else {
                            throw ParsingError(userError: QUICTransportParameterError(reason: "Parameter \(id) is too long"))
                        }
                        return integer
                    }
                    func connectionID(_ value: inout ParserSpan) throws(ParsingError) -> QUICConnectionID {
                        guard value.count <= QUICConnectionID.maximumLength else {
                            throw ParsingError(userError: QUICTransportParameterError(reason: "Connection ID too long"))
                        }
                        return try QUICConnectionID(parsing: &value, length: value.count)
                    }
                    switch id {
                    case ID.originalDestinationConnectionID:
                        self.originalDestinationConnectionID = try connectionID(&value)
                    case ID.maxIdleTimeout:
                        self.maxIdleTimeout = try integer(&value)
                    case ID.statelessResetToken:
                        guard value.count == 16 else {
                            throw ParsingError(userError: QUICTransportParameterError(reason: "Invalid reset token"))
                        }
                        let high = try UInt64(parsingBigEndian: &value)
                        let low = try UInt64(parsingBigEndian: &value)
                        self.statelessResetToken = QUICStatelessResetToken(high: high, low: low)
                    case ID.maxUDPPayloadSize:
                        self.maxUDPPayloadSize = try integer(&value)
                    case ID.initialMaxData:
                        self.initialMaxData = try integer(&value)
                    case ID.initialMaxStreamDataBidiLocal:
                        self.initialMaxStreamDataBidiLocal = try integer(&value)
                    case ID.initialMaxStreamDataBidiRemote:
                        self.initialMaxStreamDataBidiRemote = try integer(&value)
                    case ID.initialMaxStreamDataUni:
                        self.initialMaxStreamDataUni = try integer(&value)
                    case ID.initialMaxStreamsBidi:
                        self.initialMaxStreamsBidi = try integer(&value)
                    case ID.initialMaxStreamsUni:
                        self.initialMaxStreamsUni = try integer(&value)
                    case ID.ackDelayExponent:
                        self.ackDelayExponent = try integer(&value)
                    case ID.maxAckDelay:
                        self.maxAckDelay = try integer(&value)
                    case ID.disableActiveMigration:
                        guard value.isEmpty else {
                            throw ParsingError(userError: QUICTransportParameterError(reason: "Invalid migration flag"))
                        }
                        self.disableActiveMigration = true
                    case ID.activeConnectionIDLimit:
                        self.activeConnectionIDLimit = try integer(&value)
                    case ID.initialSourceConnectionID:
                        self.initialSourceConnectionID = try connectionID(&value)
                    case ID.retrySourceConnectionID:
                        self.retrySourceConnectionID = try connectionID(&value)
                    default:
                        // Unknown and reserved parameters are ignored (section 18.1). Includes preferred_address,
                        // which a client may ignore.
                        _ = value.extractRemaining()
                    }
                }
        } catch {
            if let error = error.userError as? QUICTransportParameterError {
                throw error
            }
            throw QUICTransportParameterError(reason: "Malformed transport parameters")
        }

        guard self.maxUDPPayloadSize >= 1200 else {
            throw QUICTransportParameterError(reason: "max_udp_payload_size below 1200")
        }
        guard self.ackDelayExponent <= 20 else {
            throw QUICTransportParameterError(reason: "ack_delay_exponent above 20")
        }
        guard self.maxAckDelay < 1 << 14 else {
            throw QUICTransportParameterError(reason: "max_ack_delay of 2^14 or more")
        }
        guard self.activeConnectionIDLimit >= 2 else {
            throw QUICTransportParameterError(reason: "active_connection_id_limit below 2")
        }
        guard self.initialMaxStreamsBidi <= 1 << 60, self.initialMaxStreamsUni <= 1 << 60 else {
            throw QUICTransportParameterError(reason: "Stream limit above 2^60")
        }
    }

    /// The encoded parameters, as sent in the `quic_transport_parameters` TLS extension.
    var encoded: [UInt8] {
        var bytes: [UInt8] = []
        func append(_ value: UInt64) {
            var buffer = [UInt8](repeating: 0, count: 8)
            let count = buffer.withUnsafeMutableBufferPointer { pointer in
                var output = OutputSpan<UInt8>(buffer: pointer, initializedCount: 0)
                QUICVariableLengthInteger.encode(value, into: &output)
                return output.finalize(for: pointer)
            }
            bytes.append(contentsOf: buffer[0..<count])
        }
        func appendInteger(_ id: UInt64, _ value: UInt64) {
            append(id)
            append(UInt64(QUICVariableLengthInteger.encodedLength(value)))
            append(value)
        }
        func appendBytes(_ id: UInt64, _ value: [UInt8]) {
            append(id)
            append(UInt64(value.count))
            bytes.append(contentsOf: value)
        }

        if let id = self.originalDestinationConnectionID {
            appendBytes(ID.originalDestinationConnectionID, id.bytes)
        }
        if self.maxIdleTimeout != 0 {
            appendInteger(ID.maxIdleTimeout, self.maxIdleTimeout)
        }
        if let token = self.statelessResetToken {
            var tokenBytes: [UInt8] = []
            for shift in stride(from: 56, through: 0, by: -8) {
                tokenBytes.append(UInt8(truncatingIfNeeded: token.high >> UInt64(shift)))
            }
            for shift in stride(from: 56, through: 0, by: -8) {
                tokenBytes.append(UInt8(truncatingIfNeeded: token.low >> UInt64(shift)))
            }
            appendBytes(ID.statelessResetToken, tokenBytes)
        }
        if self.maxUDPPayloadSize != 65527 {
            appendInteger(ID.maxUDPPayloadSize, self.maxUDPPayloadSize)
        }
        appendInteger(ID.initialMaxData, self.initialMaxData)
        appendInteger(ID.initialMaxStreamDataBidiLocal, self.initialMaxStreamDataBidiLocal)
        appendInteger(ID.initialMaxStreamDataBidiRemote, self.initialMaxStreamDataBidiRemote)
        appendInteger(ID.initialMaxStreamDataUni, self.initialMaxStreamDataUni)
        appendInteger(ID.initialMaxStreamsBidi, self.initialMaxStreamsBidi)
        appendInteger(ID.initialMaxStreamsUni, self.initialMaxStreamsUni)
        if self.ackDelayExponent != 3 {
            appendInteger(ID.ackDelayExponent, self.ackDelayExponent)
        }
        if self.maxAckDelay != 25 {
            appendInteger(ID.maxAckDelay, self.maxAckDelay)
        }
        if self.disableActiveMigration {
            appendBytes(ID.disableActiveMigration, [])
        }
        if self.activeConnectionIDLimit != 2 {
            appendInteger(ID.activeConnectionIDLimit, self.activeConnectionIDLimit)
        }
        if let id = self.initialSourceConnectionID {
            appendBytes(ID.initialSourceConnectionID, id.bytes)
        }
        if let id = self.retrySourceConnectionID {
            appendBytes(ID.retrySourceConnectionID, id.bytes)
        }
        return bytes
    }
}

/// Transport parameters that violate RFC 9000, which closes the connection with TRANSPORT_PARAMETER_ERROR.
@available(anyAppleOS 27.0, *)
struct QUICTransportParameterError: Error, Hashable, Sendable {
    var reason: String
}
