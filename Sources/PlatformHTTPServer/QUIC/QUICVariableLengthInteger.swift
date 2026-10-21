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

/// The variable-length integer encoding of QUIC (RFC 9000, section 16).
///
/// The two most significant bits of the first byte give the length of the encoding: 1, 2, 4 or 8 bytes, which carry
/// 6, 14, 30 or 62 bits of the value in network byte order.
@available(anyAppleOS 27.0, *)
enum QUICVariableLengthInteger {
    /// The largest value that can be encoded, 2^62 - 1.
    static var maximum: UInt64 { (1 << 62) - 1 }

    /// The number of bytes of the shortest encoding of a value.
    ///
    /// - Precondition: `value` is at most ``maximum``.
    static func encodedLength(_ value: UInt64) -> Int {
        precondition(value <= Self.maximum, "A QUIC variable-length integer has at most 62 bits")
        return switch value {
        case 0..<(1 << 6): 1
        case (1 << 6)..<(1 << 14): 2
        case (1 << 14)..<(1 << 30): 4
        default: 8
        }
    }

    /// The largest value that an encoding of the given length can carry.
    ///
    /// - Parameter length: 1, 2, 4 or 8.
    static func maximum(forLength length: Int) -> UInt64 {
        switch length {
        case 1: (1 << 6) - 1
        case 2: (1 << 14) - 1
        case 4: (1 << 30) - 1
        case 8: Self.maximum
        default: preconditionFailure("Invalid length \(length) of a QUIC variable-length integer")
        }
    }

    /// Appends the shortest encoding of a value.
    static func encode(_ value: UInt64, into output: inout OutputSpan<UInt8>) {
        Self.encode(value, length: Self.encodedLength(value), into: &output)
    }

    /// Appends the encoding of a value with the given length, which can be longer than needed.
    ///
    /// A fixed length lets a packet assembler reserve the space of a length field before it knows the value.
    ///
    /// - Parameters:
    ///   - value: The value, at most ``maximum(forLength:)`` of `length`.
    ///   - length: 1, 2, 4 or 8.
    ///   - output: Receives the encoding.
    static func encode(_ value: UInt64, length: Int, into output: inout OutputSpan<UInt8>) {
        precondition(value <= Self.maximum(forLength: length), "\(value) does not fit into \(length) bytes")
        let prefix: UInt64 =
            switch length {
            case 1: 0
            case 2: 0b01
            case 4: 0b10
            default: 0b11
            }
        let bits = UInt64(length * 8)
        let encoded = value | (prefix << (bits - 2))
        var shift = bits
        while shift > 0 {
            shift -= 8
            output.append(UInt8(truncatingIfNeeded: encoded >> shift))
        }
    }

    /// Writes the encoding of a value with the given length over bytes that were reserved before.
    ///
    /// - Parameters:
    ///   - value: The value, at most ``maximum(forLength:)`` of `length`.
    ///   - length: 1, 2, 4 or 8.
    ///   - bytes: The bytes to write to, starting at `offset`.
    ///   - offset: The index of the first byte of the encoding.
    static func write(_ value: UInt64, length: Int, into bytes: inout MutableSpan<UInt8>, at offset: Int) {
        precondition(value <= Self.maximum(forLength: length), "\(value) does not fit into \(length) bytes")
        let prefix: UInt64 =
            switch length {
            case 1: 0
            case 2: 0b01
            case 4: 0b10
            default: 0b11
            }
        let bits = UInt64(length * 8)
        let encoded = value | (prefix << (bits - 2))
        for index in 0..<length {
            bytes[offset + index] = UInt8(truncatingIfNeeded: encoded >> (bits - 8 * UInt64(index + 1)))
        }
    }

    /// Parses a value in any of the four lengths.
    static func decode(parsing input: inout ParserSpan) throws(ParsingError) -> UInt64 {
        let first = try UInt8(parsing: &input)
        let length = 1 << Int(first >> 6)
        var value = UInt64(first & 0x3f)
        for _ in 1..<length {
            value = value << 8 | UInt64(try UInt8(parsing: &input))
        }
        return value
    }

    /// Parses a value and returns it with the number of bytes of its encoding.
    static func decodeWithLength(parsing input: inout ParserSpan) throws(ParsingError) -> (value: UInt64, length: Int) {
        let start = input.startPosition
        let value = try Self.decode(parsing: &input)
        return (value, input.startPosition - start)
    }
}
