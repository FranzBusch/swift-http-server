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

/// A QUIC connection ID of 0 to 20 bytes (RFC 9000, section 5.1).
///
/// The bytes are stored inline, so that connection IDs can be compared and hashed, for example to route datagrams to
/// their connections, without allocations.
@available(anyAppleOS 27.0, *)
struct QUICConnectionID: Hashable, Sendable, CustomStringConvertible {
    /// The longest connection ID of QUIC version 1.
    static var maximumLength: Int { 20 }

    /// The empty connection ID.
    static var empty: QUICConnectionID { QUICConnectionID(storage: (0, 0, 0), length: 0) }

    // The bytes in network order: the first byte is the most significant byte of the first word.
    private var storage: (UInt64, UInt64, UInt32)

    /// The number of bytes.
    let length: Int

    private init(storage: (UInt64, UInt64, UInt32), length: Int) {
        self.storage = storage
        self.length = length
    }

    /// Creates a connection ID from its bytes.
    ///
    /// - Precondition: There are at most ``maximumLength`` bytes.
    init(_ bytes: some Collection<UInt8>) {
        precondition(bytes.count <= Self.maximumLength, "A connection ID has at most 20 bytes")
        self.storage = (0, 0, 0)
        self.length = bytes.count
        for (index, byte) in bytes.enumerated() {
            self.setByte(byte, at: index)
        }
    }

    /// Creates a connection ID with random bytes.
    static func random(length: Int) -> QUICConnectionID {
        var generator = SystemRandomNumberGenerator()
        return Self.random(length: length, using: &generator)
    }

    /// Creates a connection ID with bytes of the given generator.
    static func random(length: Int, using generator: inout some RandomNumberGenerator) -> QUICConnectionID {
        precondition((0...Self.maximumLength).contains(length), "A connection ID has at most 20 bytes")
        var id = QUICConnectionID(storage: (0, 0, 0), length: length)
        for index in 0..<length {
            id.setByte(UInt8.random(in: .min ... .max, using: &generator), at: index)
        }
        return id
    }

    /// Parses a connection ID of a known length.
    ///
    /// - Throws: If `length` is longer than ``maximumLength`` or there are not enough bytes.
    init(parsing input: inout ParserSpan, length: Int) throws(ParsingError) {
        guard length <= Self.maximumLength else {
            throw ParsingError(userError: QUICFrameError.invalidConnectionIDLength(length))
        }
        var slice = try input.sliceSpan(byteCount: length)
        self.storage = (0, 0, 0)
        self.length = length
        for index in 0..<length {
            self.setByte(try UInt8(parsing: &slice), at: index)
        }
    }

    /// The byte at an index.
    subscript(index: Int) -> UInt8 {
        precondition(index >= 0 && index < self.length, "Index out of range")
        switch index {
        case 0..<8: return UInt8(truncatingIfNeeded: self.storage.0 >> (56 - 8 * UInt64(index)))
        case 8..<16: return UInt8(truncatingIfNeeded: self.storage.1 >> (56 - 8 * UInt64(index - 8)))
        default: return UInt8(truncatingIfNeeded: self.storage.2 >> (24 - 8 * UInt32(index - 16)))
        }
    }

    /// The bytes as an array.
    var bytes: [UInt8] {
        (0..<self.length).map { self[$0] }
    }

    /// Appends the bytes, without a length.
    func encode(into output: inout OutputSpan<UInt8>) {
        for index in 0..<self.length {
            output.append(self[index])
        }
    }

    var description: String {
        var string = ""
        for byte in self.bytes {
            string += byte < 16 ? "0" + String(byte, radix: 16) : String(byte, radix: 16)
        }
        return string
    }

    private mutating func setByte(_ byte: UInt8, at index: Int) {
        switch index {
        case 0..<8: self.storage.0 |= UInt64(byte) << (56 - 8 * UInt64(index))
        case 8..<16: self.storage.1 |= UInt64(byte) << (56 - 8 * UInt64(index - 8))
        default: self.storage.2 |= UInt32(byte) << (24 - 8 * UInt32(index - 16))
        }
    }

    static func == (lhs: QUICConnectionID, rhs: QUICConnectionID) -> Bool {
        lhs.length == rhs.length && lhs.storage.0 == rhs.storage.0 && lhs.storage.1 == rhs.storage.1
            && lhs.storage.2 == rhs.storage.2
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(self.length)
        hasher.combine(self.storage.0)
        hasher.combine(self.storage.1)
        hasher.combine(self.storage.2)
    }
}

/// The 16 byte token that ends a connection without its keys (RFC 9000, section 10.3).
@available(anyAppleOS 27.0, *)
struct QUICStatelessResetToken: Hashable, Sendable {
    /// The first 8 bytes in network order.
    var high: UInt64

    /// The last 8 bytes in network order.
    var low: UInt64

    init(high: UInt64, low: UInt64) {
        self.high = high
        self.low = low
    }

    init(parsing input: inout ParserSpan) throws(ParsingError) {
        self.high = try UInt64(parsingBigEndian: &input)
        self.low = try UInt64(parsingBigEndian: &input)
    }

    func encode(into output: inout OutputSpan<UInt8>) {
        for shift in stride(from: 56, through: 0, by: -8) {
            output.append(UInt8(truncatingIfNeeded: self.high >> UInt64(shift)))
        }
        for shift in stride(from: 56, through: 0, by: -8) {
            output.append(UInt8(truncatingIfNeeded: self.low >> UInt64(shift)))
        }
    }
}
