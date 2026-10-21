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

/// Encodes into a new array of exactly `count` bytes.
@available(anyAppleOS 27.0, *)
func quicEncode(count: Int, _ body: (inout OutputSpan<UInt8>) -> Void) -> [UInt8] {
    let bytes = [UInt8](capacity: count) { output in
        body(&output)
    }
    #expect(bytes.count == count, "The encoding has \(bytes.count) bytes instead of \(count)")
    return bytes
}

/// Parses `bytes` with `body`, which has to consume all of them.
@available(anyAppleOS 27.0, *)
func quicParse<T>(_ bytes: [UInt8], _ body: (inout ParserSpan) throws(ParsingError) -> T) throws -> T {
    try bytes.withParserSpan { input throws(ParsingError) -> T in
        let value = try body(&input)
        let remaining = input.count
        #expect(remaining == 0, "\(remaining) bytes were not parsed")
        return value
    }
}

/// Decodes a hexadecimal string, ignoring white space.
@available(anyAppleOS 27.0, *)
func quicHex(_ string: String) -> [UInt8] {
    let digits = string.unicodeScalars.filter { !$0.properties.isWhitespace }.map { Character($0) }
    precondition(digits.count % 2 == 0)
    var bytes: [UInt8] = []
    bytes.reserveCapacity(digits.count / 2)
    var index = 0
    while index < digits.count {
        bytes.append(UInt8(String(digits[index...index + 1]), radix: 16)!)
        index += 2
    }
    return bytes
}

@Suite
struct QUICVariableLengthIntegerTests {
    /// The samples of RFC 9000, appendix A.1.
    @available(anyAppleOS 27.0, *)
    @Test(arguments: [
        ("c2197c5eff14e88c", UInt64(151_288_809_941_952_652)),
        ("9d7f3e7d", UInt64(494_878_333)),
        ("7bbd", UInt64(15293)),
        ("25", UInt64(37)),
        ("4025", UInt64(37)),
    ])
    func decodesTheSamplesOfTheRFC(hex: String, value: UInt64) throws {
        let decoded = try quicParse(quicHex(hex)) { input throws(ParsingError) in
            try QUICVariableLengthInteger.decode(parsing: &input)
        }
        #expect(decoded == value)
    }

    @available(anyAppleOS 27.0, *)
    @Test(arguments: [
        (UInt64(0), 1), (UInt64(63), 1), (UInt64(64), 2), (UInt64(16383), 2), (UInt64(16384), 4),
        (UInt64((1 << 30) - 1), 4), (UInt64(1 << 30), 8), (UInt64((1 << 62) - 1), 8),
    ])
    func encodesWithTheShortestLength(value: UInt64, length: Int) throws {
        #expect(QUICVariableLengthInteger.encodedLength(value) == length)
        let bytes = quicEncode(count: length) { QUICVariableLengthInteger.encode(value, into: &$0) }
        let decoded = try quicParse(bytes) { input throws(ParsingError) in
            try QUICVariableLengthInteger.decodeWithLength(parsing: &input)
        }
        #expect(decoded.value == value)
        #expect(decoded.length == length)
    }

    @available(anyAppleOS 27.0, *)
    @Test func encodesWithAForcedLength() throws {
        let bytes = quicEncode(count: 2) { QUICVariableLengthInteger.encode(37, length: 2, into: &$0) }
        #expect(bytes == [0x40, 0x25])
        var patched = [UInt8](repeating: 0, count: 4)
        var span = patched.mutableSpan
        QUICVariableLengthInteger.write(494_878_333, length: 4, into: &span, at: 0)
        _ = consume span
        #expect(patched == quicHex("9d7f3e7d"))
    }

    @available(anyAppleOS 27.0, *)
    @Test func truncatedEncodingsThrow() {
        let bytes = quicHex("c2197c5eff14e88c")
        for count in 0..<bytes.count {
            #expect(throws: ParsingError.self) {
                try Array(bytes.prefix(count)).withParserSpan { input throws(ParsingError) in
                    _ = try QUICVariableLengthInteger.decode(parsing: &input)
                }
            }
        }
    }
}
