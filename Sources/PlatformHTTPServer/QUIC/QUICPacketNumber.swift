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

/// The packet numbers of QUIC on the wire (RFC 9000, section 17.1 and appendix A).
///
/// A packet carries only the least significant 1 to 4 bytes of its packet number. The sender chooses enough bytes
/// for the receiver to recover the full number from the largest number that it received so far.
@available(anyAppleOS 27.0, *)
enum QUICPacketNumber {
    /// The largest packet number, 2^62 - 1.
    static var maximum: UInt64 { (1 << 62) - 1 }

    /// The number of bytes to encode a packet number with (appendix A.2).
    ///
    /// - Parameters:
    ///   - packetNumber: The full packet number that is sent.
    ///   - largestAcknowledged: The largest packet number of this packet number space that the peer acknowledged, or
    ///     `nil` if it acknowledged none.
    /// - Returns: 1 to 4.
    static func encodedLength(of packetNumber: UInt64, largestAcknowledged: UInt64?) -> Int {
        let unacknowledged: UInt64 =
            if let largestAcknowledged {
                packetNumber - largestAcknowledged
            } else {
                packetNumber + 1
            }
        // The encoding has to cover twice the unacknowledged range, so one bit more than the range needs.
        for length in 1...3 where unacknowledged < UInt64(1) << UInt64(8 * length - 1) {
            return length
        }
        return 4
    }

    /// The least significant bytes of a packet number that are sent in a packet of the given length.
    static func truncate(_ packetNumber: UInt64, toLength length: Int) -> UInt64 {
        packetNumber & ((UInt64(1) << UInt64(8 * length)) - 1)
    }

    /// Recovers the full packet number from its truncated encoding (appendix A.3).
    ///
    /// - Parameters:
    ///   - truncated: The value in the packet.
    ///   - length: The number of bytes of the encoding, 1 to 4.
    ///   - largestReceived: The largest packet number of the packet number space that was received and decrypted,
    ///     or `nil` if none was.
    static func decode(truncated: UInt64, length: Int, largestReceived: UInt64?) -> UInt64 {
        let expected = largestReceived.map { $0 + 1 } ?? 0
        let window = UInt64(1) << UInt64(8 * length)
        let halfWindow = window / 2
        let candidate = (expected & ~(window - 1)) | truncated
        if expected >= halfWindow, candidate <= expected - halfWindow, candidate < (UInt64(1) << 62) - window {
            return candidate + window
        }
        if candidate > expected + halfWindow, candidate >= window {
            return candidate - window
        }
        return candidate
    }
}
