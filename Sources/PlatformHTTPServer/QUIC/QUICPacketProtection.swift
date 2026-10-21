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

import Crypto
import CryptoExtras

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The AEAD and header protection algorithms of a QUIC packet, given by the TLS cipher suite (RFC 9001, section 5).
@available(anyAppleOS 27.0, *)
enum QUICCipherSuite: Hashable, Sendable {
    /// TLS_AES_128_GCM_SHA256: AEAD_AES_128_GCM with AES-128 header protection. Initial packets always use it.
    case aes128GCMSHA256

    /// TLS_CHACHA20_POLY1305_SHA256: AEAD_CHACHA20_POLY1305 with ChaCha20 header protection.
    case chacha20Poly1305SHA256

    /// The suite of a TLS cipher suite code, or `nil` if QUIC does not support it here.
    init?(tlsCipherSuite: UInt16) {
        switch tlsCipherSuite {
        case 0x1301: self = .aes128GCMSHA256
        case 0x1303: self = .chacha20Poly1305SHA256
        default: return nil
        }
    }

    /// The length of the AEAD key and of the header protection key.
    var keyLength: Int {
        switch self {
        case .aes128GCMSHA256: 16
        case .chacha20Poly1305SHA256: 32
        }
    }
}

/// The key derivation of QUIC (RFC 9001, section 5).
@available(anyAppleOS 27.0, *)
enum QUICKeyDerivation {
    /// The salt of the Initial secrets of QUIC version 1 (RFC 9001, section 5.2).
    static let initialSalt: [UInt8] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb,
        0x7f, 0x0a,
    ]

    /// HKDF-Expand-Label of TLS 1.3 with SHA-256 and an empty context (RFC 8446, section 7.1).
    static func expandLabel(secret: SymmetricKey, label: String, length: Int) -> SymmetricKey {
        let fullLabel = Array("tls13 \(label)".utf8)
        var info: [UInt8] = []
        info.reserveCapacity(4 + fullLabel.count)
        info.append(UInt8(truncatingIfNeeded: length >> 8))
        info.append(UInt8(truncatingIfNeeded: length))
        info.append(UInt8(fullLabel.count))
        info.append(contentsOf: fullLabel)
        info.append(0)
        return HKDF<SHA256>.expand(pseudoRandomKey: secret, info: info, outputByteCount: length)
    }

    /// The secrets of the Initial packets, derived from the Destination Connection ID of the first Initial packet of
    /// the client (RFC 9001, section 5.2).
    static func initialSecrets(
        destinationConnectionID: QUICConnectionID
    ) -> (initial: SymmetricKey, client: SymmetricKey, server: SymmetricKey) {
        let prk = HKDF<SHA256>.extract(
            inputKeyMaterial: SymmetricKey(data: destinationConnectionID.bytes),
            salt: Self.initialSalt
        )
        let initial = SymmetricKey(data: Array(prk))
        return (
            initial,
            Self.expandLabel(secret: initial, label: "client in", length: 32),
            Self.expandLabel(secret: initial, label: "server in", length: 32)
        )
    }
}

/// The header of a packet after header protection was removed.
@available(anyAppleOS 27.0, *)
struct QUICUnprotectedHeader: Equatable, Sendable {
    /// The first byte without protection, with the packet number length and, in short headers, the key phase.
    var firstByte: UInt8

    /// The full packet number.
    var packetNumber: UInt64

    /// The number of bytes of the packet number, 1 to 4.
    var packetNumberLength: Int

    /// The number of bytes from the start of the packet to the end of the packet number, the associated data of
    /// the AEAD.
    var headerLength: Int

    /// The key phase bit of a short header packet.
    var keyPhase: Bool {
        self.firstByte & 0x80 == 0 && self.firstByte & 0x04 != 0
    }

    /// The reserved bits, which have to be 0 once the packet is authenticated (RFC 9000, section 17).
    var reservedBits: UInt8 {
        self.firstByte & 0x80 != 0 ? self.firstByte & 0x0c : self.firstByte & 0x18
    }
}

/// The keys that protect the packets of one direction at one encryption level (RFC 9001, section 5).
///
/// A packet is protected in place. The sender writes the header with the plain packet number, the plaintext
/// payload, and ``tagLength`` bytes of space for the tag, then calls ``seal(packet:packetNumberOffset:packetNumberLength:packetNumber:)``.
/// The receiver calls ``open(packet:packetNumberOffset:largestReceived:)`` on the bytes of a ``QUICProtectedPacket``.
@available(anyAppleOS 27.0, *)
struct QUICPacketKeys: Sendable {
    /// The length of the authentication tag of both AEADs.
    static var tagLength: Int { 16 }

    /// The number of bytes that header protection samples.
    static var sampleLength: Int { 16 }

    let cipherSuite: QUICCipherSuite

    /// The traffic secret that the keys are derived from.
    let secret: SymmetricKey

    let key: SymmetricKey
    let iv: [UInt8]
    let headerProtectionKey: SymmetricKey

    /// Derives the packet keys from a traffic secret ("quic key", "quic iv" and "quic hp", section 5.1).
    init(secret: SymmetricKey, cipherSuite: QUICCipherSuite) {
        let headerProtectionKey = QUICKeyDerivation.expandLabel(
            secret: secret,
            label: "quic hp",
            length: cipherSuite.keyLength
        )
        self.init(secret: secret, cipherSuite: cipherSuite, headerProtectionKey: headerProtectionKey)
    }

    /// Derives the packet keys from the bytes of a TLS traffic secret.
    init(secret: [UInt8], cipherSuite: QUICCipherSuite) {
        self.init(secret: SymmetricKey(data: secret), cipherSuite: cipherSuite)
    }

    private init(secret: SymmetricKey, cipherSuite: QUICCipherSuite, headerProtectionKey: SymmetricKey) {
        self.cipherSuite = cipherSuite
        self.secret = secret
        self.key = QUICKeyDerivation.expandLabel(secret: secret, label: "quic key", length: cipherSuite.keyLength)
        self.iv = QUICKeyDerivation.expandLabel(secret: secret, label: "quic iv", length: 12).withUnsafeBytes {
            Array($0)
        }
        self.headerProtectionKey = headerProtectionKey
    }

    /// The keys of the Initial packets of both sides (section 5.2).
    static func initial(destinationConnectionID: QUICConnectionID) -> (client: QUICPacketKeys, server: QUICPacketKeys) {
        let secrets = QUICKeyDerivation.initialSecrets(destinationConnectionID: destinationConnectionID)
        return (
            QUICPacketKeys(secret: secrets.client, cipherSuite: .aes128GCMSHA256),
            QUICPacketKeys(secret: secrets.server, cipherSuite: .aes128GCMSHA256)
        )
    }

    /// The keys after a key update ("quic ku", section 6.1). The header protection key does not change.
    func nextGeneration() -> QUICPacketKeys {
        let secret = QUICKeyDerivation.expandLabel(secret: self.secret, label: "quic ku", length: 32)
        return QUICPacketKeys(
            secret: secret,
            cipherSuite: self.cipherSuite,
            headerProtectionKey: self.headerProtectionKey
        )
    }

    // MARK: - Sealing

    /// Encrypts a packet in place and applies header protection.
    ///
    /// - Parameters:
    ///   - packet: The whole packet: the header with the unprotected first byte and packet number, the plaintext
    ///     payload, and ``tagLength`` bytes at the end that receive the tag.
    ///   - packetNumberOffset: The offset of the packet number in the packet.
    ///   - packetNumberLength: The number of bytes of the packet number, 1 to 4.
    ///   - packetNumber: The full packet number.
    /// - Throws: ``QUICPacketError/sampleTooShort`` if the packet is too short for the sample of header protection:
    ///   the packet number and the payload need at least 4 bytes together.
    func seal(
        packet: inout MutableSpan<UInt8>,
        packetNumberOffset: Int,
        packetNumberLength: Int,
        packetNumber: UInt64
    ) throws {
        let headerLength = packetNumberOffset + packetNumberLength
        let sampleOffset = packetNumberOffset + 4
        guard sampleOffset + Self.sampleLength <= packet.count, headerLength + Self.tagLength <= packet.count else {
            throw QUICPacketError.sampleTooShort
        }
        try packet.withUnsafeMutableBufferPointer { buffer in
            let bytes = UnsafeMutableRawBufferPointer(buffer)
            let aad = UnsafeRawBufferPointer(rebasing: bytes[0..<headerLength])
            let message = UnsafeMutableRawBufferPointer(rebasing: bytes[headerLength..<(bytes.count - Self.tagLength)])
            let tag = UnsafeMutableRawBufferPointer(rebasing: bytes[(bytes.count - Self.tagLength)...])
            try self.sealPayload(message, tag: tag, aad: aad, packetNumber: packetNumber)

            let mask = try self.headerProtectionMask(
                sample: UnsafeRawBufferPointer(rebasing: bytes[sampleOffset..<(sampleOffset + Self.sampleLength)])
            )
            bytes[0] ^= mask.0 & (bytes[0] & 0x80 != 0 ? 0x0f : 0x1f)
            Self.xorPacketNumber(bytes, offset: packetNumberOffset, length: packetNumberLength, mask: mask)
        }
    }

    // MARK: - Opening

    /// Removes header protection and decrypts a packet in place.
    ///
    /// - Parameters:
    ///   - packet: The bytes of the packet, see ``QUICProtectedPacket/range``.
    ///   - packetNumberOffset: ``QUICProtectedPacket/packetNumberOffset``.
    ///   - largestReceived: The largest packet number of the packet number space that was received and decrypted.
    /// - Returns: The header and the range of the plaintext payload in `packet`.
    /// - Throws: ``QUICPacketError/decryptionFailed`` if the packet is not authentic, which the receiver drops.
    func open(
        packet: inout MutableSpan<UInt8>,
        packetNumberOffset: Int,
        largestReceived: UInt64?
    ) throws -> (header: QUICUnprotectedHeader, payload: Range<Int>) {
        let header = try self.removeHeaderProtection(
            packet: &packet,
            packetNumberOffset: packetNumberOffset,
            largestReceived: largestReceived
        )
        let payload = try self.decryptPayload(packet: &packet, header: header)
        return (header, payload)
    }

    /// Removes header protection, the first step of ``open(packet:packetNumberOffset:largestReceived:)``.
    ///
    /// A 1-RTT receiver uses it to learn the key phase, then decrypts with the keys of that phase. The header
    /// protection key is the same for all key phases.
    func removeHeaderProtection(
        packet: inout MutableSpan<UInt8>,
        packetNumberOffset: Int,
        largestReceived: UInt64?
    ) throws -> QUICUnprotectedHeader {
        let sampleOffset = packetNumberOffset + 4
        guard sampleOffset + Self.sampleLength <= packet.count else {
            throw QUICPacketError.sampleTooShort
        }
        return try packet.withUnsafeMutableBufferPointer { buffer in
            let bytes = UnsafeMutableRawBufferPointer(buffer)
            let mask = try self.headerProtectionMask(
                sample: UnsafeRawBufferPointer(rebasing: bytes[sampleOffset..<(sampleOffset + Self.sampleLength)])
            )
            bytes[0] ^= mask.0 & (bytes[0] & 0x80 != 0 ? 0x0f : 0x1f)
            let length = Int(bytes[0] & 0x03) + 1
            Self.xorPacketNumber(bytes, offset: packetNumberOffset, length: length, mask: mask)
            var truncated: UInt64 = 0
            for index in 0..<length {
                truncated = truncated << 8 | UInt64(bytes[packetNumberOffset + index])
            }
            let headerLength = packetNumberOffset + length
            guard headerLength + Self.tagLength <= bytes.count else {
                throw QUICPacketError.packetTooShort
            }
            return QUICUnprotectedHeader(
                firstByte: bytes[0],
                packetNumber: QUICPacketNumber.decode(
                    truncated: truncated,
                    length: length,
                    largestReceived: largestReceived
                ),
                packetNumberLength: length,
                headerLength: headerLength
            )
        }
    }

    /// Decrypts the payload of a packet whose header protection was removed.
    ///
    /// - Returns: The range of the plaintext payload in `packet`.
    func decryptPayload(packet: inout MutableSpan<UInt8>, header: QUICUnprotectedHeader) throws -> Range<Int> {
        let end = packet.count - Self.tagLength
        guard header.headerLength <= end else {
            throw QUICPacketError.packetTooShort
        }
        try packet.withUnsafeMutableBufferPointer { buffer in
            let bytes = UnsafeMutableRawBufferPointer(buffer)
            do {
                try self.openPayload(
                    UnsafeMutableRawBufferPointer(rebasing: bytes[header.headerLength..<end]),
                    tag: UnsafeRawBufferPointer(rebasing: bytes[end...]),
                    aad: UnsafeRawBufferPointer(rebasing: bytes[0..<header.headerLength]),
                    packetNumber: header.packetNumber
                )
            } catch {
                throw QUICPacketError.decryptionFailed
            }
        }
        return header.headerLength..<end
    }

    // MARK: - Primitives

    /// The nonce of a packet: the IV with the packet number XORed into its last bytes (section 5.3).
    private func nonce(packetNumber: UInt64) -> [UInt8] {
        var nonce = self.iv
        for index in 0..<8 {
            nonce[11 - index] ^= UInt8(truncatingIfNeeded: packetNumber >> UInt64(8 * index))
        }
        return nonce
    }

    private func sealPayload(
        _ message: UnsafeMutableRawBufferPointer,
        tag: UnsafeMutableRawBufferPointer,
        aad: UnsafeRawBufferPointer,
        packetNumber: UInt64
    ) throws {
        var messageSpan = MutableRawSpan(_unsafeBytes: message)
        var tagSpan = OutputRawSpan(buffer: tag, initializedCount: 0)
        let nonce = self.nonce(packetNumber: packetNumber)
        switch self.cipherSuite {
        case .aes128GCMSHA256:
            try AES.GCM.seal(
                inPlace: &messageSpan,
                using: self.key,
                nonce: try AES.GCM.Nonce(data: nonce),
                authenticating: RawSpan(_unsafeBytes: aad),
                tag: &tagSpan
            )
        case .chacha20Poly1305SHA256:
            try ChaChaPoly.seal(
                inPlace: &messageSpan,
                using: self.key,
                nonce: try ChaChaPoly.Nonce(data: nonce),
                authenticating: RawSpan(_unsafeBytes: aad),
                tag: &tagSpan
            )
        }
        precondition(tagSpan.byteCount == Self.tagLength)
    }

    private func openPayload(
        _ message: UnsafeMutableRawBufferPointer,
        tag: UnsafeRawBufferPointer,
        aad: UnsafeRawBufferPointer,
        packetNumber: UInt64
    ) throws {
        var messageSpan = MutableRawSpan(_unsafeBytes: message)
        let nonce = self.nonce(packetNumber: packetNumber)
        switch self.cipherSuite {
        case .aes128GCMSHA256:
            try AES.GCM.open(
                inPlace: &messageSpan,
                using: self.key,
                nonce: try AES.GCM.Nonce(data: nonce),
                authenticating: RawSpan(_unsafeBytes: aad),
                tag: RawSpan(_unsafeBytes: tag)
            )
        case .chacha20Poly1305SHA256:
            try ChaChaPoly.open(
                inPlace: &messageSpan,
                using: self.key,
                nonce: try ChaChaPoly.Nonce(data: nonce),
                authenticating: RawSpan(_unsafeBytes: aad),
                tag: RawSpan(_unsafeBytes: tag)
            )
        }
    }

    /// The 5 byte mask of header protection for a 16 byte sample of the ciphertext (section 5.4).
    func headerProtectionMask(sample: UnsafeRawBufferPointer) throws -> (UInt8, UInt8, UInt8, UInt8, UInt8) {
        precondition(sample.count == Self.sampleLength)
        switch self.cipherSuite {
        case .aes128GCMSHA256:
            var block = [UInt8](sample)
            try AES.permute(&block, key: self.headerProtectionKey)
            return (block[0], block[1], block[2], block[3], block[4])
        case .chacha20Poly1305SHA256:
            let counter = try Insecure.ChaCha20CTR.Counter(data: Array(sample[0..<4]))
            let nonce = try Insecure.ChaCha20CTR.Nonce(data: Array(sample[4..<16]))
            let mask = try Insecure.ChaCha20CTR.encrypt(
                [UInt8](repeating: 0, count: 5),
                using: self.headerProtectionKey,
                counter: counter,
                nonce: nonce
            )
            let bytes = Array(mask)
            return (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4])
        }
    }

    private static func xorPacketNumber(
        _ bytes: UnsafeMutableRawBufferPointer,
        offset: Int,
        length: Int,
        mask: (UInt8, UInt8, UInt8, UInt8, UInt8)
    ) {
        let masks = [mask.1, mask.2, mask.3, mask.4]
        for index in 0..<length {
            bytes[offset + index] ^= masks[index]
        }
    }
}

/// The integrity tag of Retry packets of QUIC version 1 (RFC 9001, section 5.8).
@available(anyAppleOS 27.0, *)
enum QUICRetryIntegrity {
    private static let key: [UInt8] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
    ]
    private static let nonce: [UInt8] = [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb]

    /// The tag of a Retry packet.
    ///
    /// - Parameters:
    ///   - retryPacketWithoutTag: The Retry packet up to the tag.
    ///   - originalDestinationConnectionID: The Destination Connection ID of the Initial packet of the client.
    static func tag(
        retryPacketWithoutTag: [UInt8],
        originalDestinationConnectionID: QUICConnectionID
    ) throws -> [UInt8] {
        var pseudoPacket: [UInt8] = [UInt8(originalDestinationConnectionID.length)]
        pseudoPacket += originalDestinationConnectionID.bytes
        pseudoPacket += retryPacketWithoutTag
        let sealed = try AES.GCM.seal(
            [UInt8](),
            using: SymmetricKey(data: Self.key),
            nonce: try AES.GCM.Nonce(data: Self.nonce),
            authenticating: pseudoPacket
        )
        return Array(sealed.tag)
    }
}
