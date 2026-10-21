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
import Crypto
import Testing

@testable import PlatformHTTPServer

/// The samples of packet protection of RFC 9001, appendix A.
@Suite
struct QUICPacketProtectionTests {
    @available(anyAppleOS 27.0, *)
    private static var clientDestinationConnectionID: QUICConnectionID {
        QUICConnectionID(quicHex("8394c8f03e515708"))
    }

    private static func bytes(of key: SymmetricKey) -> [UInt8] {
        key.withUnsafeBytes { Array($0) }
    }

    // MARK: - A.1

    @available(anyAppleOS 27.0, *)
    @Test func initialKeys() {
        let secrets = QUICKeyDerivation.initialSecrets(destinationConnectionID: Self.clientDestinationConnectionID)
        #expect(Self.bytes(of: secrets.initial) == quicHex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"))
        #expect(Self.bytes(of: secrets.client) == quicHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"))
        #expect(Self.bytes(of: secrets.server) == quicHex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"))

        let keys = QUICPacketKeys.initial(destinationConnectionID: Self.clientDestinationConnectionID)
        #expect(Self.bytes(of: keys.client.key) == quicHex("1f369613dd76d5467730efcbe3b1a22d"))
        #expect(keys.client.iv == quicHex("fa044b2f42a3fd3b46fb255c"))
        #expect(Self.bytes(of: keys.client.headerProtectionKey) == quicHex("9f50449e04a0e810283a1e9933adedd2"))
        #expect(Self.bytes(of: keys.server.key) == quicHex("cf3a5331653c364c88f0f379b6067e37"))
        #expect(keys.server.iv == quicHex("0ac1493ca1905853b0bba03e"))
        #expect(Self.bytes(of: keys.server.headerProtectionKey) == quicHex("c206b8d9b9f0f37644430b490eeaa314"))
    }

    // MARK: - A.2

    private static let clientInitialCrypto = """
        060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868
        04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578
        616d706c652e636f6dff01000100000a00080006001d00170018001000070005
        04616c706e000500050100000000003300260024001d00209370b2c9caa47fba
        baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400
        0d0010000e0403050306030203080408050806002d00020101001c0002400100
        3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000
        75300901100f088394c8f03e51570806048000ffff
        """

    private static let clientInitialProtected = """
        c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11
        d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399
        1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c
        8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212
        30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5
        457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208
        4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec
        4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3
        485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db
        059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c
        7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8
        9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556
        be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74
        68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a
        c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00
        f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632
        291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964
        25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd
        14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff
        ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198
        e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd
        c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73
        203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f
        cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e
        fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade
        a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047
        90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2
        162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4
        40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0
        6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e
        8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0
        be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400
        54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab
        760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9
        f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4
        056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064
        7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241
        e221af44860018ab0856972e194cd934
        """

    /// Seals `header` + `payload` with the keys and returns the protected packet.
    @available(anyAppleOS 27.0, *)
    private static func seal(
        header: [UInt8],
        payload: [UInt8],
        keys: QUICPacketKeys,
        packetNumberOffset: Int,
        packetNumberLength: Int,
        packetNumber: UInt64
    ) throws -> [UInt8] {
        var packet = header + payload + [UInt8](repeating: 0, count: QUICPacketKeys.tagLength)
        var span = packet.mutableSpan
        try keys.seal(
            packet: &span,
            packetNumberOffset: packetNumberOffset,
            packetNumberLength: packetNumberLength,
            packetNumber: packetNumber
        )
        _ = consume span
        return packet
    }

    /// Splits a datagram with one packet and opens it.
    @available(anyAppleOS 27.0, *)
    private static func open(
        _ datagram: [UInt8],
        keys: QUICPacketKeys,
        connectionIDLength: Int,
        largestReceived: UInt64?
    ) throws -> (QUICProtectedPacket, QUICUnprotectedHeader, [UInt8]) {
        let (packets, invalid) = datagram.withUnsafeBytes { bytes in
            QUICProtectedPacket.split(
                datagram: RawSpan(_unsafeBytes: bytes),
                shortHeaderConnectionIDLength: connectionIDLength
            )
        }
        #expect(!invalid)
        try #require(packets.count == 1)
        let packet = packets[0]
        var bytes = Array(datagram[packet.range])
        var span = bytes.mutableSpan
        let (header, payload) = try keys.open(
            packet: &span,
            packetNumberOffset: packet.packetNumberOffset,
            largestReceived: largestReceived
        )
        _ = consume span
        return (packet, header, Array(bytes[payload]))
    }

    @available(anyAppleOS 27.0, *)
    @Test func clientInitial() throws {
        let crypto = quicHex(Self.clientInitialCrypto)
        let payload = crypto + [UInt8](repeating: 0, count: 1162 - crypto.count)
        let header = quicHex("c300000001088394c8f03e5157080000449e00000002")
        let keys = QUICPacketKeys.initial(destinationConnectionID: Self.clientDestinationConnectionID)

        let protected = try Self.seal(
            header: header,
            payload: payload,
            keys: keys.client,
            packetNumberOffset: 18,
            packetNumberLength: 4,
            packetNumber: 2
        )
        #expect(protected.count == 1200)
        #expect(protected == quicHex(Self.clientInitialProtected))

        // The server opens it with the keys it derives from the connection ID in the packet.
        let (packet, unprotected, plaintext) = try Self.open(
            quicHex(Self.clientInitialProtected),
            keys: keys.client,
            connectionIDLength: 8,
            largestReceived: nil
        )
        guard case .long(let longHeader) = packet.header else {
            Issue.record("Expected a long header")
            return
        }
        #expect(longHeader.type == .initial)
        #expect(longHeader.destinationConnectionID == Self.clientDestinationConnectionID)
        #expect(longHeader.sourceConnectionID == .empty)
        #expect(longHeader.token.isEmpty)
        #expect(unprotected.packetNumber == 2)
        #expect(unprotected.packetNumberLength == 4)
        #expect(unprotected.firstByte == 0xc3)
        #expect(unprotected.reservedBits == 0)
        #expect(plaintext == payload)

        let frames = try quicParse(plaintext) { input throws(ParsingError) in
            var frames: [QUICFrame] = []
            while !input.isEmpty {
                frames.append(try QUICFrame(parsing: &input))
            }
            return frames
        }
        #expect(frames.count == 2)
        #expect(frames[0] == .crypto(offset: 0, data: Array(crypto[4...])))
        #expect(frames[1] == .padding(count: 1162 - crypto.count))
    }

    // MARK: - A.3

    @available(anyAppleOS 27.0, *)
    @Test func serverInitial() throws {
        let payload = quicHex(
            """
            02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739
            88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94
            0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00
            020304
            """
        )
        let expected = quicHex(
            """
            cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a
            5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3
            dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84
            022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4
            2158407dd074ee
            """
        )
        let keys = QUICPacketKeys.initial(destinationConnectionID: Self.clientDestinationConnectionID)
        let protected = try Self.seal(
            header: quicHex("c1000000010008f067a5502a4262b50040750001"),
            payload: payload,
            keys: keys.server,
            packetNumberOffset: 18,
            packetNumberLength: 2,
            packetNumber: 1
        )
        #expect(protected == expected)

        let (packet, unprotected, plaintext) = try Self.open(
            expected,
            keys: keys.server,
            connectionIDLength: 0,
            largestReceived: nil
        )
        #expect(packet.header.destinationConnectionID == .empty)
        #expect(unprotected.packetNumber == 1)
        #expect(plaintext == payload)

        let frames = try quicParse(plaintext) { input throws(ParsingError) in
            [try QUICFrame(parsing: &input), try QUICFrame(parsing: &input)]
        }
        #expect(frames[0] == .ack(QUICAckFrame(largestAcknowledged: 0, ackDelay: 0, firstRange: 0)))
        guard case .crypto(offset: 0, let data) = frames[1] else {
            Issue.record("Expected a CRYPTO frame")
            return
        }
        #expect(data.count == 90)
    }

    // MARK: - A.4

    @available(anyAppleOS 27.0, *)
    @Test func retryIntegrityTag() throws {
        let packet = quicHex("ff000000010008f067a5502a4262b5746f6b656e")
        let tag = try QUICRetryIntegrity.tag(
            retryPacketWithoutTag: packet,
            originalDestinationConnectionID: Self.clientDestinationConnectionID
        )
        #expect(tag == quicHex("04a265ba2eff4d829058fb3f0f2496ba"))
    }

    // MARK: - A.5

    @available(anyAppleOS 27.0, *)
    @Test func chacha20Poly1305ShortHeader() throws {
        let keys = QUICPacketKeys(
            secret: quicHex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"),
            cipherSuite: .chacha20Poly1305SHA256
        )
        #expect(Self.bytes(of: keys.key) == quicHex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"))
        #expect(keys.iv == quicHex("e0459b3474bdd0e44a41c144"))
        #expect(
            Self.bytes(of: keys.headerProtectionKey)
                == quicHex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
        )
        let next = keys.nextGeneration()
        #expect(Self.bytes(of: next.secret) == quicHex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"))
        #expect(Self.bytes(of: next.headerProtectionKey) == Self.bytes(of: keys.headerProtectionKey))

        let protected = try Self.seal(
            header: quicHex("4200bff4"),
            payload: [0x01],
            keys: keys,
            packetNumberOffset: 1,
            packetNumberLength: 3,
            packetNumber: 654_360_564
        )
        #expect(protected == quicHex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"))

        let (packet, unprotected, plaintext) = try Self.open(
            protected,
            keys: keys,
            connectionIDLength: 0,
            largestReceived: 654_360_563
        )
        #expect(packet.header == .short(destinationConnectionID: .empty))
        #expect(unprotected.packetNumber == 654_360_564)
        #expect(unprotected.firstByte == 0x42)
        #expect(!unprotected.keyPhase)
        #expect(plaintext == [0x01])
    }

    // MARK: - Failures

    @available(anyAppleOS 27.0, *)
    @Test func aModifiedPacketDoesNotOpen() throws {
        let keys = QUICPacketKeys.initial(destinationConnectionID: Self.clientDestinationConnectionID)
        var datagram = quicHex(Self.clientInitialProtected)
        datagram[100] ^= 0x01
        #expect(throws: QUICPacketError.decryptionFailed) {
            _ = try Self.open(datagram, keys: keys.client, connectionIDLength: 8, largestReceived: nil)
        }
        // The keys of the other direction do not open it either.
        #expect(throws: QUICPacketError.self) {
            _ = try Self.open(
                quicHex(Self.clientInitialProtected),
                keys: keys.server,
                connectionIDLength: 8,
                largestReceived: nil
            )
        }
    }

    @available(anyAppleOS 27.0, *)
    @Test func aPacketTooShortForTheSampleIsRejected() {
        let keys = QUICPacketKeys.initial(destinationConnectionID: Self.clientDestinationConnectionID)
        var packet = quicHex("4200bf") + [UInt8](repeating: 0, count: 16)
        var span = packet.mutableSpan
        #expect(throws: QUICPacketError.sampleTooShort) {
            try keys.client.seal(packet: &span, packetNumberOffset: 1, packetNumberLength: 1, packetNumber: 0)
        }
        _ = consume span
    }

    @available(anyAppleOS 27.0, *)
    @Test func keyUpdatesRoundTrip() throws {
        let keys = QUICPacketKeys(secret: [UInt8](repeating: 7, count: 32), cipherSuite: .aes128GCMSHA256)
        let updated = keys.nextGeneration()
        let header: [UInt8] = [0x45, 0xaa, 0xbb, 0x00, 0x05]  // key phase 1, 2 byte connection ID, 2 byte number
        let payload = [UInt8](repeating: 0x01, count: 20)
        let protected = try Self.seal(
            header: header,
            payload: payload,
            keys: updated,
            packetNumberOffset: 3,
            packetNumberLength: 2,
            packetNumber: 5
        )
        // The header protection key is shared, so the old keys reveal the key phase, but only the new keys decrypt.
        var stale = protected
        var staleSpan = stale.mutableSpan
        let staleHeader = try keys.removeHeaderProtection(packet: &staleSpan, packetNumberOffset: 3, largestReceived: 4)
        #expect(staleHeader.keyPhase)
        #expect(throws: QUICPacketError.decryptionFailed) {
            _ = try keys.decryptPayload(packet: &staleSpan, header: staleHeader)
        }
        _ = consume staleSpan

        var bytes = protected
        var span = bytes.mutableSpan
        let unprotected = try keys.removeHeaderProtection(packet: &span, packetNumberOffset: 3, largestReceived: 4)
        #expect(unprotected.packetNumber == 5)
        let range = try updated.decryptPayload(packet: &span, header: unprotected)
        _ = consume span
        #expect(Array(bytes[range]) == payload)
    }
}
