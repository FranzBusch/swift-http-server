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

/// The types of QUIC packets (RFC 9000, section 17).
@available(anyAppleOS 27.0, *)
enum QUICPacketType: Hashable, Sendable {
    /// A long header packet that carries the first CRYPTO frames of both sides.
    case initial

    /// A long header packet with early data of the client.
    case zeroRTT

    /// A long header packet with the handshake messages that are protected with the handshake keys.
    case handshake

    /// A long header packet with which a server asks the client to prove its address.
    case retry

    /// A short header packet, protected with the keys of the application.
    case oneRTT

    /// The packet number space of the packet type (RFC 9000, section 12.3), or `nil` for Retry.
    var packetNumberSpace: QUICPacketNumberSpace? {
        switch self {
        case .initial: .initial
        case .handshake: .handshake
        case .zeroRTT, .oneRTT: .applicationData
        case .retry: nil
        }
    }
}

/// The packet number spaces of QUIC (RFC 9000, section 12.3).
///
/// Every space numbers its packets and acknowledges them separately.
@available(anyAppleOS 27.0, *)
enum QUICPacketNumberSpace: Int, Hashable, Sendable, CaseIterable {
    case initial
    case handshake
    case applicationData
}
