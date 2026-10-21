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

/// A transport error code of QUIC, sent in a CONNECTION_CLOSE frame of type 0x1c (RFC 9000, section 20.1).
@available(anyAppleOS 27.0, *)
struct QUICTransportErrorCode: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    var rawValue: UInt64

    init(rawValue: UInt64) {
        self.rawValue = rawValue
    }

    static var noError: Self { Self(rawValue: 0x00) }
    static var internalError: Self { Self(rawValue: 0x01) }
    static var connectionRefused: Self { Self(rawValue: 0x02) }
    static var flowControlError: Self { Self(rawValue: 0x03) }
    static var streamLimitError: Self { Self(rawValue: 0x04) }
    static var streamStateError: Self { Self(rawValue: 0x05) }
    static var finalSizeError: Self { Self(rawValue: 0x06) }
    static var frameEncodingError: Self { Self(rawValue: 0x07) }
    static var transportParameterError: Self { Self(rawValue: 0x08) }
    static var connectionIDLimitError: Self { Self(rawValue: 0x09) }
    static var protocolViolation: Self { Self(rawValue: 0x0a) }
    static var invalidToken: Self { Self(rawValue: 0x0b) }
    static var applicationError: Self { Self(rawValue: 0x0c) }
    static var cryptoBufferExceeded: Self { Self(rawValue: 0x0d) }
    static var keyUpdateError: Self { Self(rawValue: 0x0e) }
    static var aeadLimitReached: Self { Self(rawValue: 0x0f) }
    static var noViablePath: Self { Self(rawValue: 0x10) }

    /// The error that carries a TLS alert (RFC 9001, section 4.8).
    static func cryptoError(alert: UInt8) -> Self {
        Self(rawValue: 0x0100 + UInt64(alert))
    }

    /// The TLS alert of a CRYPTO_ERROR, or `nil` for other codes.
    var tlsAlert: UInt8? {
        (0x0100...0x01ff).contains(self.rawValue) ? UInt8(truncatingIfNeeded: self.rawValue - 0x0100) : nil
    }

    var description: String {
        switch self {
        case .noError: "NO_ERROR"
        case .internalError: "INTERNAL_ERROR"
        case .connectionRefused: "CONNECTION_REFUSED"
        case .flowControlError: "FLOW_CONTROL_ERROR"
        case .streamLimitError: "STREAM_LIMIT_ERROR"
        case .streamStateError: "STREAM_STATE_ERROR"
        case .finalSizeError: "FINAL_SIZE_ERROR"
        case .frameEncodingError: "FRAME_ENCODING_ERROR"
        case .transportParameterError: "TRANSPORT_PARAMETER_ERROR"
        case .connectionIDLimitError: "CONNECTION_ID_LIMIT_ERROR"
        case .protocolViolation: "PROTOCOL_VIOLATION"
        case .invalidToken: "INVALID_TOKEN"
        case .applicationError: "APPLICATION_ERROR"
        case .cryptoBufferExceeded: "CRYPTO_BUFFER_EXCEEDED"
        case .keyUpdateError: "KEY_UPDATE_ERROR"
        case .aeadLimitReached: "AEAD_LIMIT_REACHED"
        case .noViablePath: "NO_VIABLE_PATH"
        default:
            if let alert = self.tlsAlert {
                "CRYPTO_ERROR(\(alert))"
            } else {
                "QUICTransportErrorCode(0x\(String(self.rawValue, radix: 16)))"
            }
        }
    }
}

/// A frame or packet that violates the encoding rules of QUIC.
///
/// The parsers throw it as the user error of a `ParsingError`. Other parsing errors, such as missing bytes, are
/// frame encoding errors too.
@available(anyAppleOS 27.0, *)
enum QUICFrameError: Error, Hashable, Sendable {
    /// The frame type is not defined.
    case unknownFrameType(UInt64)

    /// A frame has a value that its type does not allow.
    case invalidFrame(type: UInt64, reason: String)

    /// A connection ID is longer than 20 bytes.
    case invalidConnectionIDLength(Int)

    /// The transport error code that a CONNECTION_CLOSE for this error carries.
    var transportErrorCode: QUICTransportErrorCode {
        .frameEncodingError
    }
}
