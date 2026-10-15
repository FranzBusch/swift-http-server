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

/// An error that occurred while establishing or using a TLS connection.
@available(anyAppleOS 27.0, *)
public struct TLSError: Error, Sendable, CustomStringConvertible {
    /// The kind of failure.
    public enum Code: Sendable {
        /// The handshake failed, for example because the peer sent an unexpected message.
        case handshakeFailed
        /// A record could not be decrypted or had an unexpected content type.
        case invalidRecord
        /// The peer closed the transport before the TLS session ended.
        case connectionClosed
    }

    /// The kind of failure.
    public var code: Code

    /// A description of what went wrong.
    public var message: String

    /// Creates a TLS error.
    public init(code: Code, message: String = "") {
        self.code = code
        self.message = message
    }

    public var description: String {
        "TLSError(\(self.code): \(self.message))"
    }
}
