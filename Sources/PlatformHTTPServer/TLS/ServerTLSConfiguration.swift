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
import SwiftASN1
import SwiftTLSStateMachine

public import X509

/// The configuration of the server side of a TLS 1.3 connection.
@available(anyAppleOS 27.0, *)
public struct ServerTLSConfiguration: Sendable {
    /// The certificate chain of the server. The first entry is the leaf certificate.
    public var certificateChain: [Certificate]

    /// The private key that matches the leaf certificate. It has to be a P-256 key.
    public var privateKey: Certificate.PrivateKey

    /// The ALPN protocols that the server supports, in order of preference.
    public var alpnProtocols: [String]

    /// Creates a server TLS configuration.
    public init(
        certificateChain: [Certificate],
        privateKey: Certificate.PrivateKey,
        alpnProtocols: [String] = ["h2"]
    ) {
        self.certificateChain = certificateChain
        self.privateKey = privateKey
        self.alpnProtocols = alpnProtocols
    }

    func makeHandshakeConfiguration() throws -> ServerHandshakeConfiguration {
        var certificatesDER: [[UInt8]] = []
        for certificate in self.certificateChain {
            var serializer = DER.Serializer()
            try serializer.serialize(certificate)
            certificatesDER.append(serializer.serializedBytes)
        }

        let signingKey = try P256.Signing.PrivateKey(
            pemRepresentation: self.privateKey.serializeAsPEM().pemString
        )

        return ServerHandshakeConfiguration(
            certificateChainDER: certificatesDER,
            signingKey: signingKey,
            alpnProtocols: self.alpnProtocols
        )
    }
}
