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

import AsyncStreaming
import BasicContainers
import ContainersPreview
import Crypto
import Foundation
import SwiftTLSStateMachine
import X509

@testable import PlatformHTTPServer

/// A throwaway P-256 certificate for a server.
@available(anyAppleOS 27.0, *)
func makeServerTLSConfiguration(alpnProtocols: [String] = ["h2"]) throws -> ServerTLSConfiguration {
    let key = P256.Signing.PrivateKey()
    let name = try DistinguishedName { CommonName("localhost") }
    let privateKey = Certificate.PrivateKey(key)
    let certificate = try Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: privateKey.publicKey,
        notValidBefore: Date() - 3600,
        notValidAfter: Date() + 3600,
        issuer: name,
        subject: name,
        signatureAlgorithm: .ecdsaWithSHA256,
        extensions: try Certificate.Extensions {
            SubjectAlternativeNames([.dnsName("localhost")])
        },
        issuerPrivateKey: privateKey
    )
    return ServerTLSConfiguration(
        certificateChain: [certificate],
        privateKey: privateKey,
        alpnProtocols: alpnProtocols
    )
}

/// Performs the client side of the handshake, so that tests can talk to the server side.
///
/// The client does not validate the certificate of the server.
@available(anyAppleOS 27.0, *)
enum TestTLSClient {
    static func connect<
        Reader: AsyncReader & ~Copyable & ~Escapable,
        Writer: AsyncWriter & ~Copyable & ~Escapable,
        Return: ~Copyable
    >(
        reader: consuming Reader,
        writer: consuming Writer,
        alpnProtocols: [String] = ["h2"],
        body: (consuming TLSReader<Reader>, consuming TLSWriter<Writer>, String?) async throws -> Return
    ) async throws -> Return
    where
        Reader.ReadElement == UInt8,
        Reader.FinalElement == Void,
        Writer.WriteElement == UInt8,
        Writer.FinalElement == Void
    {
        var reader = reader
        var writer = writer
        var framingBuffer = TLSFramingBuffer()
        var stateMachine = ClientHandshakeStateMachine(
            configuration: ClientHandshakeConfiguration(serverName: "localhost", alpnProtocols: alpnProtocols)
        )

        var output = UniqueArray<UInt8>(minimumCapacity: 32768)
        output.append(addingCount: 4096) { (span: inout OutputSpan<UInt8>) in
            _ = stateMachine.start(output: &span)
        }
        try await Self.flush(&output, to: &writer)

        while true {
            while !framingBuffer.hasCompleteRecord {
                let ended: Bool = try await reader.read { buffer, finalElement -> Bool in
                    if finalElement != nil { return true }
                    framingBuffer.append(from: buffer)
                    return false
                }
                if ended {
                    throw TLSError(code: .connectionClosed, message: "The transport ended during the handshake")
                }
            }

            guard let header = framingBuffer.nextHeader else { continue }
            if header.contentType == .changeCipherSpec {
                framingBuffer.skipRecord()
                continue
            }
            guard var fragment = framingBuffer.takeFragment() else { continue }

            var received: ClientHandshakeStateMachine.ReceiveAction? = nil
            fragment.withUnsafeMutableBufferPointer { bytes in
                var view = EncryptedTLSRecordView(
                    contentType: header.contentType,
                    version: header.version,
                    fragment: MutableSpan(_unsafeElements: bytes)
                )
                received = output.append(count: 32768) { (span: inout OutputSpan<UInt8>) in
                    stateMachine.receive(&view, output: &span)
                }
            }

            guard let action = received.take() else { continue }
            switch consume action {
            case .continue:
                try await Self.flush(&output, to: &writer)
            case .complete(var applicationState):
                try await Self.flush(&output, to: &writer)
                let tlsReader = TLSReader(
                    upstream: reader,
                    framingBuffer: framingBuffer,
                    stateMachine: applicationState.takeReadStateMachine()
                )
                let tlsWriter = TLSWriter(downstream: writer, stateMachine: applicationState.takeWriteStateMachine())
                return try await body(tlsReader, tlsWriter, applicationState.negotiatedALPN)
            case .error(let error):
                throw TLSError(code: .handshakeFailed, message: "\(error)")
            }
        }
    }

    private static func flush<Writer: AsyncWriter & ~Copyable & ~Escapable>(
        _ output: inout UniqueArray<UInt8>,
        to writer: inout Writer
    ) async throws where Writer.WriteElement == UInt8 {
        guard output.count > 0 else { return }
        try await writer.write { (buffer: inout Writer.Buffer) in
            buffer.append(copying: output.span)
        }
        output.removeAll(keepingCapacity: true)
    }
}
