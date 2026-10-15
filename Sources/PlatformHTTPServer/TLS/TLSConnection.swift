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

public import AsyncStreaming
import SwiftTLSStateMachine

import BasicContainers
import ContainersPreview

/// A server side TLS 1.3 connection on top of a bidirectional byte stream.
///
/// The connection performs the handshake in ``accept(reader:writer:configuration:)``. Afterwards it is split with
/// ``withSplit(_:)`` into a ``TLSReader`` and a ``TLSWriter`` that decrypt and encrypt independently, so that
/// different tasks can read and write at the same time.
///
/// ```swift
/// let connection = try await TLSConnection.accept(reader: reader, writer: writer, configuration: configuration)
/// let protocolName = connection.negotiatedALPNProtocol
/// try await connection.withSplit { reader, writer in
///     // Read plaintext from `reader` and write plaintext to `writer`.
/// }
/// ```
@available(anyAppleOS 27.0, *)
public struct TLSConnection<
    Reader: AsyncReader & ~Copyable & ~Escapable,
    Writer: AsyncWriter & ~Copyable & ~Escapable
>: ~Copyable, ~Escapable
where
    Reader.ReadElement == UInt8,
    Reader.FinalElement == Void,
    Writer.WriteElement == UInt8,
    Writer.FinalElement == Void
{
    private var reader: Reader
    private var writer: Writer
    private var framingBuffer: TLSFramingBuffer
    private var readStateMachine: TLSReadStateMachine
    private var writeStateMachine: TLSWriteStateMachine

    /// The ALPN protocol that was negotiated during the handshake, or `nil` if the client did not offer any.
    public let negotiatedALPNProtocol: String?

    @_lifetime(copy reader, copy writer)
    private init(
        reader: consuming Reader,
        writer: consuming Writer,
        framingBuffer: TLSFramingBuffer,
        readStateMachine: consuming TLSReadStateMachine,
        writeStateMachine: consuming TLSWriteStateMachine,
        negotiatedALPNProtocol: String?
    ) {
        self.reader = reader
        self.writer = writer
        self.framingBuffer = framingBuffer
        self.readStateMachine = readStateMachine
        self.writeStateMachine = writeStateMachine
        self.negotiatedALPNProtocol = negotiatedALPNProtocol
    }

    /// Performs the server side of the TLS 1.3 handshake.
    ///
    /// - Parameters:
    ///   - reader: The stream of bytes that the peer sends.
    ///   - writer: The stream of bytes that is sent to the peer.
    ///   - configuration: The certificate and the ALPN protocols of the server.
    /// - Returns: The established connection.
    @_lifetime(copy reader, copy writer)
    public static func accept(
        reader: consuming Reader,
        writer: consuming Writer,
        configuration: ServerTLSConfiguration
    ) async throws -> TLSConnection {
        var reader = reader
        var writer = writer
        var framingBuffer = TLSFramingBuffer()
        var stateMachine = ServerHandshakeStateMachine(
            configuration: try configuration.makeHandshakeConfiguration()
        )
        var output = UniqueArray<UInt8>(minimumCapacity: 32768)

        while true {
            // Buffer the next complete record.
            while !framingBuffer.hasCompleteRecord {
                let transportEnded: Bool = try await reader.read { (buffer, finalElement) -> Bool in
                    if finalElement != nil {
                        return true
                    }
                    framingBuffer.append(from: buffer)
                    return false
                }
                if transportEnded {
                    throw TLSError(code: .connectionClosed, message: "The transport ended during the handshake")
                }
            }

            guard let header = framingBuffer.nextHeader else { continue }
            if header.contentType == .changeCipherSpec {
                framingBuffer.skipRecord()
                continue
            }
            guard var fragment = framingBuffer.takeFragment() else { continue }

            var received: ServerHandshakeStateMachine.ReceiveAction? = nil
            fragment.withUnsafeMutableBufferPointer { bytes in
                var view = EncryptedTLSRecordView(
                    contentType: header.contentType,
                    version: header.version,
                    fragment: MutableSpan(_unsafeElements: bytes)
                )
                received = output.append(count: 32768) { (outputSpan: inout OutputSpan<UInt8>) in
                    stateMachine.receive(&view, output: &outputSpan)
                }
            }

            guard let action = received.take() else { continue }
            switch consume action {
            case .continue:
                try await Self.flush(&output, to: &writer)
            case .complete(var applicationState):
                try await Self.flush(&output, to: &writer)
                return TLSConnection(
                    reader: reader,
                    writer: writer,
                    framingBuffer: framingBuffer,
                    readStateMachine: applicationState.takeReadStateMachine(),
                    writeStateMachine: applicationState.takeWriteStateMachine(),
                    negotiatedALPNProtocol: applicationState.negotiatedALPN
                )
            case .error(let error):
                throw TLSError(code: .handshakeFailed, message: "\(error)")
            }
        }
    }

    private static func flush(_ output: inout UniqueArray<UInt8>, to writer: inout Writer) async throws {
        guard output.count > 0 else { return }
        try await writer.write { (buffer: inout Writer.Buffer) in
            buffer.append(copying: output.span)
        }
        output.removeAll(keepingCapacity: true)
    }

    /// Splits the connection into a reader and a writer that can be used by different tasks.
    ///
    /// - Parameter body: Receives the reader and writer of the application data.
    public consuming func withSplit<Return: ~Copyable, Failure: Error>(
        _ body: (consuming TLSReader<Reader>, consuming TLSWriter<Writer>) async throws(Failure) -> Return
    ) async throws(Failure) -> Return {
        let reader = TLSReader(
            upstream: self.reader,
            framingBuffer: self.framingBuffer,
            stateMachine: self.readStateMachine
        )
        let writer = TLSWriter(downstream: self.writer, stateMachine: self.writeStateMachine)
        return try await body(reader, writer)
    }
}
