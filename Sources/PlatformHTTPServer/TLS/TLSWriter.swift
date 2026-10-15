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

public import BasicContainers
public import ContainersPreview

/// Writes application data to a TLS 1.3 connection, encrypting it into records.
///
/// A writer owns the encryption state of the connection. It is independent of the ``TLSReader`` of the same
/// connection, so both can be used by different tasks at the same time.
@available(anyAppleOS 27.0, *)
public struct TLSWriter<Downstream: AsyncWriter & ~Copyable & ~Escapable>: AsyncWriter, ~Copyable, ~Escapable
where Downstream.WriteElement == UInt8, Downstream.FinalElement == Void {
    public typealias WriteElement = UInt8
    public typealias WriteFailure = any Error
    public typealias Buffer = UniqueArray<UInt8>
    public typealias FinalElement = Void

    /// The largest plaintext that fits into a single record (RFC 8446, section 5.1).
    static var maximumPlaintextPerRecord: Int { 16384 }

    /// The size of a record header.
    private static var headerSize: Int { 5 }

    /// The content type that is appended to the plaintext and the authentication tag.
    private static var trailerSize: Int { 1 + 16 }

    private var downstream: Downstream
    private var stateMachine: TLSWriteStateMachine
    private var plaintext: UniqueArray<UInt8>
    private var records: UniqueArray<UInt8>

    @_lifetime(copy downstream)
    init(downstream: consuming Downstream, stateMachine: consuming TLSWriteStateMachine) {
        self.downstream = downstream
        self.stateMachine = stateMachine
        self.plaintext = UniqueArray(minimumCapacity: 16384)
        self.records = UniqueArray(minimumCapacity: 16384 + Self.headerSize + Self.trailerSize)
    }

    public mutating func write<Return: ~Copyable, Failure: Error>(
        _ body: (inout UniqueArray<UInt8>) async throws(Failure) -> Return
    ) async throws(EitherError<any Error, Failure>) -> Return {
        self.plaintext.removeAll(keepingCapacity: true)
        let result: Return
        do {
            result = try await body(&self.plaintext)
        } catch {
            throw .second(error)
        }

        guard self.plaintext.count > 0 else { return result }

        do {
            try self.encryptPlaintext()
            try await self.flushRecords()
        } catch {
            throw .first(error)
        }
        return result
    }

    public consuming func finish(finalElement: consuming Void) async throws(any Error) {
        var closeNotify = UniqueArray<UInt8>()
        closeNotify.append(addingCount: 64) { (output: inout OutputSpan<UInt8>) in
            _ = self.stateMachine.sendCloseNotify(output: &output)
        }
        if closeNotify.count > 0 {
            self.records = consume closeNotify
            try await self.flushRecords()
        }
        try await self.downstream.finish(finalElement: ())
    }

    /// Splits the plaintext into records and encrypts them in place into the records buffer.
    private mutating func encryptPlaintext() throws {
        self.records.removeAll(keepingCapacity: true)

        let total = self.plaintext.count
        var offset = 0
        while offset < total {
            let chunk = min(Self.maximumPlaintextPerRecord, total - offset)
            let fragmentLength = chunk + Self.trailerSize
            let recordStart = self.records.count

            self.records.append(ContentType.applicationData.rawValue)
            self.records.append(0x03)
            self.records.append(0x03)
            self.records.append(UInt8(truncatingIfNeeded: fragmentLength >> 8))
            self.records.append(UInt8(truncatingIfNeeded: fragmentLength))
            self.records.append(copying: self.plaintext.span.extracting(offset..<(offset + chunk)))
            self.records.append(ContentType.applicationData.rawValue)
            // The space for the authentication tag.
            self.records.append(addingCount: 16) { (output: inout OutputSpan<UInt8>) in
                for _ in 0..<16 {
                    output.append(0)
                }
            }

            let fragmentStart = recordStart + Self.headerSize
            var mutableRecords = self.records.mutableSpan
            var fragment = mutableRecords.extracting(fragmentStart..<(fragmentStart + fragmentLength))
            switch self.stateMachine.encryptApplicationData(buffer: &fragment) {
            case .ok:
                break
            case .error(let error):
                throw TLSError(code: .invalidRecord, message: "\(error)")
            }

            offset += chunk
        }
    }

    private mutating func flushRecords() async throws {
        var records = UniqueArray<UInt8>()
        swap(&records, &self.records)
        defer {
            records.removeAll(keepingCapacity: true)
            swap(&records, &self.records)
        }

        try await self.downstream.write { (buffer: inout Downstream.Buffer) in
            buffer.append(copying: records.span)
        }
    }
}

@available(anyAppleOS 27.0, *)
extension TLSWriter: @unchecked Sendable where Downstream: Sendable & ~Copyable & ~Escapable {}
