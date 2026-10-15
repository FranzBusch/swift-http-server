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

/// Reads the decrypted application data of a TLS 1.3 connection.
///
/// A reader owns the decryption state of the connection. It is independent of the ``TLSWriter`` of the same
/// connection, so both can be used by different tasks at the same time.
@available(anyAppleOS 27.0, *)
public struct TLSReader<Upstream: AsyncReader & ~Copyable & ~Escapable>: AsyncReader, ~Copyable, ~Escapable
where Upstream.ReadElement == UInt8, Upstream.FinalElement == Void {
    public typealias ReadElement = UInt8
    public typealias ReadFailure = any Error
    public typealias Buffer = UniqueArray<UInt8>
    public typealias FinalElement = Void

    private var upstream: Upstream
    private var framingBuffer: TLSFramingBuffer
    private var stateMachine: TLSReadStateMachine
    private var plaintext: UniqueArray<UInt8>
    private var endOfStream: Bool

    @_lifetime(copy upstream)
    init(
        upstream: consuming Upstream,
        framingBuffer: TLSFramingBuffer,
        stateMachine: consuming TLSReadStateMachine
    ) {
        self.upstream = upstream
        self.framingBuffer = framingBuffer
        self.stateMachine = stateMachine
        self.plaintext = UniqueArray(minimumCapacity: 16384)
        self.endOfStream = false
    }

    public mutating func read<Return: ~Copyable, Failure: Error>(
        body: (inout UniqueArray<UInt8>, consuming Void?) async throws(Failure) -> Return
    ) async throws(EitherError<any Error, Failure>) -> Return {
        self.plaintext.removeAll(keepingCapacity: true)
        let isEnd: Bool
        do {
            isEnd = try await self.fillPlaintext()
        } catch {
            throw .first(error)
        }

        do {
            if isEnd {
                return try await body(&self.plaintext, ())
            }
            return try await body(&self.plaintext, nil)
        } catch {
            throw .second(error)
        }
    }

    /// Decrypts buffered records into the plaintext buffer, reading from upstream if needed.
    ///
    /// - Returns: `true` if the end of the stream was reached after the plaintext buffer was filled.
    private mutating func fillPlaintext() async throws -> Bool {
        while true {
            while let step = self.decryptNextRecord() {
                switch step {
                case .plaintext, .skip:
                    continue
                case .closeNotify:
                    self.endOfStream = true
                case .failure(let error):
                    throw TLSError(code: .invalidRecord, message: "\(error)")
                }
                if self.endOfStream { break }
            }

            if self.plaintext.count > 0 {
                return self.endOfStream
            }
            if self.endOfStream {
                return true
            }

            let transportEnded: Bool = try await self.upstream.read { (buffer, finalElement) -> Bool in
                if finalElement != nil {
                    return true
                }
                self.framingBuffer.append(from: buffer)
                return false
            }
            if transportEnded {
                // A peer that closes the transport without a close_notify is treated like one that sent it. The
                // protocol above this one detects truncated messages.
                self.endOfStream = true
            }
        }
    }

    private enum Step {
        case plaintext
        case skip
        case closeNotify
        case failure(TLSConnectionError)
    }

    /// Decrypts the next complete record if there is one.
    private mutating func decryptNextRecord() -> Step? {
        // Moves the plaintext buffer into a local, so that the closure only touches the state machine and it.
        var plaintext = UniqueArray<UInt8>()
        swap(&plaintext, &self.plaintext)
        defer { swap(&plaintext, &self.plaintext) }

        return self.framingBuffer.nextRecord { (view: inout EncryptedTLSRecordView) -> Step in
            switch self.stateMachine.recordReceived(&view) {
            case .applicationData(let decrypted):
                plaintext.append(copying: decrypted.plaintext.span)
                return .plaintext
            case .closeNotifyReceived:
                return .closeNotify
            case .postHandshakeMessage:
                return .skip
            case .discardChangeCipherSpec:
                return .skip
            case .error(let error):
                return .failure(error)
            }
        }
    }
}

@available(anyAppleOS 27.0, *)
extension TLSReader: @unchecked Sendable where Upstream: Sendable & ~Copyable & ~Escapable {}
