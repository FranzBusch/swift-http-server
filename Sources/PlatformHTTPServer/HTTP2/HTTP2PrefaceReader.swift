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

public import BasicContainers
public import ContainersPreview

/// An error that violates the HTTP/2 connection preface or framing rules.
@available(anyAppleOS 27.0, *)
public enum HTTP2ConnectionPrefaceError: Error, Sendable {
    /// The client did not start the connection with the HTTP/2 connection preface.
    case invalidPreface
}

/// Reads a byte stream that starts with the HTTP/2 client connection preface.
///
/// The reader validates and removes the 24 bytes of the preface (RFC 9113, section 3.4) and passes on everything
/// that follows, so that the frame parser sees a stream that consists of frames only.
@available(anyAppleOS 27.0, *)
public struct HTTP2PrefaceReader<Upstream: AsyncReader & ~Copyable & ~Escapable>: AsyncReader, ~Copyable, ~Escapable
where Upstream.ReadElement == UInt8, Upstream.FinalElement == Void {
    public typealias ReadElement = UInt8
    public typealias ReadFailure = any Error
    public typealias Buffer = UniqueArray<UInt8>
    public typealias FinalElement = Void

    /// `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`
    static var preface: [UInt8] {
        Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
    }

    private var upstream: Upstream
    private var matched: Int
    private var output: UniqueArray<UInt8>

    @_lifetime(copy upstream)
    init(upstream: consuming Upstream) {
        self.upstream = upstream
        self.matched = 0
        self.output = UniqueArray(minimumCapacity: 16384)
    }

    public mutating func read<Return: ~Copyable, Failure: Error>(
        body: (inout UniqueArray<UInt8>, consuming Void?) async throws(Failure) -> Return
    ) async throws(EitherError<any Error, Failure>) -> Return {
        self.output.removeAll(keepingCapacity: true)

        var ended = false
        do {
            let preface = Self.preface
            repeat {
                ended = try await self.upstream.read { (buffer, finalElement) throws -> Bool in
                    var index = buffer.startIndex
                    while index != buffer.endIndex {
                        let span = buffer.nextSpan(after: &index)
                        var offset = 0
                        while offset < span.count, self.matched < preface.count {
                            guard span[offset] == preface[self.matched] else {
                                throw HTTP2ConnectionPrefaceError.invalidPreface
                            }
                            self.matched += 1
                            offset += 1
                        }
                        if offset < span.count {
                            self.output.append(copying: span.extracting(offset..<span.count))
                        }
                    }
                    return finalElement != nil
                }
            } while self.output.isEmpty && !ended

            if ended && self.matched < preface.count {
                throw HTTP2ConnectionPrefaceError.invalidPreface
            }
        } catch {
            throw .first(error)
        }

        do {
            if ended {
                return try await body(&self.output, ())
            }
            return try await body(&self.output, nil)
        } catch {
            throw .second(error)
        }
    }
}

@available(anyAppleOS 27.0, *)
extension HTTP2PrefaceReader: @unchecked Sendable where Upstream: Sendable & ~Copyable & ~Escapable {}
