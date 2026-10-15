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

import SwiftTLSStateMachine

import ContainersPreview

/// Accumulates the bytes of a TLS connection and hands out complete records.
@available(anyAppleOS 27.0, *)
struct TLSFramingBuffer {
    static let headerSize = 5

    private(set) var buffer: [UInt8]
    private(set) var readOffset: Int

    init() {
        self.buffer = []
        self.buffer.reserveCapacity(32768)
        self.readOffset = 0
    }

    /// Appends all bytes of the container.
    mutating func append<Source: Container<UInt8> & ~Copyable & ~Escapable>(
        from source: borrowing Source
    ) {
        var index = source.startIndex
        while index != source.endIndex {
            let span = source.nextSpan(after: &index)
            self.buffer.reserveCapacity(self.buffer.count + span.count)
            span.withUnsafeBufferPointer { bytes in
                unsafe self.buffer.append(contentsOf: bytes)
            }
        }
    }

    /// The content type, protocol version and fragment length of the next record if its header is complete.
    var nextHeader: (contentType: ContentType, version: ProtocolVersion, fragmentLength: Int)? {
        let available = self.buffer.count - self.readOffset
        guard available >= Self.headerSize else { return nil }
        let fragmentLength =
            Int(self.buffer[self.readOffset + 3]) << 8
            | Int(self.buffer[self.readOffset + 4])
        return (
            ContentType(rawValue: self.buffer[self.readOffset]),
            ProtocolVersion(major: self.buffer[self.readOffset + 1], minor: self.buffer[self.readOffset + 2]),
            fragmentLength
        )
    }

    /// Whether a complete record is buffered.
    var hasCompleteRecord: Bool {
        guard let header = self.nextHeader else { return false }
        return self.buffer.count - self.readOffset >= Self.headerSize + header.fragmentLength
    }

    /// Drops the next record without looking at it.
    mutating func skipRecord() {
        guard let header = self.nextHeader else { return }
        self.readOffset += Self.headerSize + header.fragmentLength
        self.compactIfNeeded()
    }

    /// Copies the fragment of the next complete record and drops the record.
    mutating func takeFragment() -> [UInt8]? {
        guard let header = self.nextHeader, self.hasCompleteRecord else { return nil }
        let start = self.readOffset + Self.headerSize
        let fragment = Array(self.buffer[start..<(start + header.fragmentLength)])
        self.readOffset += Self.headerSize + header.fragmentLength
        self.compactIfNeeded()
        return fragment
    }

    /// Yields the next complete record to `body`.
    ///
    /// The fragment of the view points into the internal buffer. ChangeCipherSpec records are skipped.
    ///
    /// - Returns: The result of `body`, or `nil` if no complete record is buffered.
    mutating func nextRecord<Result>(
        body: (inout EncryptedTLSRecordView) throws -> Result
    ) rethrows -> Result? {
        while true {
            guard let header = self.nextHeader, self.hasCompleteRecord else { return nil }

            if header.contentType == .changeCipherSpec {
                self.skipRecord()
                continue
            }

            let fragmentStart = self.readOffset + Self.headerSize
            let fragmentLength = header.fragmentLength
            let result = try self.buffer.withUnsafeMutableBufferPointer { bytes in
                let fragment = unsafe MutableSpan<UInt8>(
                    _unsafeStart: bytes.baseAddress! + fragmentStart,
                    count: fragmentLength
                )
                var view = EncryptedTLSRecordView(
                    contentType: header.contentType,
                    version: header.version,
                    fragment: fragment
                )
                return try body(&view)
            }

            self.readOffset += Self.headerSize + fragmentLength
            self.compactIfNeeded()
            return result
        }
    }

    private mutating func compactIfNeeded() {
        if self.readOffset == self.buffer.count {
            self.buffer.removeAll(keepingCapacity: true)
            self.readOffset = 0
            return
        }
        guard self.readOffset > self.buffer.count / 2 else { return }
        self.buffer.removeSubrange(0..<self.readOffset)
        self.readOffset = 0
    }
}
