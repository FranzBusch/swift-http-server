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

@available(anyAppleOS 27.0, *)
extension OutputSpan where Element == UInt8 {
    /// Appends bytes with one copy instead of one append per byte.
    ///
    /// - Precondition: The free capacity holds the bytes.
    mutating func appendQUICBytes(_ bytes: borrowing Span<UInt8>) {
        let count = bytes.count
        precondition(count <= self.freeCapacity, "Not enough space for \(count) bytes")
        guard count > 0 else { return }
        bytes.withUnsafeBufferPointer { source in
            self.withUnsafeMutableBufferPointer { buffer, initializedCount in
                let destination = UnsafeMutableBufferPointer(rebasing: buffer[initializedCount..<(initializedCount + count)])
                _ = destination.initialize(fromContentsOf: source)
                initializedCount += count
            }
        }
    }

    /// Appends the bytes of an array with one copy.
    mutating func appendQUICBytes(_ bytes: [UInt8]) {
        self.appendQUICBytes(bytes.span)
    }
}
