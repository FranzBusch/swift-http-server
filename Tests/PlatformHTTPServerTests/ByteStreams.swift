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

/// A reader of bytes that is fed by a test.
@available(anyAppleOS 27.0, *)
struct TestByteReader: AsyncReader, @unchecked Sendable {
    typealias ReadElement = UInt8
    typealias ReadFailure = any Error
    typealias Buffer = UniqueArray<UInt8>
    typealias FinalElement = Void

    var iterator: AsyncStream<[UInt8]>.Iterator

    mutating func read<Return: ~Copyable, Failure: Error>(
        body: (inout UniqueArray<UInt8>, consuming Void?) async throws(Failure) -> Return
    ) async throws(EitherError<any Error, Failure>) -> Return {
        var buffer = UniqueArray<UInt8>()
        let chunk = await self.iterator.next()
        do {
            if let chunk {
                buffer.append(copying: chunk.span)
                return try await body(&buffer, nil)
            }
            return try await body(&buffer, ())
        } catch {
            throw .second(error)
        }
    }
}

/// A writer of bytes that a test observes. It splits what it writes into chunks of at most `chunkSize` bytes.
@available(anyAppleOS 27.0, *)
struct TestByteWriter: AsyncWriter, @unchecked Sendable {
    typealias WriteElement = UInt8
    typealias WriteFailure = any Error
    typealias Buffer = UniqueArray<UInt8>
    typealias FinalElement = Void

    var continuation: AsyncStream<[UInt8]>.Continuation
    var chunkSize: Int

    mutating func write<Return: ~Copyable, Failure: Error>(
        _ body: (inout UniqueArray<UInt8>) async throws(Failure) -> Return
    ) async throws(EitherError<any Error, Failure>) -> Return {
        var buffer = UniqueArray<UInt8>()
        let result: Return
        do {
            result = try await body(&buffer)
        } catch {
            throw .second(error)
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(buffer.count)
        for index in 0..<buffer.count {
            bytes.append(buffer[index])
        }
        var offset = 0
        while offset < bytes.count {
            let end = min(offset + self.chunkSize, bytes.count)
            self.continuation.yield(Array(bytes[offset..<end]))
            offset = end
        }
        return result
    }

    consuming func finish(finalElement: consuming Void) async throws(any Error) {
        self.continuation.finish()
    }
}

/// An in-memory connection between two peers.
@available(anyAppleOS 27.0, *)
struct TestPipe {
    var reader: TestByteReader
    var writer: TestByteWriter

    /// Creates a one directional pipe.
    static func make(chunkSize: Int = .max) -> TestPipe {
        let (stream, continuation) = AsyncStream<[UInt8]>.makeStream()
        return TestPipe(
            reader: TestByteReader(iterator: stream.makeAsyncIterator()),
            writer: TestByteWriter(continuation: continuation, chunkSize: chunkSize)
        )
    }
}
