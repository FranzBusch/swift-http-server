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
public import BinaryParsingAsync
public import BinarySerialization
public import HTTP2StateMachine

/// The reader of the frames that a peer sends on an HTTP/2 connection.
@available(anyAppleOS 27.0, *)
public typealias HTTP2FrameReader<Reader: AsyncReader & ~Copyable & ~Escapable> =
    ParsingAsyncReader<HTTP2PrefaceReader<Reader>, HTTP2Frame>
where Reader.ReadElement == UInt8, Reader.FinalElement == Void

/// The writer of the frames that are sent to a peer on an HTTP/2 connection.
@available(anyAppleOS 27.0, *)
public typealias HTTP2FrameWriter<Writer: AsyncWriter & ~Copyable & ~Escapable> =
    SerializingAsyncWriter<Writer, HTTP2Frame>
where Writer.WriteElement == UInt8, Writer.FinalElement == Void

/// An HTTP connection on top of a bidirectional byte stream.
///
/// The connection only parses and serializes. It turns the byte stream of the peer into a reader of
/// ``HTTP2Frame`` and turns a writer of ``HTTP2Frame`` into bytes. It does not interpret the frames: running the
/// connection, for example by multiplexing streams, is up to the user of the frame reader and writer, such as the
/// ``HTTP2ServerDriver``.
///
/// ```swift
/// let connection = HTTPConnection(reader: tlsReader, writer: tlsWriter)
/// try await connection.withHTTP2Frames { frameReader, frameWriter in
///     try await driver.run(reader: frameReader, writer: frameWriter) { stream in
///         // Handle the stream.
///     }
/// }
/// ```
@available(anyAppleOS 27.0, *)
public struct HTTPConnection<
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

    /// Creates a connection on top of the given byte streams.
    ///
    /// - Parameters:
    ///   - reader: The stream of bytes that the peer sends.
    ///   - writer: The stream of bytes that is sent to the peer.
    @_lifetime(copy reader, copy writer)
    public init(reader: consuming Reader, writer: consuming Writer) {
        self.reader = reader
        self.writer = writer
    }

    /// Provides the frames of an HTTP/2 connection that a client opened.
    ///
    /// The reader expects the connection preface of the client first, and fails if it does not receive it.
    ///
    /// - Parameter body: Receives the reader and the writer of the frames. The reader and the writer can be used
    ///   by different tasks at the same time.
    public consuming func withHTTP2Frames<Return: ~Copyable, Failure: Error>(
        _ body: (consuming HTTP2FrameReader<Reader>, consuming HTTP2FrameWriter<Writer>) async throws(Failure) -> Return
    ) async throws(Failure) -> Return {
        let frameReader = ParsingAsyncReader<HTTP2PrefaceReader<Reader>, HTTP2Frame>(
            upstream: HTTP2PrefaceReader(upstream: self.reader)
        )
        let frameWriter = SerializingAsyncWriter<Writer, HTTP2Frame>(downstream: self.writer)
        return try await body(frameReader, frameWriter)
    }
}
