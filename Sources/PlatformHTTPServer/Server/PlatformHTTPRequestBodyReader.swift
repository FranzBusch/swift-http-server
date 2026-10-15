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
import ContainersPreview
import HTTP2StateMachine
public import HTTPTypes
import Synchronization

/// Reads the body of a request that the ``PlatformHTTPServer`` received.
///
/// The final element is `nil` if the body ended with a DATA frame, and the trailers if the request carried some.
@available(anyAppleOS 27.0, *)
public struct PlatformHTTPRequestBodyReader: AsyncReader, ~Copyable {
    public typealias ReadElement = UInt8
    public typealias ReadFailure = any Error
    public typealias Buffer = UniqueArray<UInt8>
    public typealias FinalElement = HTTPFields?

    /// The state that survives the consumption of the reader, so that the server can check after the handler
    /// returned whether the body was read completely.
    final class State: Sendable {
        private let finished = Mutex(false)

        init(finished: Bool) {
            self.finished.withLock { $0 = finished }
        }

        var finishedReading: Bool {
            self.finished.withLock { $0 }
        }

        func markFinished() {
            self.finished.withLock { $0 = true }
        }
    }

    private var inbound: HTTP2StreamInbound
    private let state: State
    private var buffer: UniqueArray<UInt8>

    init(inbound: consuming HTTP2StreamInbound, state: State) {
        self.inbound = inbound
        self.state = state
        self.buffer = UniqueArray()
    }

    public mutating func read<Return: ~Copyable, Failure: Error>(
        body: (inout UniqueArray<UInt8>, consuming HTTPFields??) async throws(Failure) -> Return
    ) async throws(EitherError<any Error, Failure>) -> Return {
        self.buffer.removeAll(keepingCapacity: true)
        var finalElement: HTTPFields?? = nil

        if self.state.finishedReading {
            // The caller reads after it observed the end of the body.
            finalElement = .some(nil)
        } else {
            readLoop: while true {
                guard let event = await self.inbound.next() else {
                    // The inbound events ended, but the request did not.
                    self.state.markFinished()
                    throw .first(PlatformHTTPServerError.connectionClosed)
                }

                switch event {
                case .data(let bytes, let endStream):
                    if bytes.isEmpty && !endStream {
                        continue readLoop
                    }
                    self.buffer.append(copying: bytes.span)
                    if endStream {
                        self.state.markFinished()
                        finalElement = .some(nil)
                    }
                    break readLoop

                case .trailers(let headers):
                    self.state.markFinished()
                    finalElement = .some(HPACKBridge.parseTrailers(from: headers))
                    break readLoop

                case .reset(let code):
                    self.state.markFinished()
                    throw .first(PlatformHTTPServerError.streamReset(code))
                }
            }
        }

        do {
            return try await body(&self.buffer, finalElement)
        } catch {
            throw .second(error)
        }
    }
}

@available(*, unavailable)
extension PlatformHTTPRequestBodyReader: Sendable {}
