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

import HTTP2StateMachine
import Synchronization

/// Tracks the streams of a connection that are open for incoming events.
///
/// The reading side of the driver delivers events and registers streams, while the tasks of the streams unregister
/// themselves when their handler returns.
@available(anyAppleOS 27.0, *)
final class HTTP2StreamRegistry: Sendable {
    private struct Entry {
        var continuation: AsyncStream<HTTP2StreamEvent>.Continuation
        var endStreamReceived: Bool
    }

    private struct State {
        var streams: [UInt32: Entry] = [:]
        /// The highest stream identifier that the peer opened.
        var lastPeerStreamID: UInt32 = 0
    }

    /// The outcome of delivering an event.
    enum Delivery {
        case delivered
        /// The stream is closed or unknown but the peer could have sent frames before it learned of that.
        case ignored
        /// The stream was never opened.
        case idleStream
        /// The stream already received its last frame.
        case streamClosed
    }

    private let state = Mutex(State())

    var count: Int {
        self.state.withLock { $0.streams.count }
    }

    var lastPeerStreamID: UInt32 {
        self.state.withLock { $0.lastPeerStreamID }
    }

    func contains(_ id: HTTP2StreamID) -> Bool {
        self.state.withLock { $0.streams[id.value] != nil }
    }

    /// Whether `id` can be the identifier of a new stream that the peer opens.
    func isNewPeerStream(_ id: HTTP2StreamID) -> Bool {
        self.state.withLock { id.value % 2 == 1 && id.value > $0.lastPeerStreamID }
    }

    /// Registers a stream that the peer opened.
    func open(
        _ id: HTTP2StreamID,
        endStreamReceived: Bool,
        continuation: AsyncStream<HTTP2StreamEvent>.Continuation
    ) {
        self.state.withLock {
            $0.lastPeerStreamID = id.value
            $0.streams[id.value] = Entry(continuation: continuation, endStreamReceived: endStreamReceived)
        }
    }

    /// Delivers an event to the stream.
    func deliver(_ event: HTTP2StreamEvent, to id: HTTP2StreamID) -> Delivery {
        self.state.withLock { state in
            guard var entry = state.streams[id.value] else {
                return id.value > state.lastPeerStreamID ? .idleStream : .ignored
            }
            if entry.endStreamReceived {
                if case .reset = event {
                    return .ignored
                }
                return .streamClosed
            }
            switch event {
            case .data(_, let endStream):
                entry.endStreamReceived = endStream
            case .trailers:
                entry.endStreamReceived = true
            case .reset:
                entry.endStreamReceived = true
            }
            entry.continuation.yield(event)
            if entry.endStreamReceived {
                entry.continuation.finish()
            }
            state.streams[id.value] = entry
            return .delivered
        }
    }

    /// Removes the stream, which ends its inbound events.
    func close(_ id: HTTP2StreamID) {
        let entry = self.state.withLock { $0.streams.removeValue(forKey: id.value) }
        entry?.continuation.finish()
    }

    /// Ends the inbound events of all streams.
    func closeAll() {
        let entries = self.state.withLock { state in
            let entries = Array(state.streams.values)
            state.streams.removeAll()
            return entries
        }
        for entry in entries {
            entry.continuation.finish()
        }
    }
}
