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

import DequeModule
import Synchronization

/// Hands the events of one stream from the reading side of the driver to the task of the stream.
///
/// It does what an unbounded `AsyncStream` does for one consumer. Every stream has one, and the generic code of
/// `AsyncStream` lives in the standard library where it cannot be specialized, so it instantiated its metadata at
/// runtime for every stream.
@available(anyAppleOS 27.0, *)
final class HTTP2StreamInbox: Sendable {
    private struct State: ~Copyable {
        var events = Deque<HTTP2StreamEvent>()
        var finished: Bool
        var waiter: UnsafeContinuation<HTTP2StreamEvent?, Never>? = nil
    }

    private let state: Mutex<State>

    /// Creates an inbox, which is finished from the start if the stream does not receive any events.
    init(finished: Bool) {
        self.state = Mutex(State(finished: finished))
    }

    /// Delivers an event, unless the inbox is finished.
    func yield(_ event: HTTP2StreamEvent) {
        let waiter = self.state.withLock { state -> UnsafeContinuation<HTTP2StreamEvent?, Never>? in
            if state.finished {
                return nil
            }
            if let waiter = state.waiter.take() {
                return waiter
            }
            state.events.append(event)
            return nil
        }
        waiter?.resume(returning: event)
    }

    /// Ends the events. The consumer still receives the ones that were delivered before.
    func finish() {
        let waiter = self.state.withLock { state in
            state.finished = true
            return state.waiter.take()
        }
        waiter?.resume(returning: nil)
    }

    /// The next event, or `nil` once the inbox is finished and empty or the task is cancelled.
    ///
    /// Only one task may call this at a time.
    func next() async -> HTTP2StreamEvent? {
        if let ready = self.state.withLock({ Self.poll(&$0) }) {
            return ready
        }
        return await withTaskCancellationHandler {
            await withUnsafeContinuation { (continuation: UnsafeContinuation<HTTP2StreamEvent?, Never>) in
                let ready = self.state.withLock { state -> HTTP2StreamEvent?? in
                    if let ready = Self.poll(&state) {
                        return ready
                    }
                    state.waiter = continuation
                    return nil
                }
                if let ready {
                    continuation.resume(returning: ready)
                }
            }
        } onCancel: {
            self.finish()
        }
    }

    /// The next event, `.some(nil)` if there are no more, or `nil` if the consumer has to wait.
    private static func poll(_ state: inout State) -> HTTP2StreamEvent?? {
        if let event = state.events.popFirst() {
            return .some(event)
        }
        if state.finished {
            return .some(nil)
        }
        return nil
    }
}
