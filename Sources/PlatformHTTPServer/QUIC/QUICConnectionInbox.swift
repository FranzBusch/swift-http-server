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
import PlatformExecutors
import Synchronization

/// A datagram that the endpoint received for a connection.
@available(anyAppleOS 27.0, *)
struct QUICReceivedDatagram: Sendable {
    var bytes: [UInt8]
    var peer: SocketAddress
}

/// What wakes up the task that drives a connection.
@available(anyAppleOS 27.0, *)
enum QUICConnectionEvent: Sendable {
    /// Datagrams arrived, in the order of arrival.
    case datagrams(Deque<QUICReceivedDatagram>)

    /// The deadline that the connection armed passed.
    case timer

    /// The writing side of the connection queued frames, or the congestion window opened.
    case wakeUp
}

/// Hands datagrams, timer expiries and wake-ups to the task that drives one connection.
///
/// Every connection has one. The receive loop of the endpoint yields the datagrams whose destination connection ID
/// belongs to the connection, the ``QUICTimerService`` fires the deadline of the connection, and the writing side
/// wakes it up when it queued frames. Events that arrive while the task is busy are merged: the datagrams are
/// batched, and a timer or a wake-up is delivered once.
@available(anyAppleOS 27.0, *)
final class QUICConnectionInbox: Sendable {
    private struct State: ~Copyable {
        var datagrams = Deque<QUICReceivedDatagram>()
        var timerFired = false
        var wakeUp = false
        var finished = false
        var waiter: UnsafeContinuation<QUICConnectionEvent?, Never>? = nil
        /// The deadline that the connection armed, and the generation that identifies the arming.
        var deadline: ContinuousClock.Instant? = nil
        var deadlineGeneration: UInt64 = 0
    }

    private let state = Mutex(State())

    init() {}

    /// Delivers a datagram, unless the inbox is finished.
    func yield(_ datagram: QUICReceivedDatagram) {
        self.deliver { state in
            state.datagrams.append(datagram)
            return true
        }
    }

    /// Wakes up the task, for example because the writing side queued frames.
    func wakeUp() {
        self.deliver { state in
            state.wakeUp = true
            return true
        }
    }

    /// Arms the deadline of the connection, replacing the previous one, or disarms it with `nil`.
    ///
    /// - Returns: The generation of the arming, which the timer service passes back to ``fireTimer(generation:)``.
    func arm(_ deadline: ContinuousClock.Instant?) -> UInt64 {
        self.state.withLock { state in
            state.deadline = deadline
            state.deadlineGeneration &+= 1
            return state.deadlineGeneration
        }
    }

    /// Fires the timer if the deadline of the given arming is still the current one.
    func fireTimer(generation: UInt64) {
        self.deliver { state in
            guard state.deadline != nil, state.deadlineGeneration == generation else {
                return false
            }
            state.deadline = nil
            state.timerFired = true
            return true
        }
    }

    /// Applies an event to the state and resumes the waiting task with it.
    ///
    /// - Parameter apply: Records the event and returns whether there was one.
    private func deliver(_ apply: (inout State) -> Bool) {
        let resumption = self.state.withLock {
            state -> (UnsafeContinuation<QUICConnectionEvent?, Never>, QUICConnectionEvent)? in
            guard !state.finished, apply(&state), state.waiter != nil, let event = Self.poll(&state) ?? nil else {
                return nil
            }
            return (state.waiter.take()!, event)
        }
        if let (waiter, event) = resumption {
            waiter.resume(returning: event)
        }
    }

    /// Ends the events. Datagrams that were delivered before are dropped.
    func finish() {
        let waiter = self.state.withLock { state in
            state.finished = true
            state.datagrams.removeAll()
            return state.waiter.take()
        }
        waiter?.resume(returning: nil)
    }

    /// The next event, or `nil` once the inbox is finished or the task is cancelled.
    ///
    /// Only one task may call this at a time.
    func next() async -> QUICConnectionEvent? {
        if let ready = self.state.withLock({ Self.poll(&$0) }) {
            return ready
        }
        return await withTaskCancellationHandler {
            await withUnsafeContinuation { (continuation: UnsafeContinuation<QUICConnectionEvent?, Never>) in
                let ready = self.state.withLock { state -> QUICConnectionEvent?? in
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

    /// The next event, `.some(nil)` if the inbox is finished, or `nil` if the task has to wait.
    ///
    /// Datagrams come first, so that acknowledgements are processed before a timer declares packets lost.
    private static func poll(_ state: inout State) -> QUICConnectionEvent?? {
        if state.finished {
            return .some(nil)
        }
        if !state.datagrams.isEmpty {
            var datagrams = Deque<QUICReceivedDatagram>()
            swap(&datagrams, &state.datagrams)
            return .some(.datagrams(datagrams))
        }
        if state.timerFired {
            state.timerFired = false
            return .some(.timer)
        }
        if state.wakeUp {
            state.wakeUp = false
            return .some(.wakeUp)
        }
        return nil
    }
}
