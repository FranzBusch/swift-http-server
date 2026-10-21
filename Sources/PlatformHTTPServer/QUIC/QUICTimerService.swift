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
import HeapModule
import PlatformExecutors
import Synchronization

/// Fires the deadlines of all connections of an endpoint.
///
/// One task serves every connection: it ticks with the timer granularity of RFC 9002 (1 ms) while a deadline is
/// armed, and sleeps otherwise. A connection that re-arms its deadline does not touch the heap entry of the old one;
/// the inbox drops expiries of arming generations that are no longer current.
@available(anyAppleOS 27.0, *)
final class QUICTimerService: Sendable {
    /// The granularity of the timers (RFC 9002, section 6.1.2).
    static var granularity: Duration { .milliseconds(1) }

    private struct Entry: Comparable {
        var deadline: ContinuousClock.Instant
        var generation: UInt64
        var inbox: QUICConnectionInbox

        static func < (lhs: Entry, rhs: Entry) -> Bool { lhs.deadline < rhs.deadline }
        static func == (lhs: Entry, rhs: Entry) -> Bool {
            lhs.deadline == rhs.deadline && lhs.generation == rhs.generation && lhs.inbox === rhs.inbox
        }
    }

    private struct State: ~Copyable {
        var entries = Heap<Entry>()
        var finished = false
        var waiter: UnsafeContinuation<Void, Never>? = nil
    }

    private let state = Mutex(State())

    init() {}

    /// Arms the deadline of a connection, replacing its previous one, or disarms it with `nil`.
    func schedule(_ inbox: QUICConnectionInbox, at deadline: ContinuousClock.Instant?) {
        let generation = inbox.arm(deadline)
        guard let deadline else { return }
        let waiter = self.state.withLock { state -> UnsafeContinuation<Void, Never>? in
            guard !state.finished else { return nil }
            state.entries.insert(Entry(deadline: deadline, generation: generation, inbox: inbox))
            return state.waiter.take()
        }
        waiter?.resume()
    }

    /// Stops ``run()``.
    func finish() {
        let waiter = self.state.withLock { state in
            state.finished = true
            state.entries = Heap()
            return state.waiter.take()
        }
        waiter?.resume()
    }

    /// Fires deadlines until ``finish()`` is called or the task is cancelled.
    func run() async {
        let clock = ContinuousClock()
        await withTaskCancellationHandler {
            var expired: [Entry] = []
            while true {
                let (finished, isIdle) = self.state.withLock { state -> (Bool, Bool) in
                    let now = clock.now
                    while let first = state.entries.min, first.deadline <= now {
                        expired.append(state.entries.removeMin())
                    }
                    return (state.finished, state.entries.isEmpty)
                }
                if finished { return }
                for entry in expired {
                    entry.inbox.fireTimer(generation: entry.generation)
                }
                expired.removeAll(keepingCapacity: true)

                if isIdle {
                    await withUnsafeContinuation { (continuation: UnsafeContinuation<Void, Never>) in
                        let ready = self.state.withLock { state -> Bool in
                            if state.finished || !state.entries.isEmpty {
                                return true
                            }
                            state.waiter = continuation
                            return false
                        }
                        if ready {
                            continuation.resume()
                        }
                    }
                } else {
                    try? await Task.sleep(for: Self.granularity)
                }
            }
        } onCancel: {
            self.finish()
        }
    }
}

/// A datagram that a connection sends.
@available(anyAppleOS 27.0, *)
struct QUICOutboundDatagram: Sendable {
    var bytes: [UInt8]
    var peer: SocketAddress
}

/// Collects the datagrams of all connections of an endpoint for the task that owns the sending half of the socket.
@available(anyAppleOS 27.0, *)
final class QUICDatagramQueue: Sendable {
    private struct State: ~Copyable {
        var datagrams = Deque<QUICOutboundDatagram>()
        var finished = false
        var waiter: UnsafeContinuation<Deque<QUICOutboundDatagram>?, Never>? = nil
    }

    private let state = Mutex(State())

    init() {}

    /// Queues datagrams in the given order, unless the queue is finished.
    func send(_ datagrams: some Sequence<QUICOutboundDatagram>) {
        let resumption = self.state.withLock {
            state -> (UnsafeContinuation<Deque<QUICOutboundDatagram>?, Never>, Deque<QUICOutboundDatagram>)? in
            guard !state.finished else { return nil }
            state.datagrams.append(contentsOf: datagrams)
            guard !state.datagrams.isEmpty, let waiter = state.waiter.take() else { return nil }
            var batch = Deque<QUICOutboundDatagram>()
            swap(&batch, &state.datagrams)
            return (waiter, batch)
        }
        if let (waiter, batch) = resumption {
            waiter.resume(returning: batch)
        }
    }

    /// Ends the queue once the datagrams queued so far were taken.
    func finish() {
        let waiter = self.state.withLock { state -> UnsafeContinuation<Deque<QUICOutboundDatagram>?, Never>? in
            state.finished = true
            return state.datagrams.isEmpty ? state.waiter.take() : nil
        }
        waiter?.resume(returning: nil)
    }

    /// All queued datagrams, waiting for one if there is none, or `nil` once the queue is finished and empty.
    ///
    /// Only one task may call this at a time.
    func next() async -> Deque<QUICOutboundDatagram>? {
        await withTaskCancellationHandler {
            await withUnsafeContinuation { (continuation: UnsafeContinuation<Deque<QUICOutboundDatagram>?, Never>) in
                let ready = self.state.withLock { state -> Deque<QUICOutboundDatagram>?? in
                    if !state.datagrams.isEmpty {
                        var batch = Deque<QUICOutboundDatagram>()
                        swap(&batch, &state.datagrams)
                        return .some(batch)
                    }
                    if state.finished {
                        return .some(nil)
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
}
