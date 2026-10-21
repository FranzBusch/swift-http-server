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

/// The round trip time estimate of a connection (RFC 9002, section 5).
@available(anyAppleOS 27.0, *)
struct QUICRTTEstimator: Sendable {
    /// The RTT before the first sample (section 6.2.2).
    static var initialRTT: Duration { .milliseconds(333) }

    private(set) var latest: Duration = .zero
    private(set) var smoothed: Duration = Self.initialRTT
    private(set) var variance: Duration = Self.initialRTT / 2
    private(set) var minimum: Duration = .zero
    private(set) var hasSample = false

    /// Applies an RTT sample (section 5.3).
    ///
    /// - Parameters:
    ///   - sample: The time from sending the largest newly acknowledged packet to receiving the ACK.
    ///   - ackDelay: The delay that the peer reported, already limited to its max_ack_delay once the handshake is
    ///     confirmed.
    mutating func update(sample: Duration, ackDelay: Duration) {
        self.latest = sample
        guard self.hasSample else {
            self.hasSample = true
            self.minimum = sample
            self.smoothed = sample
            self.variance = sample / 2
            return
        }
        self.minimum = min(self.minimum, sample)
        var adjusted = sample
        if sample >= self.minimum + ackDelay {
            adjusted = sample - ackDelay
        }
        let difference = self.smoothed > adjusted ? self.smoothed - adjusted : adjusted - self.smoothed
        self.variance = (self.variance * 3 + difference) / 4
        self.smoothed = (self.smoothed * 7 + adjusted) / 8
    }

    /// The probe timeout without the backoff and without max_ack_delay (section 6.2.1).
    var probeTimeout: Duration {
        self.smoothed + max(self.variance * 4, QUICTimerService.granularity)
    }

    /// The time after which a packet that was sent before an acknowledged one is lost (section 6.1.2).
    var lossDelay: Duration {
        max(max(self.latest, self.smoothed) * 9 / 8, QUICTimerService.granularity)
    }
}

/// NewReno congestion control (RFC 9002, section 7).
@available(anyAppleOS 27.0, *)
struct QUICCongestionController: Sendable {
    let maxDatagramSize: Int
    private(set) var window: Int
    private(set) var bytesInFlight = 0
    private var slowStartThreshold = Int.max
    private var recoveryStart: ContinuousClock.Instant? = nil

    init(maxDatagramSize: Int) {
        self.maxDatagramSize = maxDatagramSize
        self.window = min(10 * maxDatagramSize, max(2 * maxDatagramSize, 14720))
    }

    private var minimumWindow: Int { 2 * self.maxDatagramSize }

    /// The bytes that may be sent before the window is full.
    var available: Int { max(0, self.window - self.bytesInFlight) }

    mutating func sent(bytes: Int) {
        self.bytesInFlight += bytes
    }

    mutating func acknowledged(bytes: Int, sentAt: ContinuousClock.Instant) {
        self.bytesInFlight -= bytes
        if let recoveryStart = self.recoveryStart, sentAt <= recoveryStart {
            return
        }
        if self.window < self.slowStartThreshold {
            self.window += bytes
        } else {
            self.window += max(1, self.maxDatagramSize * bytes / self.window)
        }
    }

    mutating func lost(bytes: Int, sentAt: ContinuousClock.Instant, now: ContinuousClock.Instant) {
        self.bytesInFlight -= bytes
        if let recoveryStart = self.recoveryStart, sentAt <= recoveryStart {
            return
        }
        self.recoveryStart = now
        self.slowStartThreshold = max(self.window / 2, self.minimumWindow)
        self.window = self.slowStartThreshold
    }

    /// Removes packets whose keys were discarded, which are neither acknowledged nor lost (section 6.4).
    mutating func discarded(bytes: Int) {
        self.bytesInFlight -= bytes
    }
}

/// A frame that has to reach the peer, kept with its packet until it is acknowledged or declared lost.
@available(anyAppleOS 27.0, *)
enum QUICRetransmittableFrame: Sendable {
    case crypto(offset: UInt64, data: [UInt8])
    case stream(QUICStreamFrame)
    case resetStream(streamID: UInt64, applicationErrorCode: UInt64, finalSize: UInt64)
    case stopSending(streamID: UInt64, applicationErrorCode: UInt64)
    case maxData
    case maxStreamData(streamID: UInt64)
    case maxStreams(bidirectional: Bool)
    case handshakeDone
}

/// A packet that was sent and is not yet acknowledged or lost.
@available(anyAppleOS 27.0, *)
struct QUICSentPacket: Sendable {
    var packetNumber: UInt64
    var sentAt: ContinuousClock.Instant
    var size: Int
    var isAckEliciting: Bool
    /// Whether the packet counts towards the bytes in flight: it is ack-eliciting or contains PADDING.
    var isInFlight: Bool
    var frames: [QUICRetransmittableFrame]
    /// The largest packet number that an ACK frame of this packet acknowledged, so that the receiver can forget
    /// the ranges below once the ACK is acknowledged.
    var largestAcknowledged: UInt64?
}

/// The packet numbers that a connection received in one packet number space, and when to acknowledge them.
@available(anyAppleOS 27.0, *)
struct QUICReceivedPackets: Sendable {
    /// The most ranges that are remembered and sent in an ACK frame.
    static var maximumRanges: Int { 32 }

    /// The received packet numbers, highest first, at least one missing number apart.
    private(set) var ranges: [ClosedRange<UInt64>] = []

    /// Packet numbers below this are treated as received, since their ranges were forgotten.
    private var floor: UInt64 = 0

    /// When the largest packet number was received, for the ACK Delay field.
    private var largestReceivedAt: ContinuousClock.Instant? = nil

    /// The ack-eliciting packets received since the last ACK frame was sent.
    private(set) var unacknowledgedAckEliciting = 0

    /// The time by which the ack-eliciting packets have to be acknowledged at the latest.
    private(set) var ackDeadline: ContinuousClock.Instant? = nil

    var largest: UInt64? { self.ranges.first?.upperBound }

    /// Whether an ACK frame would tell the peer something new.
    private(set) var hasNewPackets = false

    /// Whether the packet number was not received before.
    func isNew(_ packetNumber: UInt64) -> Bool {
        if packetNumber < self.floor {
            return false
        }
        for range in self.ranges {
            if range.contains(packetNumber) {
                return false
            }
            if range.upperBound < packetNumber {
                return true
            }
        }
        return true
    }

    /// Records a received packet.
    ///
    /// - Parameters:
    ///   - maxAckDelay: How long an acknowledgment may be delayed, or `nil` to acknowledge right away.
    mutating func insert(
        _ packetNumber: UInt64,
        isAckEliciting: Bool,
        now: ContinuousClock.Instant,
        maxAckDelay: Duration?
    ) {
        self.hasNewPackets = true
        if packetNumber >= (self.largest ?? 0) || self.ranges.isEmpty {
            self.largestReceivedAt = now
        }
        if isAckEliciting {
            self.unacknowledgedAckEliciting += 1
            let deadline = maxAckDelay.map { now + $0 } ?? now
            if self.ackDeadline == nil || deadline < self.ackDeadline! {
                self.ackDeadline = deadline
            }
        }

        // Find the first range whose upper bound is below the packet number.
        var index = 0
        while index < self.ranges.count && self.ranges[index].lowerBound > packetNumber {
            index += 1
        }
        if index < self.ranges.count && self.ranges[index].contains(packetNumber) {
            return
        }
        let extendsAbove = index > 0 && self.ranges[index - 1].lowerBound == packetNumber + 1
        let extendsBelow = index < self.ranges.count && self.ranges[index].upperBound + 1 == packetNumber
        switch (extendsAbove, extendsBelow) {
        case (true, true):
            self.ranges[index - 1] = self.ranges[index].lowerBound...self.ranges[index - 1].upperBound
            self.ranges.remove(at: index)
        case (true, false):
            self.ranges[index - 1] = packetNumber...self.ranges[index - 1].upperBound
        case (false, true):
            self.ranges[index] = self.ranges[index].lowerBound...packetNumber
        case (false, false):
            self.ranges.insert(packetNumber...packetNumber, at: index)
        }
        if self.ranges.count > Self.maximumRanges {
            let removed = self.ranges.removeLast()
            self.floor = max(self.floor, removed.upperBound + 1)
        }
    }

    /// Forgets the ranges up to a packet number, once the peer acknowledged an ACK frame that contained them.
    mutating func forget(upTo packetNumber: UInt64) {
        guard packetNumber >= self.floor else { return }
        self.floor = packetNumber + 1
        self.ranges.removeAll { $0.upperBound <= packetNumber }
        if let last = self.ranges.last, last.lowerBound <= packetNumber {
            self.ranges[self.ranges.count - 1] = (packetNumber + 1)...last.upperBound
        }
    }

    /// Creates the ACK frame of the received packets and resets the acknowledgment timer.
    mutating func makeAckFrame(now: ContinuousClock.Instant, ackDelayExponent: UInt64) -> QUICAckFrame? {
        guard !self.ranges.isEmpty else { return nil }
        let delay = self.largestReceivedAt.map { now - $0 } ?? .zero
        let microseconds = UInt64(max(0, delay.components.seconds)) * 1_000_000
            + UInt64(max(0, delay.components.attoseconds / 1_000_000_000_000))
        self.unacknowledgedAckEliciting = 0
        self.ackDeadline = nil
        self.hasNewPackets = false
        return QUICAckFrame(acknowledging: self.ranges, ackDelay: microseconds >> ackDelayExponent)
    }
}

/// Reassembles the bytes of a stream or of the CRYPTO frames of a packet number space, which arrive in any order.
@available(anyAppleOS 27.0, *)
struct QUICReceiveBuffer: Sendable {
    /// The offset up to which the bytes were delivered.
    private(set) var deliveredOffset: UInt64 = 0

    /// The largest offset that was received.
    private(set) var highestOffset: UInt64 = 0

    /// The final size, once a frame with FIN or a RESET_STREAM told it.
    private(set) var finalSize: UInt64? = nil

    /// Bytes beyond the delivered offset, by offset, not overlapping.
    private var segments: [(offset: UInt64, data: [UInt8])] = []

    /// The bytes that are buffered but not delivered.
    var bufferedBytes: Int { self.segments.reduce(0) { $0 + $1.data.count } }

    /// Whether every byte up to the final size was delivered.
    var isComplete: Bool { self.finalSize == self.deliveredOffset }

    /// Adds received bytes.
    ///
    /// - Throws: ``QUICTransportErrorCode/finalSizeError`` if the bytes contradict the final size.
    mutating func insert(offset: UInt64, data: [UInt8], fin: Bool) throws(QUICTransportErrorCode) {
        let end = offset + UInt64(data.count)
        if let finalSize = self.finalSize {
            guard end <= finalSize, !fin || end == finalSize else {
                throw .finalSizeError
            }
        }
        if fin {
            guard end >= self.highestOffset else {
                throw .finalSizeError
            }
            self.finalSize = end
        }
        self.highestOffset = max(self.highestOffset, end)

        // Drop what was delivered or is buffered already.
        var start = max(offset, self.deliveredOffset)
        guard start < end else { return }
        var index = 0
        while index < self.segments.count {
            let segment = self.segments[index]
            let segmentEnd = segment.offset + UInt64(segment.data.count)
            if segmentEnd <= start {
                index += 1
                continue
            }
            if segment.offset >= end {
                break
            }
            if segment.offset > start {
                // A gap before this segment: insert the bytes that fill it.
                let piece = Array(data[Int(start - offset)..<Int(segment.offset - offset)])
                self.segments.insert((start, piece), at: index)
                index += 1
            }
            start = max(start, segmentEnd)
            index += 1
            if start >= end { return }
        }
        if start < end {
            let piece = start == offset ? data : Array(data[Int(start - offset)...])
            self.segments.insert((start, piece), at: index)
        }
    }

    /// Records the final size of a stream that the peer reset.
    mutating func reset(finalSize: UInt64) throws(QUICTransportErrorCode) {
        if let known = self.finalSize, known != finalSize {
            throw .finalSizeError
        }
        guard finalSize >= self.highestOffset else {
            throw .finalSizeError
        }
        self.finalSize = finalSize
        self.highestOffset = finalSize
        self.segments.removeAll()
    }

    /// Takes the bytes that follow the delivered ones without a gap.
    mutating func takeContiguous() -> [UInt8]? {
        guard let first = self.segments.first, first.offset == self.deliveredOffset else { return nil }
        self.segments.removeFirst()
        self.deliveredOffset += UInt64(first.data.count)
        guard let next = self.segments.first, next.offset == self.deliveredOffset else {
            return first.data
        }
        var data = first.data
        while let next = self.segments.first, next.offset == self.deliveredOffset {
            data.append(contentsOf: next.data)
            self.deliveredOffset += UInt64(next.data.count)
            self.segments.removeFirst()
        }
        return data
    }
}

/// The bytes that are queued for one direction of a stream or of a CRYPTO stream.
@available(anyAppleOS 27.0, *)
struct QUICSendBuffer: Sendable {
    private var chunks = Deque<[UInt8]>()
    private var firstChunkOffset = 0

    /// The offset of the next new byte.
    private(set) var nextOffset: UInt64 = 0

    /// The queued bytes that were not sent.
    private(set) var pendingBytes = 0

    /// Whether the stream ends after the queued bytes.
    var finQueued = false

    /// Whether the frame with FIN was sent.
    private(set) var finSent = false

    /// Whether there is something to send: bytes, or the FIN.
    var hasPending: Bool { self.pendingBytes > 0 || (self.finQueued && !self.finSent) }

    mutating func append(_ data: [UInt8]) {
        guard !data.isEmpty else { return }
        self.chunks.append(data)
        self.pendingBytes += data.count
    }

    /// Takes up to `maximum` bytes.
    ///
    /// - Returns: The offset and the bytes, and whether they end the stream.
    mutating func take(maximum: Int) -> (offset: UInt64, data: [UInt8], fin: Bool) {
        let offset = self.nextOffset
        var data: [UInt8] = []
        var remaining = min(maximum, self.pendingBytes)
        if remaining > 0, let first = self.chunks.first, self.firstChunkOffset == 0, first.count <= remaining {
            // The common case: hand out a whole chunk without copying it.
            data = first
            self.chunks.removeFirst()
            remaining -= first.count
        }
        if remaining > 0 {
            data.reserveCapacity(data.count + remaining)
        }
        while remaining > 0, let first = self.chunks.first {
            let available = first.count - self.firstChunkOffset
            let count = min(available, remaining)
            data.append(contentsOf: first[self.firstChunkOffset..<(self.firstChunkOffset + count)])
            remaining -= count
            if count == available {
                self.chunks.removeFirst()
                self.firstChunkOffset = 0
            } else {
                self.firstChunkOffset += count
            }
        }
        self.pendingBytes -= data.count
        self.nextOffset += UInt64(data.count)
        let fin = self.finQueued && self.pendingBytes == 0
        if fin {
            self.finSent = true
        }
        return (offset, data, fin)
    }

    /// Drops the queued bytes, for a stream that is reset.
    mutating func discard() {
        self.chunks.removeAll()
        self.firstChunkOffset = 0
        self.pendingBytes = 0
        self.finQueued = false
    }
}
