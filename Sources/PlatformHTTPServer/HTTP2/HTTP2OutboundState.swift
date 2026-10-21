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

import BasicContainers
import HTTP2StateMachine

/// The state of the writing side of the driver.
///
/// It turns the frames that streams want to send into frames on the wire. It owns the HPACK encoder, so that header
/// blocks are encoded in the order in which they are sent, and it applies the flow control and the maximum frame
/// size of the peer to DATA frames.
@available(anyAppleOS 27.0, *)
struct HTTP2OutboundState {
    private enum Queued {
        case data([UInt8], offset: Int, endStream: Bool)
        case headers(HPACKHeaders, endStream: Bool)
    }

    private struct StreamState {
        var window: Int
        var queue: [Queued] = []
    }

    private var encoder = HPACKEncoder()
    private var connectionWindow = 65535
    private var initialStreamWindow = 65535
    private var maxFrameSize = 16384
    private var streams: [UInt32: StreamState] = [:]

    /// Applies a frame to the state and appends the frames that can be sent now.
    ///
    /// - Throws: A failure of the connection if the peer raised the window of the connection above the largest one
    ///   (RFC 9113, section 6.9.1). Only this side can tell, because only it knows how much data it sent.
    mutating func process(
        _ outbound: HTTP2OutboundFrame,
        into frames: inout UniqueArray<HTTP2Frame>
    ) throws(HTTP2ConnectionFailure) {
        switch outbound {
        case .control(let frame):
            frames.append(frame)

        case .stream(let id, let output):
            switch output {
            case .headers(let headers, let endStream):
                self.sendHeaders(id: id, headers: headers, endStream: endStream, into: &frames)
            case .data(let bytes, let endStream):
                self.sendData(id: id, bytes: bytes, endStream: endStream, into: &frames)
            case .reset(let code):
                self.streams.removeValue(forKey: id.value)
                frames.append(HTTP2Frame(streamID: id, payload: .rstStream(code)))
            }

        case .peerSettings(let initialWindowSize, let maxFrameSize):
            if let maxFrameSize {
                self.maxFrameSize = Int(maxFrameSize)
            }
            if let initialWindowSize {
                let delta = Int(initialWindowSize) - self.initialStreamWindow
                self.initialStreamWindow = Int(initialWindowSize)
                for id in self.streams.keys {
                    self.streams[id]?.window += delta
                }
                self.flushQueues(into: &frames)
            }

        case .peerWindowUpdate(let id, let increment):
            if id == .connectionStream {
                let window = self.connectionWindow + Int(increment)
                guard window <= Int(Int32.max) else {
                    throw HTTP2ConnectionFailure(code: .flowControlError, reason: "Connection window overflow")
                }
                self.connectionWindow = window
                self.flushQueues(into: &frames)
            } else if self.streams[id.value] != nil {
                self.streams[id.value]?.window += Int(increment)
                self.flushQueue(of: id, into: &frames)
            }
        }
    }

    private mutating func sendHeaders(
        id: HTTP2StreamID,
        headers: HPACKHeaders,
        endStream: Bool,
        into frames: inout UniqueArray<HTTP2Frame>
    ) {
        if self.streams[id.value]?.queue.isEmpty == false {
            // Trailers have to wait for the data before them.
            self.streams[id.value]?.queue.append(.headers(headers, endStream: endStream))
            return
        }
        self.emitHeaders(id: id, headers: headers, endStream: endStream, into: &frames)
    }

    private mutating func emitHeaders(
        id: HTTP2StreamID,
        headers: HPACKHeaders,
        endStream: Bool,
        into frames: inout UniqueArray<HTTP2Frame>
    ) {
        let block = self.encoder.encode(headers)
        frames.append(
            HTTP2Frame(streamID: id, payload: .headers(.init(headerBlock: block, endStream: endStream)))
        )
        if endStream {
            self.streams.removeValue(forKey: id.value)
        } else if self.streams[id.value] == nil {
            self.streams[id.value] = StreamState(window: self.initialStreamWindow)
        }
    }

    private mutating func sendData(
        id: HTTP2StreamID,
        bytes: [UInt8],
        endStream: Bool,
        into frames: inout UniqueArray<HTTP2Frame>
    ) {
        if self.streams[id.value] == nil {
            self.streams[id.value] = StreamState(window: self.initialStreamWindow)
        }
        if self.streams[id.value]?.queue.isEmpty == false {
            self.streams[id.value]?.queue.append(.data(bytes, offset: 0, endStream: endStream))
            return
        }
        if let remainder = self.emitData(id: id, bytes: bytes, offset: 0, endStream: endStream, into: &frames) {
            self.streams[id.value]?.queue.append(remainder)
        }
    }

    /// Emits as much of the data as the windows allow.
    ///
    /// - Returns: The data that has to wait for a window update, or `nil` if all data was emitted.
    private mutating func emitData(
        id: HTTP2StreamID,
        bytes: [UInt8],
        offset: Int,
        endStream: Bool,
        into frames: inout UniqueArray<HTTP2Frame>
    ) -> Queued? {
        var offset = offset
        if bytes.count == offset {
            if endStream {
                frames.append(HTTP2Frame(streamID: id, payload: .data(.init(data: [], endStream: true))))
                self.streams.removeValue(forKey: id.value)
            }
            return nil
        }

        while offset < bytes.count {
            let streamWindow = self.streams[id.value]?.window ?? 0
            let allowed = min(bytes.count - offset, self.maxFrameSize, streamWindow, self.connectionWindow)
            if allowed <= 0 {
                return .data(bytes, offset: offset, endStream: endStream)
            }
            let isLast = offset + allowed == bytes.count
            let chunk = (offset == 0 && isLast) ? bytes : Array(bytes[offset..<(offset + allowed)])
            frames.append(
                HTTP2Frame(streamID: id, payload: .data(.init(data: chunk, endStream: isLast && endStream)))
            )
            offset += allowed
            self.connectionWindow -= allowed
            self.streams[id.value]?.window -= allowed
        }
        if endStream {
            self.streams.removeValue(forKey: id.value)
        }
        return nil
    }

    private mutating func flushQueues(into frames: inout UniqueArray<HTTP2Frame>) {
        for id in self.streams.keys.sorted() {
            self.flushQueue(of: HTTP2StreamID(id), into: &frames)
        }
    }

    private mutating func flushQueue(of id: HTTP2StreamID, into frames: inout UniqueArray<HTTP2Frame>) {
        while let queued = self.streams[id.value]?.queue.first {
            switch queued {
            case .data(let bytes, let offset, let endStream):
                if let remainder = self.emitData(
                    id: id,
                    bytes: bytes,
                    offset: offset,
                    endStream: endStream,
                    into: &frames
                ) {
                    self.streams[id.value]?.queue[0] = remainder
                    return
                }
            case .headers(let headers, let endStream):
                let block = self.encoder.encode(headers)
                frames.append(
                    HTTP2Frame(streamID: id, payload: .headers(.init(headerBlock: block, endStream: endStream)))
                )
                if endStream {
                    self.streams.removeValue(forKey: id.value)
                    return
                }
            }
            // The head of the queue was emitted completely, unless the stream state is gone.
            if self.streams[id.value] != nil {
                self.streams[id.value]?.queue.removeFirst()
            } else {
                return
            }
        }
    }
}
