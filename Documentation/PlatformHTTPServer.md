# PlatformHTTPServer

`PlatformHTTPServer` is an `HTTPServer` that serves HTTP/2 over TLS 1.3 without SwiftNIO. It exists to compare a fully
async design against `NIOHTTPServer`. This is a local prototype. Nothing in it is pushed or released.

## Layers

Every layer is a reader and a writer on top of the layer below. All of them use `AsyncReader` and `AsyncWriter` from
`swift-async-algorithms`.

| Layer | Type | Package | What it does |
|---|---|---|---|
| TCP | `TCPConnection.ReadHalf` / `WriteHalf` | swift-platform-executors | Reads and writes bytes. Conforms to `AsyncReader` and `AsyncWriter`. |
| TLS | `TLSConnection`, `TLSReader`, `TLSWriter` | `PlatformHTTPServer` | Runs the handshake with `SwiftTLSStateMachine`, then decrypts and encrypts records. |
| Frames | `HTTPConnection` | `PlatformHTTPServer` | Parses the byte stream into a reader of `HTTP2Frame` and serializes a writer of `HTTP2Frame`. It does nothing else. |
| Streams | `HTTP2ServerDriver` | `PlatformHTTPServer` | Takes a frame reader and writer, runs the connection and starts a child task for every stream. |
| HTTP | `PlatformHTTPServer` | `PlatformHTTPServer` | Maps a stream to `HTTPServerRequestHandler`. |

```swift
try await connection.withOwnedSplit { readHalf, writeHalf in
    let tls = try await TLSConnection.accept(reader: readHalf, writer: writeHalf, configuration: tlsConfiguration)
    try await tls.withSplit { tlsReader, tlsWriter in
        try await HTTPConnection(reader: tlsReader, writer: tlsWriter).withHTTP2Frames { frameReader, frameWriter in
            try await HTTP2ServerDriver().run(reader: frameReader, writer: frameWriter) { stream in
                // One child task per stream.
            }
        }
    }
}
```

### The driver

`HTTP2ServerDriver.run` starts two concurrent halves with `withConcurrently`, because the reader and the writer are
`~Escapable` values that a task group cannot capture:

* The reading side reads frames, applies SETTINGS, PING, GOAWAY and WINDOW_UPDATE, decodes HEADERS with HPACK, routes
  DATA to the stream and starts the child task of a new stream in a `ThrowingDiscardingTaskGroup`.
* The writing side owns the HPACK encoder and the send windows. It reads batches of frames from a
  `MultiProducerSingleConsumerAsyncChannel`, splits DATA by the window and the maximum frame size of the peer, and
  writes a whole batch with one call.

Streams talk to the driver through that channel and through one `AsyncStream` per stream. A slow peer therefore
blocks the streams that write to it, but not the reading side.

## Building

The Xcode linker on this machine fails with `Argument list too long`, and the I/O interfaces of swift-platform-executors
need the toolchain of swiftlang/swift#91981. Use the recipe that works:

```bash
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
TC=~/Library/Developer/Toolchains/swift-PR-91981-2475.xctoolchain
$TC/usr/bin/swift build --build-system native -c release --product HTTPServerBenchmark
export DYLD_LIBRARY_PATH=$TC/usr/lib/swift/macosx
```

`swift-collections` has to resolve to 1.6.0. Releases 1.6.1 and later removed `Optional.borrow()`, which `AsyncStreaming`
uses at the pinned swift-async-algorithms revision.

## Comparing the servers

```bash
Scripts/compare-http-servers.sh                 # RUNS=3 THREADS=1 by default
.build/release/HTTPServerBenchmark --implementation platform --port 8443 --threads 1
.build/release/HTTPServerBenchmark --implementation nio --port 8443 --threads 1
```

`HTTPServerBenchmark` answers every request with the same body through the same handler, the same self-signed P-256
certificate and the same thread count. The script drives it with `h2load` and prints the median requests per second.

Result on an Apple silicon Mac, release build, loopback, `h2load` with two threads on the same machine, one server
thread, median of three runs. The numbers describe this machine only.

| Scenario | NIOHTTPServer | PlatformHTTPServer |
|---|---|---|
| 16 connections x 10 streams, 15 byte body | 36 k req/s | 211 k req/s |
| 100 connections x 100 streams, 15 byte body | 38 k req/s | 279 k req/s |
| 16 connections x 10 streams, 16 KiB body | 29 k req/s | 75 k req/s |
| 8 connections x 8 streams, 1 MiB body | 2.9 k req/s, 277 failed of 9000 | 1.9 k req/s |

Open questions before the ratio means anything:

* The NIO numbers are lower than expected for one thread. Profile `NIOHTTPServer` before concluding.
* NIO fails some of the 1 MiB requests (277 of 9000 over three runs). The cause is not investigated.
* Large bodies cost more in the platform server than they should: the copy through `[UInt8]` in `HTTP2Frame`, the
  emulated in-place AES-GCM in swift-tls and the `Data` round trip in it.

## Known limitations

* HTTP/2 only. The server refuses a connection that does not negotiate `h2`.
* The certificate has to be a P-256 key. The key exchange supports X25519 and P-256. The record protection implements
  AES-GCM only, although the handshake configuration also lists ChaCha20-Poly1305, so a client that offers only
  ChaCha20 fails. No session resumption, no client certificates.
* No CONTINUATION frames, so a header block has to fit in one frame. A frame of an unknown type ends the connection.
* The HPACK encoder ignores `SETTINGS_HEADER_TABLE_SIZE` of the peer and does not use Huffman coding.
* The server replenishes receive windows when it gets the data. The peer gets no backpressure.
* No graceful shutdown, no timeouts, no connection limit.
* Tested on macOS only. The Linux backends (epoll, io_uring) of swift-platform-executors are untested here.

## Repositories

Every repository has a worktree on a local branch. Commits that start with `[local]` only wire the packages together
by path and should not go upstream.

| Repository | Worktree | Branch | Based on |
|---|---|---|---|
| swift-http-server | `swift-http-server-worktrees/platform-server/swift-http-server` | `fb-platform-http-server` | `main` |
| swift-platform-executors | `swiftlang/swift-platform-executors-worktrees/http-server-prototype/swift-platform-executors` | `fb-async-streaming-conformances` | `upstream/main` |
| swift-tls | `swiftlang/swift-tls-worktrees/http-server-prototype/swift-tls` | `fb-http-server-prototype` | `fb-pure-state` |
| swift-nio-http2 | `swift-nio-http2-worktrees/http-server-prototype/swift-nio-http2` | `fb-http-server-prototype` | `fb-pure-state` |
| swift-binary-parsing | `swiftlang/swift-binary-parsing-worktrees/http-server-prototype/swift-binary-parsing` | `fb-http-server-prototype` | `fb-networking` |
