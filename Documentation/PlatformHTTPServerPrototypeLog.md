# Platform HTTP server prototype: what we did

This document records the prototype of an HTTP/2 over TLS 1.3 server that does not use SwiftNIO. It also records the
state of every branch and the work that remains. `PlatformHTTPServer.md` describes the design. This document describes
the history, the measurements and the open work.

Nothing described here is pushed to a remote at the time of writing.

## Goal

Show a TLS 1.3 and HTTP/2 `HTTPServer` next to `NIOHTTPServer` that is built on
[swift-platform-executors](https://github.com/swiftlang/swift-platform-executors), swift-tls and the pure
`HTTP2StateMachine` of swift-nio-http2, and compare the performance of the two.

The design differs from the earlier prototype in `~/Developer/swift-networking`:

* `HTTPConnection` only parses a byte stream into a reader of `HTTP2Frame` and serializes a writer of `HTTP2Frame`.
* `HTTP2ServerDriver` takes that reader and writer, runs the connection, and starts one child task per stream.
* Every layer is an `AsyncReader` and `AsyncWriter` from swift-async-algorithms on top of the layer below.

## Results

Release builds on an Apple silicon Mac, loopback, `h2load` with two threads on the same machine, one server thread,
15 byte body, 100 connections with 100 streams each, median of three runs of 600 000 requests.

| Server | req/s | CPU per request |
|---|---|---|
| Rust: hyper 1 + tokio-rustls, single threaded runtime | 571 k | ~1.5 µs |
| Swift `PlatformHTTPServer` | 258 k | ~3.9 µs |
| Go: `net/http`, `GOMAXPROCS=1` | 65 k | ~15 µs |
| `NIOHTTPServer`, tasks pinned to the event loop (`--nio-pin-tasks`) | 33 k | ~30 µs |
| `NIOHTTPServer`, default | 33 k | ~112 µs |
| `NIOHTTPServer`, NIO as global executor (`--nio-global-executor`) | 25 k | ~40 µs |

Other scenarios from `Scripts/compare-http-servers.sh` (NIO default vs platform): 16 connections x 10 streams 36 k vs
211 k req/s, 16 KiB body 29 k vs 75 k req/s, 1 MiB body 2.9 k (with failed requests) vs 1.9 k req/s.

### Findings

* **Default NIO is mostly lock contention.** The benchmark pins the event loop count, but the handler tasks run on
  Swift's global executor. About 16 pool threads fight for `SelectableEventLoop._schedule0`. Pinning the tasks to the
  event loop removes that, but NIO is then bound by its per-stream flush: one TLS record and one `write` per response.
  Its throughput stays at 33 k req/s because the single event loop thread is saturated either way.
* **The takeover of the global executor was slower than pinning** (25 k vs 33 k). The response write runs inline in the
  handler task, and the concurrency overhead moves onto the event loop thread.
* **The platform server batches.** Its write side collects whatever many streams queued, then does one TLS pass and
  one syscall. Its time goes to HPACK (about 13 %), per-stream `AsyncStream` and `MultiProducerSingleConsumerAsyncChannel`
  `Source` setup including runtime generic metadata lookups (about 10 %), task creation, and the executor job queue.
  Crypto and syscalls are small.
* **Large bodies are copy bound.** A 1 MiB body is copied about ten times on the way out, and the emulated in-place
  AES-GCM adds three more copies per record plus a `Data` allocation.
* **Go is not mis-measured.** It scales with `GOMAXPROCS` (71 k, 125 k, 214 k for 1, 2, 4) and spends about 14 µs of CPU
  per request in goroutine scheduling, allocation, GC and its HTTP/2 write scheduler.
* **The NIO numbers are suspiciously low for one thread.** Profile `NIOHTTPServer` before quoting the ratio.

### Ideas ranked by expected gain

1. Do not clone a `MultiProducerSingleConsumerAsyncChannel.Source` per stream. Pass one shared writer and the stream id.
2. Replace the per-stream `AsyncStream` and task setup with a cheaper inbox, since benchmark requests carry no body.
3. Make HPACK cheaper: `findMatch`, `[UInt8]` allocations, avoid decoding repeated header blocks.
4. Look at the job queue of the platform executor (`PriorityQueue` heap work on every enqueue).
5. Serialize frames straight into the TLS plaintext buffer, keep DATA payloads as slices, and encrypt in place.

## What was built

| Area | Where |
|---|---|
| `TLSConnection`, `TLSReader`, `TLSWriter` | `Sources/PlatformHTTPServer/TLS` |
| `HTTPConnection`, preface reader | `Sources/PlatformHTTPServer/HTTP2/HTTPConnection.swift`, `HTTP2PrefaceReader.swift` |
| `HTTP2ServerDriver`, stream registry, outbound state with flow control | `Sources/PlatformHTTPServer/HTTP2` |
| `PlatformHTTPServer` (`HTTPServer` conformance) | `Sources/PlatformHTTPServer/Server` |
| Benchmark executable | `Sources/HTTPServerBenchmark` (`--implementation nio\|platform`, `--nio-pin-tasks`, `--nio-global-executor`) |
| Comparison script | `Scripts/compare-http-servers.sh` |
| Tests (19) | `Tests/PlatformHTTPServerTests` |

The tests cover the driver with in-memory frames (flow control, many streams, PING, settings), the frame parser split at
every offset, TLS against an in-memory client (large data, one byte at a time), and end to end over TCP with TLS and
HTTP/2 on the loopback interface. The 139 existing `NIOHTTPServerTests` still pass.

## Repositories and branches

Each repository has a worktree, and every worktree directory is named like its repository, because SwiftPM derives the
identity of a path dependency from the directory name.

| Repository | Worktree | Branch | Based on |
|---|---|---|---|
| swift-http-server | `~/Developer/swift-server/public/swift-http-server-worktrees/platform-server/swift-http-server` | `fb-platform-http-server` | `main` |
| swift-platform-executors | `~/Developer/swiftlang/swift-platform-executors-worktrees/http-server-prototype/swift-platform-executors` | `fb-async-streaming-conformances` | `upstream/main` (9093ad8) |
| swift-tls | `~/Developer/swiftlang/swift-tls-worktrees/http-server-prototype/swift-tls` | `fb-http-server-prototype` | `fb-pure-state` |
| swift-nio-http2 | `~/Developer/swift-server/public/swift-nio-http2-worktrees/http-server-prototype/swift-nio-http2` | `fb-http-server-prototype` | `fb-pure-state` |
| swift-binary-parsing | `~/Developer/swiftlang/swift-binary-parsing-worktrees/http-server-prototype/swift-binary-parsing` | `fb-http-server-prototype` | `fb-networking` |

The stack that compiles and is benchmarked uses the **container based** async streaming protocols, with
swift-async-algorithms at revision `11645b8feb9081ecf0f27b6f4d0821bd550fed01` (main, no branch of our own).

A second, **span based** stack exists and is not ported further:

| Repository | Worktree | Branch |
|---|---|---|
| swift-async-algorithms | `~/Developer/swiftlang/swift-async-algorithms-worktrees/span-streaming/swift-async-algorithms` | `fb-async-streaming-spans` |
| swift-platform-executors | `~/Developer/swiftlang/swift-platform-executors-worktrees/span-streaming/swift-platform-executors` | `fb-async-streaming-spans` |

It replaces `RangeReplaceableContainer` with `Span` and `OutputSpan`. Only the TCP halves are ported to it. Binary
parsing, the TLS and HTTP code, `swift-http-api-proposal` and `NIOHTTPServer` are not.

### Commits that go upstream, per repository

Commits that start with `[local]` only wire the packages together by path and must not go upstream.

* **swift-platform-executors:** the `ExperimentalAsyncStreaming` trait, the `AsyncReader`/`AsyncWriter` conformances of
  the TCP halves, `TCPConnection.withOwnedSplit`, a bulk copy fix.
* **swift-tls:** no `try!` on decryption, tests ported to `TLSWriteStateMachine`, X25519 key exchange (the server
  advertised it but only did P-256, so OpenSSL and h2load clients failed), bulk copies in the AES-GCM emulation.
* **swift-nio-http2:** reject header blocks with more than two table size updates.
* **swift-binary-parsing:** `_checkCount` overflow fix, `Sendable` conformances, tests migrated to the current
  `AsyncReader`, bulk copies and surfaced parse errors in `ParsingAsyncReader`.
* **swift-http-server:** everything in this repository's branch except the Package.swift wiring.

The swift-tls `fb-pure-state`, swift-nio-http2 `fb-pure-state` and swift-binary-parsing `fb-networking` branches are
unlanded work of their own and have to land before the commits above.

## Wiring that is local only

The `Package.swift` of the swift-http-server branch uses path dependencies on the sibling worktrees. It also contains:

* `platforms: macOS 27`,
* `swift-collections` pinned to exactly `1.6.0`, because swift-async-algorithms at `11645b8` calls `Optional.borrow()`,
  which only 1.6.0 has,
* swift-async-algorithms by revision with the `UnstableAsyncStreaming` trait,
* `swift-nio-http2-state-machine`, a wrapper package inside the swift-nio-http2 worktree
  (`Prototype/swift-nio-http2-state-machine`) that exposes only the `HTTP2StateMachine` target. The real package cannot
  be used next to the released swift-nio-http2: both declare `NIOHTTP2` and `NIOHPACK`, and the branch declares
  macOS 13 where swift-nio-extras needs 12.

The other worktrees point at each other by relative path as well. None of this works from a fresh clone. It has to be
replaced by URL and branch dependencies on the forks before the branches can be pushed.

## Building

The Xcode linker on the machine fails with `Argument list too long`, and the I/O interfaces of swift-platform-executors
need the toolchain of swiftlang/swift#91981:

```bash
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
TC=~/Library/Developer/Toolchains/swift-PR-91981-2475.xctoolchain
$TC/usr/bin/swift build --build-system native -c release --product HTTPServerBenchmark
export DYLD_LIBRARY_PATH=$TC/usr/lib/swift/macosx
```

Do not use `swift build` from the swiftly shim. Tests that need XCTest need the Xcode framework path flags.

## Known limitations of the server

HTTP/2 only; P-256 certificates only; the record layer implements AES-GCM only; no CONTINUATION frames; the HPACK
encoder ignores the peer's table size; receive windows are replenished without backpressure; no graceful shutdown, no
timeouts, no connection limit; Linux is untested; `swift-format` was not run.

## Open work

1. Push the compiling branches to forks in the `swift-mirrors` organisation of the internal GitHub, with manifests that
   work from a fresh clone.
2. Add a workload for the server to `performance-workloads`, set up so that it is measured the same way as the NIO
   HTTP/2 case.
3. Port the stack to the span based protocols (binary parsing, TLS and HTTP code, `swift-http-api-proposal`,
   `NIOHTTPServer`) and rerun the benchmarks.
4. Land the upstream commits in the order: swift-binary-parsing, swift-async-algorithms, swift-platform-executors,
   swift-tls and swift-nio-http2, swift-http-api-proposal, swift-http-server.
5. Profile `NIOHTTPServer`, and work through the performance ideas above.
