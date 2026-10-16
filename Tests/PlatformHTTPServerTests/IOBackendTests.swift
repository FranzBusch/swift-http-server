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

import Testing

@testable import PlatformHTTPServer

@Suite("PlatformHTTPServer I/O backend")
struct IOBackendTests {
    @Test("The platform default is always available")
    func platformDefault() throws {
        _ = try PlatformHTTPServer.ioBackend(for: .platformDefault)
    }

    @Test("A backend that the platform does not have is reported")
    func unavailableBackend() {
        #if canImport(Darwin)
        #expect(throws: PlatformHTTPServerError.self) {
            _ = try PlatformHTTPServer.ioBackend(for: .epoll)
        }
        #endif
        #if !(canImport(Glibc) && IOUring)
        #expect(throws: PlatformHTTPServerError.self) {
            _ = try PlatformHTTPServer.ioBackend(for: .ioUring)
        }
        #endif
    }

    @Test("The configuration defaults to the platform default")
    func configurationDefault() throws {
        #expect(PlatformHTTPServerConfiguration.IOBackend.allCases.first == .platformDefault)
    }
}
