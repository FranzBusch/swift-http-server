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

public import HTTPAPIs

/// The context of a request that the ``PlatformHTTPServer`` received.
@available(anyAppleOS 27.0, *)
public struct PlatformHTTPRequestContext: HTTPServerCapability.RequestContext {
    /// Creates a request context.
    public init() {}
}
