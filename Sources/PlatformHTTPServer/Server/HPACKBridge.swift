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
import HTTPTypes

/// Converts between the HPACK header representation and the types of `HTTPTypes`.
@available(anyAppleOS 27.0, *)
enum HPACKBridge {
    /// Converts the headers of a request into an ``HTTPRequest``.
    ///
    /// All pseudo-headers have to appear before the regular headers (RFC 9113, section 8.3).
    static func parseRequest(from headers: HPACKHeaders) throws(PlatformHTTPServerError) -> HTTPRequest {
        var method: HTTPRequest.Method? = nil
        var scheme: String? = nil
        var authority: String? = nil
        var path: String? = nil
        var sawRegularHeader = false
        var fields = HTTPFields()
        fields.reserveCapacity(headers.headers.count)

        for header in headers.headers {
            let name = header.name
            let value = header.value

            if name.utf8.first == UInt8(ascii: ":") {
                if sawRegularHeader {
                    throw .malformedRequest("Pseudo-header \(name) after a regular header")
                }
                switch name {
                case ":method":
                    guard method == nil else { throw .malformedRequest("Duplicate :method") }
                    guard let parsed = HTTPRequest.Method(value) else {
                        throw .malformedRequest("Invalid :method \(value)")
                    }
                    method = parsed
                case ":scheme":
                    guard scheme == nil else { throw .malformedRequest("Duplicate :scheme") }
                    scheme = value
                case ":authority":
                    guard authority == nil else { throw .malformedRequest("Duplicate :authority") }
                    authority = value
                case ":path":
                    guard path == nil else { throw .malformedRequest("Duplicate :path") }
                    path = value
                case ":protocol":
                    throw .unsupportedConnect
                default:
                    throw .malformedRequest("Unknown pseudo-header \(name)")
                }
            } else {
                sawRegularHeader = true
                guard let fieldName = HTTPField.Name(name) else {
                    throw .malformedRequest("Invalid field name \(name)")
                }
                fields.append(HTTPField(name: fieldName, value: value))
            }
        }

        guard let method else { throw .malformedRequest("Missing :method") }
        if method == .connect {
            throw .unsupportedConnect
        }
        guard scheme != nil else { throw .malformedRequest("Missing :scheme") }
        guard let path else { throw .malformedRequest("Missing :path") }

        return HTTPRequest(
            method: method,
            scheme: scheme,
            authority: authority,
            path: path,
            headerFields: fields
        )
    }

    /// Converts the headers of a trailing HEADERS frame into ``HTTPFields``. Pseudo-headers are dropped.
    static func parseTrailers(from headers: HPACKHeaders) -> HTTPFields {
        var fields = HTTPFields()
        fields.reserveCapacity(headers.headers.count)
        for header in headers.headers {
            if header.name.utf8.first == UInt8(ascii: ":") { continue }
            guard let name = HTTPField.Name(header.name) else { continue }
            fields.append(HTTPField(name: name, value: header.value))
        }
        return fields
    }

    /// Converts the head of a response into HPACK headers, with `:status` first.
    static func encodeResponseHead(_ response: HTTPResponse) -> HPACKHeaders {
        var result: [HPACKHeader] = []
        result.reserveCapacity(1 + response.headerFields.count)
        result.append(HPACKHeader(name: ":status", value: response.status.statusCodeString))
        for field in response.headerFields {
            result.append(HPACKHeader(name: field.name.canonicalName, value: field.value))
        }
        return HPACKHeaders(result)
    }

    /// Converts trailing fields into HPACK headers.
    static func encodeTrailers(_ fields: HTTPFields) -> HPACKHeaders {
        var result: [HPACKHeader] = []
        result.reserveCapacity(fields.count)
        for field in fields {
            result.append(HPACKHeader(name: field.name.canonicalName, value: field.value))
        }
        return HPACKHeaders(result)
    }
}

extension HTTPResponse.Status {
    /// The three digits of the status code.
    fileprivate var statusCodeString: String {
        let hundreds = UInt8(code / 100) + 0x30
        let tens = UInt8((code / 10) % 10) + 0x30
        let ones = UInt8(code % 10) + 0x30
        return String(decoding: [hundreds, tens, ones], as: UTF8.self)
    }
}
