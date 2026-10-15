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

import ArgumentParser
import BasicContainers
import Crypto
import Foundation
import HTTPAPIs
import HTTPTypes
import Logging
import NIOCore
import NIOHTTPServer
import PlatformHTTPServer
import X509

/// The implementation that serves the requests.
enum Implementation: String, ExpressibleByArgument, CaseIterable {
    /// `NIOHTTPServer`, which runs on SwiftNIO.
    case nio

    /// `PlatformHTTPServer`, which runs on `swift-platform-executors`, `swift-tls` and `HTTP2StateMachine`.
    case platform
}

/// Serves one fixed response over HTTP/2 and TLS with the chosen implementation.
///
/// Both implementations run the same handler with the same certificate and the same number of threads, so a load
/// generator measures the servers and not what runs on top of them:
///
/// ```
/// swift run -c release HTTPServerBenchmark --implementation platform --port 8443 &
/// h2load -n 100000 -c 16 -m 10 https://127.0.0.1:8443/
/// ```
@available(anyAppleOS 27.0, *)
@main
struct HTTPServerBenchmark: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Serves a fixed HTTP/2 response with NIOHTTPServer or the PlatformHTTPServer."
    )

    @Option(help: "The implementation to run: nio or platform.")
    var implementation: Implementation = .platform

    @Option(help: "The IPv4 address to bind to.")
    var host: String = "127.0.0.1"

    @Option(help: "The port to bind to. 0 picks a free port.")
    var port: Int = 8443

    @Option(help: "The number of threads that run the connections.")
    var threads: Int = 1

    @Option(help: "The size of the response body in bytes.")
    var responseSize: Int = 15

    @Option(help: "The log level: trace, debug, info, notice, warning, error or critical.")
    var logLevel: String = "info"

    func run() async throws {
        LoggingSystem.bootstrap(StreamLogHandler.standardError)
        var logger = Logger(label: "http-server-benchmark")
        logger.logLevel = Logger.Level(rawValue: self.logLevel) ?? .info

        let certificate = try SelfSignedCertificate.make()
        let body = Self.makeBody(size: self.responseSize)

        switch self.implementation {
        case .nio:
            // `NIOHTTPServer` takes no event loop group, so the thread count is set on the singleton.
            NIOSingletons.groupLoopCountSuggestion = self.threads
            let server = NIOHTTPServer(
                logger: logger,
                configuration: try .init(
                    bindTarget: .hostAndPort(host: self.host, port: self.port),
                    supportedHTTPVersions: [.http2(config: .init())],
                    transportSecurity: .tls(
                        credentials: .x509(
                            .certificates(chain: [certificate.certificate], privateKey: certificate.privateKey)
                        )
                    )
                )
            )
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask {
                    try await Self.serve(on: server, body: body)
                }
                let addresses = try await server.listeningAddresses
                if let port = addresses.first.flatMap({ $0.ipv4?.port ?? $0.ipv6?.port }) {
                    print("listening on port \(port) with nio")
                }
                try await group.waitForAll()
            }

        case .platform:
            let server = PlatformHTTPServer(
                configuration: .init(
                    host: self.host,
                    port: self.port,
                    certificateChain: [certificate.certificate],
                    privateKey: certificate.privateKey,
                    threadCount: self.threads
                ),
                logger: logger
            )
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask {
                    try await Self.serve(on: server, body: body)
                }
                var ports = server.listeningPorts.makeAsyncIterator()
                if let port = try await ports.next() {
                    print("listening on port \(port) with platform")
                }
                try await group.waitForAll()
            }
        }
    }

    /// The body that every request is answered with.
    static func makeBody(size: Int) -> [UInt8] {
        let text = Array("Hello, HTTP/2!\n".utf8)
        guard size > 0 else { return [] }
        return (0..<size).map { text[$0 % text.count] }
    }

    /// Answers every request with the same response, whatever server runs it.
    ///
    /// The handler is the same for every implementation, so the comparison only measures the servers.
    static func serve<Server: HTTPServer>(on server: Server, body: [UInt8]) async throws
    where
        Server.RequestContext: ~Copyable,
        Server.Reader: ~Copyable,
        Server.ResponseSender: ~Copyable,
        Server.ResponseSender.Writer: ~Copyable
    {
        // The type of the handler is named, because the closure based `serve` cannot infer it in a generic context.
        let handler = HTTPServerClosureRequestHandler<
            Server.RequestContext,
            Server.Reader,
            Server.ResponseSender
        > { _, _, reader, responseSender in
            var reader = reader

            // Drain the request body. A server that leaves the request unread resets the stream.
            var finished = false
            while !finished && !Task.isCancelled {
                finished = try await reader.read { _, finalElement in
                    finalElement != nil
                }
            }

            var headerFields = HTTPFields()
            headerFields[.contentType] = "text/plain"
            var payload = UniqueArray<UInt8>(copying: body)
            try await responseSender.sendAndFinish(
                HTTPResponse(status: .ok, headerFields: headerFields),
                buffer: &payload,
                trailer: nil
            )
        }
        try await server.serve(handler: handler)
    }
}

/// A throwaway P-256 certificate, which both implementations can serve.
@available(anyAppleOS 27.0, *)
struct SelfSignedCertificate {
    var certificate: Certificate
    var privateKey: Certificate.PrivateKey

    static func make() throws -> SelfSignedCertificate {
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName("localhost") }
        let privateKey = Certificate.PrivateKey(key)
        let certificate = try Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: privateKey.publicKey,
            notValidBefore: Date() - 3600,
            notValidAfter: Date() + 24 * 3600,
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                SubjectAlternativeNames([.dnsName("localhost")])
            },
            issuerPrivateKey: privateKey
        )
        return SelfSignedCertificate(certificate: certificate, privateKey: privateKey)
    }
}
