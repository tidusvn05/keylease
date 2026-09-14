import Foundation
import XCTest

@testable import KeyLeaseCore

/// Drives the real socket client against `test-vectors/rpc/golden/`: the
/// request the client puts on the wire must equal the recorded request, and
/// the decoded result (or typed error) must equal the recorded response.
final class GoldenVectorTests: XCTestCase {
    private var tokenPath = ""

    override func setUpWithError() throws {
        // The golden requests were recorded with the literal placeholder
        // string, so using it as the token makes wire bytes match verbatim.
        tokenPath = try writeTokenFile("<redacted-client-token>")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: tokenPath)
    }

    private func client(
        socketPath: String,
        agentId: String = "agent_golden-capture",
        sessionId: String = "golden"
    ) -> KeyLeaseRpc {
        KeyLeaseRpc(
            socketPath: socketPath,
            agentId: agentId,
            tokenPath: tokenPath,
            sessionId: sessionId
        )
    }

    /// Builds the typed request matching a golden file.
    private func request(
        for name: String, goldenRequest: JSONValue
    ) throws -> RpcRequest {
        func field(_ key: String) throws -> String {
            guard let value = goldenRequest[key]?.stringValue else {
                throw NSError(
                    domain: "test", code: 1,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            "\(name): missing \(key) in golden request",
                    ]
                )
            }
            return value
        }
        switch name {
        case "00_status_locked", "03_status_unlocked":
            return .status
        case "01_unlock_wrong_password", "02_unlock":
            return .unlock(
                password: SecretValue(try field("password")),
                sessionTtlSeconds: goldenRequest["session_ttl_seconds"]!
                    .intValue!
            )
        case "04_groups_create":
            return .groupsCreate(
                name: try field("name"),
                parentId: nil,
                idempotencyKey: try field("idempotency_key"),
                dryRun: goldenRequest["dry_run"]!.boolValue!
            )
        case "05_groups_list": return .groupsList
        case "06_templates_list": return .templatesList
        case "07_templates_get": return .templatesGet(kind: try field("kind"))
        case "08_entries_create":
            return .entriesCreate(
                input: try goldenRequest["input"]!.decoded(
                    as: NewEntryInput.self
                ),
                idempotencyKey: try field("idempotency_key"),
                dryRun: goldenRequest["dry_run"]!.boolValue!
            )
        case "09_entries_search", "21_denied", "24_vault_locked":
            return .entriesSearch(query: try field("query"))
        case "10_entries_get": return .entriesGet(id: try field("id"))
        case "11_entries_view": return .entriesView(id: try field("id"))
        case "12_entries_reveal_username", "13_entries_reveal_password":
            return .entriesReveal(id: try field("id"), field: try field("field"))
        case "14_entries_totp": return .entriesTotp(id: try field("id"))
        case "15_entries_history": return .entriesHistory(id: try field("id"))
        case "16_entries_reveal_by_id":
            return .entriesRevealById(
                id: try field("id"), fieldId: try field("field_id")
            )
        case "17_generate_password":
            return .generatePassword(
                length: UInt(goldenRequest["length"]!.intValue!),
                recipe: nil
            )
        case "18_connections_list": return .connectionsList
        case "19_approvals_list":
            return .approvalsList(
                limit: UInt32(goldenRequest["limit"]!.intValue!)
            )
        case "20_audit_query":
            return .auditQuery(
                limit: UInt32(goldenRequest["limit"]!.intValue!)
            )
        case "23_lock": return .lock
        default:
            throw NSError(
                domain: "test", code: 2,
                userInfo: [
                    NSLocalizedDescriptionKey: "no request builder for \(name)"
                ]
            )
        }
    }

    /// Golden files the typed enum can reproduce on the wire.
    /// (`22_invalid_request` is deliberately malformed and cannot be built.)
    static let replayable = [
        "00_status_locked", "02_unlock", "03_status_unlocked",
        "04_groups_create", "05_groups_list", "06_templates_list",
        "07_templates_get", "08_entries_create", "09_entries_search",
        "10_entries_get", "11_entries_view", "12_entries_reveal_username",
        "13_entries_reveal_password", "14_entries_totp",
        "15_entries_history", "16_entries_reveal_by_id",
        "17_generate_password", "18_connections_list", "19_approvals_list",
        "20_audit_query", "21_denied", "23_lock", "24_vault_locked",
    ]

    func testGoldenVectors() async throws {
        for name in Self.replayable {
            let golden = try loadGolden(name)
            var captured: JSONValue?
            let daemon = try FakeDaemon { request in
                captured = request
                return golden.response
            }
            defer { daemon.stop() }

            let rpc = client(
                socketPath: daemon.socketPath,
                agentId: golden.request["auth"]?["agent_id"]?.stringValue
                    ?? "agent_golden-capture",
                sessionId: golden.request["auth"]?["session_id"]?.stringValue
                    ?? "golden"
            )
            let request = try self.request(
                for: name, goldenRequest: golden.request
            )

            do {
                let result = golden.request["auth"] == nil
                    ? try await rpc.unauthenticated(request)
                    : try await rpc.authorized(request)
                XCTAssertEqual(
                    golden.response["ok"], .bool(true),
                    "\(name): golden is an error but client succeeded"
                )
                XCTAssertEqual(
                    result, golden.response["result"] ?? .null,
                    "\(name): result mismatch"
                )
            } catch let error as KeyLeaseError {
                XCTAssertEqual(
                    golden.response["ok"], .bool(false),
                    "\(name): client threw \(error.code) but golden is ok"
                )
                XCTAssertEqual(
                    error.code.rawValue,
                    golden.response["error"]?["error"]?.stringValue,
                    "\(name): error code mismatch"
                )
            }

            // The bytes on the wire must equal the recorded request.
            let wire = captured ?? daemon.requests.last
            XCTAssertEqual(wire, golden.request, "\(name): wire mismatch")
        }
    }

    func testWrongPasswordVectorThrowsCryptoOrDenied() async throws {
        let golden = try loadGolden("01_unlock_wrong_password")
        let daemon = try FakeDaemon { _ in golden.response }
        defer { daemon.stop() }
        let rpc = client(socketPath: daemon.socketPath)
        do {
            _ = try await rpc.authorized(
                .unlock(
                    password: SecretValue("not the password"),
                    sessionTtlSeconds: 3600
                )
            )
            XCTFail("expected error")
        } catch let error as KeyLeaseError {
            XCTAssertEqual(
                error.code.rawValue,
                golden.response["error"]?["error"]?.stringValue
            )
        }
    }
}
