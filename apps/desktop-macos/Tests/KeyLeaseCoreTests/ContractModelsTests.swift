import Foundation
import XCTest

@testable import KeyLeaseCore

/// Decodes generated contract models from the recorded daemon responses —
/// a schema/codegen bug shows up here before it can reach the UI.
final class ContractModelsTests: XCTestCase {
    private func result(_ name: String) throws -> JSONValue {
        let golden = try loadGolden(name)
        guard golden.response["ok"] == .bool(true) else {
            throw NSError(
                domain: "test", code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey: "\(name) is an error vector"
                ]
            )
        }
        return golden.response["result"] ?? .null
    }

    func testGroupsList() throws {
        let groups = try result("05_groups_list")
            .decoded(as: [VaultGroup].self)
        XCTAssertEqual(groups.count, 1)
        XCTAssertEqual(groups[0].name, "Golden Group")
        XCTAssertEqual(groups[0].purpose, .user)
        XCTAssertNil(groups[0].parentId)
    }

    func testEntriesSearch() throws {
        let items = try result("09_entries_search")
            .decoded(as: [ItemMetadata].self)
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items[0].title, "Golden Login")
        XCTAssertEqual(items[0].kind, "core.login")
        XCTAssertEqual(items[0].hasTotp, true)
    }

    func testEntryViewFieldValueVariants() throws {
        let view = try result("11_entries_view").decoded(as: EntryView.self)
        XCTAssertFalse(view.fields.isEmpty)
        let username = try XCTUnwrap(
            view.fields.first { $0.key == "username" }
        )
        guard case .text(let payload)? = username.value else {
            return XCTFail("username field should decode as .text")
        }
        XCTAssertEqual(payload.value, "golden@example.com")
        // A concealed field arrives without its value.
        let password = try XCTUnwrap(
            view.fields.first { $0.key == "password" }
        )
        XCTAssertNil(password.value)
        XCTAssertEqual(password.sensitivity, .secret)
    }

    func testTemplatesList() throws {
        let kinds = try result("06_templates_list")
            .decoded(as: [ItemKindDefinition].self)
        XCTAssertTrue(kinds.contains { $0.kind == "core.login" })
    }

    func testAuditQuery() throws {
        let events = try result("20_audit_query")
            .decoded(as: [AuditEvent].self)
        XCTAssertFalse(events.isEmpty)
        XCTAssertTrue(
            events.contains { $0.action == "entry:read_secret" }
        )
    }

    func testFieldValueRoundTrip() throws {
        let json = """
            {"type":"month_year","value":{"month":3,"year":2030}}
            """
        let value = try JSONDecoder().decode(
            FieldValue.self, from: Data(json.utf8)
        )
        guard case .monthYear(let payload) = value else {
            return XCTFail("expected .monthYear")
        }
        XCTAssertEqual(payload.value.month, 3)
        XCTAssertEqual(payload.value.year, 2030)
        let reencoded = try JSONEncoder().encode(value)
        let roundTrip = try JSONDecoder().decode(JSONValue.self, from: reencoded)
        XCTAssertEqual(roundTrip["type"], .string("month_year"))
        XCTAssertEqual(roundTrip["value"]?["month"]?.intValue, 3)
    }

    func testPolicyDecisionVariants() throws {
        let deny = try JSONDecoder().decode(
            PolicyDecision.self,
            from: Data(
                #"{"decision":"deny","matched_rule":null,"reason":"nope"}"#
                    .utf8
            )
        )
        guard case .deny(let payload) = deny else {
            return XCTFail("expected .deny")
        }
        XCTAssertEqual(payload.reason, "nope")

        let approval = try JSONDecoder().decode(
            PolicyDecision.self,
            from: Data(
                #"""
                {"decision":"require_approval","matched_rule":"r",
                 "policy_version":1,"max_ttl_seconds":60,"max_uses":1,
                 "budget":{"max_items":1},
                 "request_digest_hex":"ab","risk":"r2"}
                """#.utf8
            )
        )
        guard case .requireApproval = approval else {
            return XCTFail("expected .requireApproval")
        }
    }
}
