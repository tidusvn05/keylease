import Foundation
import XCTest

@testable import KeyLeaseCore

/// `EntryDraft` validation and payload parity with the Dart `EntryDraft`
/// in `packages/leasegate_vault_ui` — the wire objects are compared as
/// decoded `JSONValue` so a missing or renamed key fails here first.
final class EntryDraftTests: XCTestCase {
    private func sampleEntry() -> ItemMetadata {
        ItemMetadata(
            favorite: false,
            groupId: "group_1",
            hasNotes: false,
            hasPassword: true,
            hasTotp: true,
            id: "item_1",
            kind: "core.login",
            revision: 7,
            title: "Example Login",
            updatedAt: "2026-01-01T00:00:00Z",
            urls: ["https://example.com"],
            username: "user@example.com"
        )
    }

    private func object<T: Encodable>(_ value: T) throws -> [String: JSONValue]
    {
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder()
            .decode(JSONValue.self, from: data)
        return try XCTUnwrap(decoded.objectValue)
    }

    // MARK: Validation

    func testCreateDraftRequiresTitleAndGroup() {
        let draft = EntryDraft()
        let errors = draft.validate()
        XCTAssertEqual(errors["title"], "Give this item a name.")
        XCTAssertEqual(errors["group"], "Choose a group for this item.")
    }

    func testAgentContentSkipsGroupRequirement() {
        let draft = EntryDraft(kind: "core.prompt")
        draft.title = "Prompt"
        XCTAssertTrue(draft.isAgentContent)
        XCTAssertNil(draft.validate()["group"])
    }

    func testInvalidCustomFieldsJsonFailsValidation() {
        let draft = EntryDraft(groupId: "group_1")
        draft.title = "X"
        draft.customFields = "not json"
        XCTAssertNotNil(draft.validate()["custom_fields"])
        draft.customFields = #"{"key":"a"}"#
        XCTAssertNotNil(draft.validate()["custom_fields"])
        draft.customFields = "[]"
        XCTAssertNil(draft.validate()["custom_fields"])
    }

    func testInvalidSectionsJsonFailsValidation() {
        let draft = EntryDraft(groupId: "group_1")
        draft.title = "X"
        draft.sections = "{}"
        XCTAssertEqual(
            draft.validate()["sections"], "Sections must be a JSON array.")
    }

    // MARK: Create payload

    func testCreateInputMatchesDartShape() throws {
        let draft = EntryDraft(groupId: "group_1", kind: "core.login")
        draft.title = "  My Login  "
        draft.username = "user"
        draft.password = "s3cret"
        draft.url = "https://example.com"
        draft.notes = "hello"
        draft.totp = "JBSWY3DPEHPK3PXP"
        draft.favorite = true
        draft.customFields = #"""
            [{"id":"f1","key":"k","label":"L",
              "value":{"type":"text","value":"v"},
              "sensitivity":"private_metadata","protected":false,
              "semantic_role":"x"}]
            """#
        draft.sections = #"""
            [{"id":"s1","label":"S","field_ids":["f1"],"semantic_role":null}]
            """#
        let payload = try object(draft.createInput())
        XCTAssertEqual(payload["group_id"]?.stringValue, "group_1")
        XCTAssertEqual(payload["kind"]?.stringValue, "core.login")
        XCTAssertEqual(payload["title"]?.stringValue, "My Login")
        XCTAssertEqual(payload["username"]?.stringValue, "user")
        XCTAssertEqual(payload["password"]?.stringValue, "s3cret")
        XCTAssertEqual(payload["url"]?.stringValue, "https://example.com")
        XCTAssertEqual(payload["notes"]?.stringValue, "hello")
        XCTAssertEqual(payload["favorite"]?.boolValue, true)
        let totp = try XCTUnwrap(payload["totp"]?.objectValue)
        XCTAssertEqual(totp["secret_base32"]?.stringValue, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(totp["algorithm"]?.stringValue, "sha1")
        XCTAssertEqual(totp["digits"]?.intValue, 6)
        XCTAssertEqual(totp["period"]?.intValue, 30)
        XCTAssertEqual(totp["source_representation"]?.stringValue, "base32")
        XCTAssertNil(payload["totp_uri"])
        XCTAssertEqual(payload["custom_fields"]?.arrayValue?.count, 1)
        XCTAssertEqual(payload["sections"]?.arrayValue?.count, 1)
    }

    func testCreateInputOmitsEmptySecrets() throws {
        let draft = EntryDraft(groupId: "group_1")
        draft.title = "X"
        let payload = try object(draft.createInput())
        XCTAssertNil(payload["password"])
        XCTAssertNil(payload["notes"])
        XCTAssertNil(payload["url"])
        XCTAssertNil(payload["totp"])
        XCTAssertNil(payload["totp_uri"])
        XCTAssertEqual(payload["custom_fields"], .array([]))
        XCTAssertEqual(payload["sections"], .array([]))
    }

    func testTotpUriGoesToTotpUriNotConfig() {
        let draft = EntryDraft(groupId: "g")
        draft.totp = "otpauth://totp/x?secret=ABC"
        XCTAssertNil(draft.totpConfig())
        XCTAssertEqual(draft.totpUri, "otpauth://totp/x?secret=ABC")
    }

    // MARK: Update patch

    func testPatchKeepsSecretsAndOnlySendsChanges() throws {
        let draft = EntryDraft(editing: sampleEntry())
        let payload = try object(draft.patch())
        // Always sent.
        XCTAssertEqual(payload["title"]?.stringValue, "Example Login")
        XCTAssertEqual(payload["username"]?.stringValue, "user@example.com")
        // Unchanged group/favorite, empty secrets: omitted.
        XCTAssertNil(payload["group_id"])
        XCTAssertNil(payload["favorite"])
        XCTAssertNil(payload["password"])
        XCTAssertNil(payload["notes"])
        XCTAssertNil(payload["totp"])
        XCTAssertNil(payload["totp_uri"])
        XCTAssertNil(payload["field_updates"])
        XCTAssertNil(payload["sections"])
        XCTAssertNil(payload["remove_field_ids"])
        XCTAssertEqual(payload["url"]?.stringValue, "https://example.com")
    }

    func testPatchIncludesGroupFavoriteAndFieldUpdates() throws {
        let draft = EntryDraft(editing: sampleEntry())
        draft.groupId = "group_2"
        draft.favorite = true
        draft.password = "new"
        draft.removeFieldIds = ["field_x"]
        draft.customFields = #"""
            [{"id":"f1","key":"k","label":"L",
              "value":{"type":"concealed","value":"v"},
              "sensitivity":"highly_sensitive","protected":true,
              "semantic_role":"r"}]
            """#
        let payload = try object(draft.patch())
        XCTAssertEqual(payload["group_id"]?.stringValue, "group_2")
        XCTAssertEqual(payload["favorite"]?.boolValue, true)
        XCTAssertEqual(payload["password"]?.stringValue, "new")
        XCTAssertEqual(
            payload["remove_field_ids"], .array([.string("field_x")]))
        XCTAssertEqual(
            payload["field_updates"]?.arrayValue?.first?["key"]?
                .stringValue,
            "k")
    }

    // MARK: Content payloads

    func testContentCreateAndPatch() throws {
        let draft = EntryDraft(kind: "core.runbook")
        draft.title = "  Deploy runbook "
        draft.notes = "body"
        draft.tags = "ops, prod, ops"
        draft.projectSlug = "web"
        draft.favorite = true
        let create = try object(draft.contentCreateInput())
        XCTAssertEqual(create["kind"]?.stringValue, "core.runbook")
        XCTAssertEqual(create["title"]?.stringValue, "Deploy runbook")
        XCTAssertEqual(create["body"]?.stringValue, "body")
        XCTAssertEqual(
            create["tags"], .array([.string("ops"), .string("prod")]))
        XCTAssertEqual(create["project_slug"]?.stringValue, "web")
        XCTAssertEqual(create["favorite"]?.boolValue, true)

        let contentDraft = EntryDraft(
            editing: ItemMetadata(
                favorite: false,
                groupId: "",
                hasNotes: true,
                hasPassword: false,
                hasTotp: false,
                id: "item_c",
                kind: "core.note",
                revision: 3,
                title: "Note",
                updatedAt: "t",
                urls: [],
                username: nil
            ))
        contentDraft.notes = "new body"
        let patch = try object(contentDraft.contentPatch())
        XCTAssertEqual(patch["title"]?.stringValue, "Note")
        XCTAssertEqual(patch["body"]?.stringValue, "new body")
        XCTAssertEqual(patch["add_tags"], .array([]))
        XCTAssertEqual(patch["remove_tags"], .array([]))
        XCTAssertEqual(patch["clear_project"], .bool(false))
        XCTAssertNil(patch["tags"])
        XCTAssertNil(patch["favorite"])
        XCTAssertNil(patch["project_slug"])
    }

    // MARK: Dirty tracking and wiping

    func testIsDirtyTracksOriginals() {
        let draft = EntryDraft(editing: sampleEntry())
        XCTAssertFalse(draft.isDirty)
        draft.title = "Other"
        XCTAssertTrue(draft.isDirty)
        draft.title = "Example Login"
        XCTAssertFalse(draft.isDirty)
        draft.password = "x"
        XCTAssertTrue(draft.isDirty)
    }

    func testWipeSecretsClearsSensitiveState() {
        let draft = EntryDraft(editing: sampleEntry())
        draft.password = "p"
        draft.notes = "n"
        draft.totp = "t"
        draft.customFields = "[]"
        draft.sections = "[]"
        draft.removeFieldIds = ["a"]
        draft.sshKeyBindings = ["e": "/k"]
        draft.structuredErrors = ["x": "y"]
        draft.wipeSecrets()
        XCTAssertFalse(draft.isDirty)
        XCTAssertTrue(draft.customFields.isEmpty)
        XCTAssertTrue(draft.removeFieldIds.isEmpty)
        XCTAssertTrue(draft.sshKeyBindings.isEmpty)
    }
}
