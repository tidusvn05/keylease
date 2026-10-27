import Foundation
import XCTest

@testable import KeyLeaseCore

/// Asserts the Swift client's wire `command` names against the frozen list in
/// `test-vectors/rpc/commands.json` — the same contract the Rust
/// `tests/parity.rs` guards.
final class WireCommandParityTests: XCTestCase {
    /// One instance per `RpcRequest` case, in `commands.json` order.
    private var allRequests: [RpcRequest] {
        [
            .status,
            .unlock(password: SecretValue("pw"), sessionTtlSeconds: 3600),
            .groupsList,
            .groupsCreate(
                name: "g", parentId: nil, idempotencyKey: "k", dryRun: false
            ),
            .groupsUpdate(
                id: "g", name: "n", ifRevision: 1, idempotencyKey: "k",
                dryRun: false
            ),
            .groupsReorder(
                parentId: nil, orderedIds: ["g"], expectedRevisions: ["g": 1],
                idempotencyKey: "k", dryRun: false
            ),
            .groupsDelete(
                id: "g", ifRevision: 1, idempotencyKey: "k", dryRun: false
            ),
            .templatesList,
            .templatesGet(kind: "core.login"),
            .agentHandoffCreate(input: AgentNewItemHandoffInput(
                agentAccess: .readWrite, context: nil, expectedVaultId: "v",
                groupId: "g", kind: "core.login", projectSlug: nil,
                protocolVersion: 1, recipeId: "r", sourcePath: nil, tags: nil
            )),
            .agentHandoffGet(handoffId: "h"),
            .migrationsStatus,
            .migrationsPreview(migrationId: "m"),
            .migrationsApply(migrationId: "m", previewDigest: "d"),
            .migrationsRollback(migrationId: "m"),
            .projectsList,
            .projectsCreate(slug: "s", name: nil, idempotencyKey: "k"),
            .contentSearch(
                query: "q", kind: nil, tag: nil, projectSlug: nil,
                reviewedOnly: false
            ),
            .contentGet(id: "c"),
            .contentCreate(input: ContentCreateInput(
                body: "b", favorite: nil, kind: "k", projectSlug: "p",
                tags: nil, title: "t"
            ), idempotencyKey: "k"),
            .contentUpdate(
                id: "c", patch: ContentPatch(
                    addTags: nil, body: nil, clearProject: nil,
                    favorite: nil, projectSlug: nil, removeTags: nil,
                    tags: nil, title: nil
                ), ifRevision: 1, idempotencyKey: "k"
            ),
            .contentSetAccess(
                id: "c", access: .readWrite, ifRevision: 1,
                idempotencyKey: "k"
            ),
            .contentReview(id: "c", ifRevision: 1, idempotencyKey: "k"),
            .entriesSearch(query: "q"),
            .entriesGet(id: "i"),
            .entriesView(id: "i"),
            .entriesCreate(
                input: NewEntryInput(
                    customFields: nil, favorite: nil, groupId: "g",
                    kind: "core.login", notes: nil, password: nil,
                    projectSlug: nil, sections: nil, title: "t", totp: nil, totpUri: nil,
                    url: nil, username: nil
                ),
                idempotencyKey: "k", dryRun: false
            ),
            .entriesUpdate(
                id: "i",
                patch: EntryPatch(
                    clearProject: nil, customFields: nil, favorite: nil,
                    fieldUpdates: nil, groupId: nil, notes: nil,
                    password: nil, projectSlug: nil, removeFieldIds: nil, sections: nil, title: nil,
                    totp: nil, totpUri: nil, url: nil, username: nil
                ),
                ifRevision: 1, idempotencyKey: "k", dryRun: false
            ),
            .entriesDelete(
                id: "i", ifRevision: 1, idempotencyKey: "k", dryRun: false
            ),
            .entriesReveal(id: "i", field: "password"),
            .entriesRevealById(id: "i", fieldId: "f"),
            .entriesRevealMany(id: "i", fieldIds: ["f"]),
            .entriesTotp(id: "i"),
            .entriesHistory(id: "i"),
            .generatePassword(length: 24, recipe: nil),
            .connectionsList,
            .connectionAdd(
                provider: "fake", credential: SecretValue("c"),
                authorizedResources: ["fake:resource/1"]
            ),
            .connectionEnroll(id: "c", resource: "r"),
            .connectionUnenroll(id: "c", resource: "r"),
            .connectionTest(id: "c"),
            .connectionRefresh(id: "c"),
            .connectionDisconnect(id: "c"),
            .connectionRevoke(id: "c"),
            .connectionGoogleOauthBegin(clientId: "id", clientSecret: nil),
            .connectionGoogleOauthComplete(flowId: "f"),
            .approvalsList(limit: 50),
            .approvalDecide(id: "a", approve: true),
            .trustsList,
            .trustRevoke(id: "trust_1"),
            .agentEnroll(name: "codex"),
            .sshIdentities,
            .entriesInject(
                program: "terraform",
                fields: [InjectField(itemId: "item_1", field: "password")]
            ),
            .dbTarget(id: "item_1"),
            .dbScram(
                id: "item_1", database: "postgres", clientFirstBare: "n=,r=a",
                serverFirst: "r=ab,s=c2FsdA==,i=4096"
            ),
            .sshSign(publicKeyBlob: "AAAA", data: "AAAA", flags: 0),
            .auditQuery(limit: 50),
            .leaseRequest(
                request: ActionRequest(
                    action: "entry:read_secret", arguments: .object([:]),
                    connectionId: "c", idempotencyKey: "k", requestId: "r",
                    resource: "kl://v", schemaVersion: 1,
                    subject: ActorContext(
                        agentId: "a", clientSessionId: "s",
                        humanPrincipal: nil, onBehalfOf: nil, purpose: nil,
                        workloadId: nil
                    ),
                    taskId: nil
                ),
                ttlSeconds: 60, maxUses: 1, approvalId: nil
            ),
            .gateExecute(
                leaseToken: SecretValue("t"),
                request: ActionRequest(
                    action: "entry:read_secret", arguments: .object([:]),
                    connectionId: "c", idempotencyKey: "k", requestId: "r",
                    resource: "kl://v", schemaVersion: 1,
                    subject: ActorContext(
                        agentId: "a", clientSessionId: "s",
                        humanPrincipal: nil, onBehalfOf: nil, purpose: nil,
                        workloadId: nil
                    ),
                    taskId: nil
                )
            ),
            .lock,
        ]
    }

    func testCommandNamesMatchFrozenList() throws {
        let url = rpcTestVectors.appendingPathComponent("commands.json")
        let frozen = try JSONDecoder().decode(
            [String: JSONValue].self, from: Data(contentsOf: url)
        )
        let expected = Set(
            frozen["commands"]?.arrayValue?.compactMap(\.stringValue) ?? []
        )
        XCTAssertFalse(expected.isEmpty, "commands.json unreadable?")
        let actual = Set(allRequests.map(\.command))
        XCTAssertEqual(
            actual, expected,
            "RpcRequest commands drifted from test-vectors/rpc/commands.json"
        )
    }

    func testEncodedShapeCarriesCommandTag() throws {
        let data = try JSONEncoder().encode(RpcRequest.entriesSearch(query: "q"))
        let value = try JSONDecoder().decode(JSONValue.self, from: data)
        XCTAssertEqual(value["command"], .string("entries_search"))
        XCTAssertEqual(value["query"], .string("q"))
    }

    func testApprovalTrustIsOmittedUnlessGiven() throws {
        let once = try JSONDecoder().decode(
            JSONValue.self,
            from: JSONEncoder().encode(
                RpcRequest.approvalDecide(id: "a", approve: true)))
        XCTAssertNil(once["trust"])
        let trusted = try JSONDecoder().decode(
            JSONValue.self,
            from: JSONEncoder().encode(
                RpcRequest.approvalDecide(
                    id: "a", approve: true,
                    trust: TrustDecision(scope: .item, duration: .hour1))))
        XCTAssertEqual(trusted["trust"]?["scope"], .string("item"))
        XCTAssertEqual(trusted["trust"]?["duration"], .string("1h"))
    }

    func testTrustCeilingsFollowRiskTiers() {
        XCTAssertEqual(TrustDuration.allowed(for: .r4), [.once])
        XCTAssertEqual(TrustDuration.allowed(for: nil), [.once])
        XCTAssertEqual(
            TrustDuration.allowed(for: .r3), [.once, .minutes30, .hour1])
        XCTAssertEqual(TrustDuration.allowed(for: .r2).last, .day1)
        XCTAssertEqual(TrustDuration.allowed(for: .r1).last, .days7)
    }

    func testOptionalsEncodeAsExplicitNull() throws {
        let data = try JSONEncoder().encode(
            RpcRequest.groupsCreate(
                name: "g", parentId: nil, idempotencyKey: "k", dryRun: false
            )
        )
        let value = try JSONDecoder().decode(JSONValue.self, from: data)
        XCTAssertEqual(value["parent_id"], .null)
        XCTAssertEqual(value["dry_run"], .bool(false))
        XCTAssertEqual(value["idempotency_key"], .string("k"))
    }
}
