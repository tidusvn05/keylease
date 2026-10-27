import Foundation
import XCTest

@testable import KeyLeaseCore

/// Parity tests for the structured developer-template editors:
/// `parseDotEnv`, `renderDotEnv`, `renderSshConfig` and the editor-state
/// `sync()` that writes `customFields`/`sections`/`removeFieldIds`.
final class DeveloperTemplateTests: XCTestCase {
    // MARK: parseDotEnv

    func testParseDotEnvBasics() {
        let result = parseDotEnv("""
            # comment

            export A=1
            B = two
            EMPTY=
            QUOTED='a b'
            DOUBLE="x\\ny"
            MULTI="line1
            line2"
            INLINE=1 # trailing
            """)
        XCTAssertTrue(result.valid)
        XCTAssertEqual(result.ignoredComments, 1)
        XCTAssertEqual(result.ignoredBlankLines, 1)
        XCTAssertEqual(result.normalizedExports, 1)
        let values = Dictionary(
            result.variables.map { ($0.key, $0.value) },
            uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(values["A"], "1")
        XCTAssertEqual(values["B"], "two")
        XCTAssertEqual(values["EMPTY"], "")
        XCTAssertEqual(values["QUOTED"], "a b")
        XCTAssertEqual(values["DOUBLE"], "x\ny")
        XCTAssertEqual(values["MULTI"], "line1\nline2")
        XCTAssertEqual(values["INLINE"], "1")
    }

    func testParseDotEnvIssues() {
        let result = parseDotEnv("""
            1BAD=x
            GOOD=1
            GOOD=2
            MISSING
            "unclosed
            """)
        XCTAssertFalse(result.valid)
        XCTAssertEqual(result.variables.map(\.key), ["GOOD"])
        let lines = result.issues.map(\.line)
        XCTAssertEqual(lines, [1, 3, 4, 5])
    }

    func testParseDotEnvBomAndCrlf() {
        let result = parseDotEnv("\u{FEFF}A=1\r\nB=2\r\n")
        XCTAssertTrue(result.valid)
        XCTAssertEqual(result.variables.count, 2)
    }

    // MARK: renderDotEnv

    func testRenderDotEnvQuoting() {
        let rendered = renderDotEnv([
            ("PLAIN", "abc-123_./:@%+,="),
            ("EMPTY", ""),
            ("SPACES", "a b c"),
            ("QUOTE", "it's"),
            ("MULTI", "a\nb"),
            ("DOLLAR", "a$b"),
        ])
        XCTAssertTrue(rendered.contains("PLAIN=abc-123_./:@%+,=\n"))
        XCTAssertTrue(rendered.contains("EMPTY=\n"))
        XCTAssertTrue(rendered.contains("SPACES='a b c'\n"))
        XCTAssertTrue(rendered.contains("MULTI=\"a\\nb\"\n"))
        XCTAssertTrue(rendered.contains("DOLLAR='a$b'\n"))
        // Round-trip: rendering then parsing recovers the values.
        let parsed = parseDotEnv(rendered)
        XCTAssertTrue(parsed.valid)
        let values = Dictionary(
            parsed.variables.map { ($0.key, $0.value) },
            uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(values["QUOTE"], "it's")
        XCTAssertEqual(values["MULTI"], "a\nb")
    }

    // MARK: renderSshConfig

    private func endpoint(
        _ id: String, alias: String, auth: String = "ssh_agent",
        via: String? = nil
    ) -> SshEndpointConfig {
        SshEndpointConfig(
            sectionId: id, name: id, alias: alias, host: "10.0.0.1",
            port: 22, username: "deploy", authMode: auth, connectVia: via)
    }

    func testRenderSshConfigBasic() throws {
        let config = try renderSshConfig(
            endpoints: [endpoint("e1", alias: "web")],
            forwards: [], privateKeyPaths: [:])
        XCTAssertTrue(config.contains("Host web\n"))
        XCTAssertTrue(config.contains("  HostName 10.0.0.1\n"))
        XCTAssertTrue(config.contains("  User deploy\n"))
        XCTAssertTrue(config.contains("  Port 22\n"))
    }

    func testRenderSshConfigProxyJumpChain() throws {
        let config = try renderSshConfig(
            endpoints: [
                endpoint("bastion", alias: "bastion"),
                endpoint("mid", alias: "mid", via: "bastion"),
                endpoint("app", alias: "app", via: "mid"),
            ],
            forwards: [], privateKeyPaths: [:])
        XCTAssertTrue(config.contains("  ProxyJump bastion\n"))
        XCTAssertTrue(config.contains("  ProxyJump bastion,mid\n"))
    }

    func testRenderSshConfigCycleThrows() {
        XCTAssertThrowsError(
            try renderSshConfig(
                endpoints: [
                    endpoint("a", alias: "a", via: "b"),
                    endpoint("b", alias: "b", via: "a"),
                ],
                forwards: [], privateKeyPaths: [:]))
    }

    func testRenderSshConfigForwardsAndKey() throws {
        let config = try renderSshConfig(
            endpoints: [endpoint("e1", alias: "db", auth: "private_key")],
            forwards: [
                SshForwardConfig(
                    endpointId: "e1", type: "local",
                    bindAddress: "127.0.0.1", bindPort: 15432,
                    destinationHost: "db.internal", destinationPort: 5432),
                SshForwardConfig(
                    endpointId: "e1", type: "dynamic",
                    bindAddress: "127.0.0.1", bindPort: 1080,
                    destinationHost: "", destinationPort: 0),
            ],
            privateKeyPaths: ["e1": "~/.ssh/id_ed25519"])
        XCTAssertTrue(
            config.contains("  IdentityFile \"~/.ssh/id_ed25519\"\n"))
        XCTAssertTrue(config.contains("  IdentitiesOnly yes\n"))
        XCTAssertTrue(config.contains(
            "  LocalForward 127.0.0.1:15432 db.internal:5432\n"))
        XCTAssertTrue(config.contains("  DynamicForward 127.0.0.1:1080\n"))
    }

    func testRenderSshConfigMissingKeyThrows() {
        XCTAssertThrowsError(
            try renderSshConfig(
                endpoints: [endpoint("e1", alias: "db", auth: "private_key")],
                forwards: [], privateKeyPaths: [:]))
    }

    // MARK: resolveSshPrivateKeyPaths

    func testResolveKeysAutoSelectsSingleDiscovery() async {
        let endpoints = [endpoint("e1", alias: "db", auth: "private_key")]
        var recorded: [String] = []
        let paths = await resolveSshPrivateKeyPaths(
            endpoints: endpoints, currentPaths: [:],
            discover: { ["~/.ssh/id_ed25519"] },
            select: { _ in nil },
            onSelected: { _, path in recorded.append(path) })
        XCTAssertEqual(paths?["e1"], "~/.ssh/id_ed25519")
        XCTAssertEqual(recorded, ["~/.ssh/id_ed25519"])
    }

    func testResolveKeysCancelReturnsNil() async {
        let endpoints = [endpoint("e1", alias: "db", auth: "private_key")]
        let paths = await resolveSshPrivateKeyPaths(
            endpoints: endpoints, currentPaths: [:],
            discover: { ["a", "b"] },
            select: { _ in nil },
            onSelected: { _, _ in })
        XCTAssertNil(paths)
    }

    // MARK: EnvironmentTemplateState sync

    func testEnvironmentSyncProducesStructuredPayloads() {
        let draft = EntryDraft(groupId: "g", kind: "core.environment")
        let state = EnvironmentTemplateState(draft: draft)
        state.project = " web-app "
        state.scope = "production"
        state.variables = [
            EnvVariableDraft(
                id: "f1", key: "API_KEY", value: "v", secret: true),
            EnvVariableDraft(
                id: "f2", key: "DEBUG", value: "1", secret: false),
        ]
        state.sync()
        XCTAssertTrue(draft.structuredErrors.isEmpty)
        let fields = draft.parsedCustomFields()
        XCTAssertEqual(fields?.count, 5)  // 3 metadata + 2 variables
        XCTAssertEqual(
            fields?.first?.semanticRole, "environment_project")
        let variable = fields?.last
        XCTAssertEqual(variable?.key, "env.DEBUG")
        XCTAssertEqual(variable?.protected, false)
        let sections = draft.parsedSections()
        XCTAssertEqual(sections?.count, 2)
        XCTAssertEqual(
            sections?.last?.semanticRole, "environment_variables")
        XCTAssertEqual(sections?.last?.fieldIds, ["f1", "f2"])
    }

    func testEnvironmentSyncValidatesNamesAndProject() {
        let draft = EntryDraft(groupId: "g", kind: "core.environment")
        let state = EnvironmentTemplateState(draft: draft)
        state.variables = [
            EnvVariableDraft(id: "f1", key: "1BAD", value: ""),
            EnvVariableDraft(id: "f2", key: "DUP", value: ""),
            EnvVariableDraft(id: "f3", key: "DUP", value: ""),
        ]
        state.sync()
        XCTAssertNotNil(draft.structuredErrors["environment_project"])
        XCTAssertNotNil(draft.structuredErrors["environment_variables"])
        XCTAssertFalse(draft.validate().isEmpty)
    }

    func testEnvironmentHydrateAndRemove() {
        // Build a stored detail view as the daemon would return it.
        let detail = EntryView(
            attachments: [],
            fields: [
                FieldView(
                    displayHint: nil, hasValue: true,
                    id: "meta_project", key: "environment.project",
                    label: "Project / repository", protected: false,
                    semanticRole: "environment_project",
                    sensitivity: .privateMetadata,
                    value: .text(FieldValue.FieldValueText(value: "app")),
                    valueType: "text"),
                FieldView(
                    displayHint: nil, hasValue: true,
                    id: "meta_scope", key: "environment.scope",
                    label: "Environment", protected: false,
                    semanticRole: "environment_scope",
                    sensitivity: .privateMetadata,
                    value: .text(FieldValue.FieldValueText(value: "prod")),
                    valueType: "text"),
                FieldView(
                    displayHint: "Stored", hasValue: true,
                    id: "var_secret", key: "env.SECRET",
                    label: "SECRET", protected: true,
                    semanticRole: "environment_variable",
                    sensitivity: .highlySensitive,
                    value: nil, valueType: "concealed"),
            ],
            hasNotes: false,
            metadata: ItemMetadata(
                favorite: false, groupId: "g", hasNotes: false,
                hasPassword: false, hasTotp: false, id: "item_e",
                kind: "core.environment", projectId: nil, revision: 2,
                title: "Env", updatedAt: "t", urls: [], username: nil),
            projectId: nil,
            sections: [
                ItemSection(
                    fieldIds: ["meta_project", "meta_scope"],
                    id: "environment_metadata", label: "Environment",
                    semanticRole: "environment_metadata"),
                ItemSection(
                    fieldIds: ["var_secret"], id: "environment_variables",
                    label: "Variables",
                    semanticRole: "environment_variables"),
            ],
            tags: [], templateVersion: 1)
        let draft = EntryDraft(editing: detail.metadata)
        let state = EnvironmentTemplateState(draft: draft)
        XCTAssertTrue(state.hydrate(detail: detail))
        XCTAssertEqual(state.project, "app")
        XCTAssertEqual(state.scope, "prod")
        XCTAssertEqual(state.variables.count, 1)
        XCTAssertTrue(state.variables[0].hasStoredValue)
        // Removing an existing variable records the removal.
        state.removeVariable(state.variables[0])
        XCTAssertEqual(draft.removeFieldIds, ["var_secret"])
        XCTAssertTrue(state.variables.isEmpty)
    }

    // MARK: SshTemplateState sync

    func testSshSyncBuildsEndpointSections() {
        let draft = EntryDraft(groupId: "g", kind: "core.ssh_server")
        let state = SshTemplateState(draft: draft)
        state.addEndpoint()
        let endpoint = state.endpoints[0]
        endpoint.name = "Web"
        endpoint.alias = "web"
        endpoint.host = "10.0.0.5"
        endpoint.username = "deploy"
        endpoint.authMode = "password"
        endpoint.password = "pw"
        state.sync()
        XCTAssertTrue(draft.structuredErrors.isEmpty)
        let fields = draft.parsedCustomFields()
        XCTAssertEqual(
            fields?.first(where: { $0.semanticRole == "ssh_alias" })?.key,
            "ssh.\(endpoint.id).alias")
        XCTAssertEqual(
            fields?.first(where: {
                $0.semanticRole == "ssh_password"
            })?.protected, true)
        let sections = draft.parsedSections()
        XCTAssertEqual(
            sections?.first?.semanticRole, "ssh_endpoint")
        XCTAssertEqual(sections?.first?.label, "Web")
    }

    func testSshSyncFlagsInvalidEndpoint() {
        let draft = EntryDraft(groupId: "g", kind: "core.ssh_server")
        let state = SshTemplateState(draft: draft)
        state.addEndpoint()
        state.sync()
        XCTAssertNotNil(draft.structuredErrors["ssh_endpoints"])
        XCTAssertFalse(draft.validate().isEmpty)
    }

    func testSshRemoveEndpointCascades() {
        let draft = EntryDraft(groupId: "g", kind: "core.ssh_server")
        let state = SshTemplateState(draft: draft)
        state.addEndpoint()
        state.addEndpoint()
        state.endpoints[0].name = "Bastion"
        state.endpoints[0].alias = "bastion"
        state.endpoints[0].host = "h"
        state.endpoints[1].connectVia = state.endpoints[0].id
        state.addForward()
        state.sync()
        let removedId = state.endpoints[0].id
        state.removeEndpoint(state.endpoints[0])
        XCTAssertEqual(state.endpoints.count, 1)
        XCTAssertTrue(state.forwards.isEmpty)
        XCTAssertEqual(state.endpoints[0].connectVia, "")
        XCTAssertTrue(draft.sshBindingsToClear.contains(removedId))
    }

    // MARK: EntryDraft JSON decode of editor output

    func testStructuredFieldsRoundTripThroughDraft() {
        let draft = EntryDraft(groupId: "g")
        draft.customFields = encodeItemFields([
            structuredTextField(
                id: "f1", key: "env.A", label: "A",
                role: "environment_variable", value: "1", secret: true),
        ])
        draft.sections = encodeStructuredSections([
            ItemSection(
                id: "s", label: "Vars", fieldIds: ["f1"],
                semanticRole: "environment_variables"),
        ])
        XCTAssertTrue(draft.validate()["custom_fields"] == nil)
        let fields = draft.parsedCustomFields()
        XCTAssertEqual(fields?[0].protected, true)
        XCTAssertEqual(fields?[0].sensitivity, .highlySensitive)
    }
}
