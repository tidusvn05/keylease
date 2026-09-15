import Foundation
import XCTest

@testable import KeyLeaseCore

/// `PasswordGeneratorSettings` parity with
/// `password_generator_settings.dart` and `AgentCreation` with
/// `agent_driven_creation.dart`.
final class PasswordGeneratorAndAgentTests: XCTestCase {
    private func object<T: Encodable>(_ value: T) throws -> [String: JSONValue]
    {
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder()
            .decode(JSONValue.self, from: data)
        return try XCTUnwrap(decoded.objectValue)
    }

    // MARK: Settings round trip

    func testDefaultsAndJsonRoundTrip() {
        let defaults = PasswordGeneratorSettings()
        XCTAssertEqual(defaults.pattern, .random)
        XCTAssertEqual(defaults.length, 24)
        XCTAssertTrue(defaults.uppercase)
        XCTAssertEqual(defaults.wordCount, 5)
        XCTAssertEqual(defaults.pinLength, 6)
        // fromJson(toJson(x)) is the identity.
        XCTAssertEqual(
            PasswordGeneratorSettings(json: .object(defaults.jsonObject)),
            defaults)
        // Unknown/out-of-range values fall back to defaults.
        let clamped = PasswordGeneratorSettings(
            json: .object(["length": .int(999), "word_count": .int(0)]))
        XCTAssertEqual(clamped.length, defaults.length)
        XCTAssertEqual(clamped.wordCount, defaults.wordCount)
    }

    func testRecipeEncoding() throws {
        var settings = PasswordGeneratorSettings()
        settings.numbers = false
        let recipe = try object(settings.recipe)
        XCTAssertEqual(recipe["type"]?.stringValue, "random")
        XCTAssertEqual(recipe["length"]?.intValue, 24)
        XCTAssertEqual(recipe["numbers"]?.boolValue, false)
        XCTAssertEqual(recipe["symbols"]?.boolValue, true)
        XCTAssertEqual(recipe["avoid_ambiguous"]?.boolValue, true)

        settings.pattern = .pin
        let pin = try object(settings.recipe)
        XCTAssertEqual(pin["type"]?.stringValue, "pin")
        XCTAssertEqual(pin["length"]?.intValue, 6)

        settings.pattern = .words
        let words = try object(settings.recipe)
        XCTAssertEqual(words["type"]?.stringValue, "words")
        XCTAssertEqual(words["count"]?.intValue, 5)
        XCTAssertEqual(words["separator"]?.stringValue, "-")
        XCTAssertEqual(words["include_number"]?.boolValue, true)
    }

    // MARK: Entropy estimate parity with Dart

    func testPasswordEntropy() {
        var settings = PasswordGeneratorSettings()
        // pool = 24 upper + 25 lower + 8 digits + 14 symbols = 71.
        XCTAssertEqual(
            settings.estimatedEntropyBits, Int((24 * log2(71.0)).rounded()))
        settings.symbols = false
        XCTAssertEqual(
            settings.estimatedEntropyBits, Int((24 * log2(57.0)).rounded()))
    }

    func testPassphraseAndPinEntropy() {
        var settings = PasswordGeneratorSettings()
        settings.pattern = .words
        // Dart: wordCount * 12 + (wordNumber ? 7 : 0)
        XCTAssertEqual(settings.estimatedEntropyBits, 5 * 12 + 7)
        settings.wordNumber = false
        XCTAssertEqual(settings.estimatedEntropyBits, 60)
        settings.pattern = .pin
        XCTAssertEqual(
            settings.estimatedEntropyBits,
            Int((6 * log2(10.0)).rounded()))
    }

    func testStrengthLabels() {
        var settings = PasswordGeneratorSettings()
        settings.pattern = .pin
        settings.pinLength = 4  // ~13 bits
        XCTAssertEqual(settings.strengthLabel, "Weak")
        settings.pattern = .words
        settings.wordCount = 4
        settings.wordNumber = false  // 48 bits
        XCTAssertEqual(settings.strengthLabel, "Fair")
        settings.wordNumber = true  // 55 bits… under 60 → Fair
        XCTAssertEqual(settings.strengthLabel, "Fair")
        settings.wordCount = 6  // 79 bits
        XCTAssertEqual(settings.strengthLabel, "Strong")
        settings.pattern = .random  // ~148 bits
        XCTAssertEqual(settings.strengthLabel, "Very strong")
    }

    // MARK: Agent creation

    func testRecipesCoverExpectedKinds() {
        XCTAssertEqual(agentCreationRecipes.count, 8)
        XCTAssertEqual(
            agentCreationRecipes.map(\.id),
            ["describe", "project", "dotenv", "ssh_config", "ssh_topology",
             "credential", "prompt", "runbook"])
        let ssh = agentCreationRecipes.first { $0.id == "ssh_config" }
        XCTAssertEqual(ssh?.defaultKind, "core.ssh_server")
        XCTAssertEqual(ssh?.defaultSourcePath, "~/.ssh/config")
    }

    func testApplyRecipeResetsHandoff() {
        let draft = AgentCreationDraft(kind: "core.login", groupId: "g")
        XCTAssertFalse(draft.isDirty)
        draft.applyRecipe(agentCreationRecipes[2])  // dotenv
        XCTAssertEqual(draft.recipeId, "dotenv")
        XCTAssertEqual(draft.kind, "core.environment")
        XCTAssertTrue(draft.isDirty)
    }

    func testHandoffInputShape() throws {
        let draft = AgentCreationDraft(kind: "core.login", groupId: "g1")
        draft.applyRecipe(agentCreationRecipes[3])  // ssh_config
        draft.context = " capture bastion "
        draft.sourcePath = "~/.ssh/config"
        let input = try object(draft.handoffInput(expectedVaultId: "vault_1"))
        XCTAssertEqual(input["agent_access"]?.stringValue, "read_write")
        XCTAssertEqual(input["expected_vault_id"]?.stringValue, "vault_1")
        XCTAssertEqual(input["group_id"]?.stringValue, "g1")
        XCTAssertEqual(input["kind"]?.stringValue, "core.ssh_server")
        XCTAssertEqual(input["protocol_version"]?.intValue, 1)
        XCTAssertEqual(input["recipe_id"]?.stringValue, "ssh_config")
        XCTAssertEqual(input["source_path"]?.stringValue, "~/.ssh/config")
        XCTAssertEqual(input["context"]?.stringValue, "capture bastion")
    }

    func testHandoffInputForAgentContentOmitsGroup() throws {
        let draft = AgentCreationDraft(kind: "core.prompt", groupId: "g1")
        draft.recipeId = "prompt"
        draft.tags = "x, y ,x"
        draft.projectSlug = "web"
        let input = try object(draft.handoffInput(expectedVaultId: "v"))
        XCTAssertNil(input["group_id"])
        XCTAssertEqual(input["project_slug"]?.stringValue, "web")
        XCTAssertEqual(input["tags"], .array([.string("x"), .string("y")]))
    }

    func testParsedTagsDedup() {
        let draft = AgentCreationDraft(kind: "core.note", groupId: nil)
        draft.tags = "ops, prod, ops, , "
        XCTAssertEqual(draft.parsedTags, ["ops", "prod"])
    }

    func testInvalidateHandoff() {
        let draft = AgentCreationDraft(kind: "core.login", groupId: nil)
        draft.handoff = AgentNewItemHandoffReceipt(
            command: "keylease agent …", expiresAt: "2030-01-01T00:00:00Z",
            handoffId: "h", protocolVersion: 1)
        draft.handoffCopied = true
        draft.invalidateHandoff()
        XCTAssertNil(draft.handoff)
        XCTAssertFalse(draft.handoffCopied)
    }
}
