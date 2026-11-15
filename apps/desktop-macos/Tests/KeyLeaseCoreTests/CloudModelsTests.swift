import Foundation
import XCTest

@testable import KeyLeaseCore

/// Decodes `test-vectors/rpc/cloud/overview.json`, which the Rust test
/// `overview_wire_matches_the_shared_vector` serializes byte for byte.
final class CloudModelsTests: XCTestCase {
    func testOverviewDecodesTheSharedVector() throws {
        let url = rpcTestVectors.appendingPathComponent("cloud/overview.json")
        let overview = try JSONDecoder().decode(
            CloudOverview.self, from: Data(contentsOf: url))
        XCTAssertTrue(overview.linked)
        XCTAssertTrue(overview.isOwner)
        XCTAssertEqual(overview.url, "https://keys.example.com")
        XCTAssertNil(overview.lastError)
        XCTAssertEqual(overview.nodes, 2)
        XCTAssertEqual(overview.pendingRequests, 1)
        XCTAssertTrue(overview.consoleApprovals.enabled)
        XCTAssertEqual(overview.consoleApprovals.passkeys, ["MacBook Touch ID"])
        XCTAssertTrue(overview.consoleApprovals.shareAudit)
        XCTAssertEqual(overview.org?.orgName, "Acme")
        XCTAssertNil(overview.org?.policyVersion)
    }

    func testUnlinkedOverviewDecodes() throws {
        let json = """
            {"linked":false,"nodes":0,"active_shares":0,"pending_requests":0,
             "console_approvals":{"enabled":false,"passkeys":[],"share_audit":false}}
            """
        let overview = try JSONDecoder().decode(
            CloudOverview.self, from: Data(json.utf8))
        XCTAssertFalse(overview.linked)
        XCTAssertFalse(overview.isOwner)
        XCTAssertNil(overview.org)
        XCTAssertFalse(overview.consoleApprovals.enabled)
    }
}
