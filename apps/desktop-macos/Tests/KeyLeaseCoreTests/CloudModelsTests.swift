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

    /// `test-vectors/rpc/cloud/nodes.json`, written by the Rust test
    /// `node_request_and_adopt_wires_match_the_shared_vector`.
    func testNodesRequestsAndAdoptDecodeTheSharedVector() throws {
        let url = rpcTestVectors.appendingPathComponent("cloud/nodes.json")
        let vector = try JSONDecoder().decode(
            JSONValue.self, from: Data(contentsOf: url))
        let nodes = try XCTUnwrap(vector["nodes"]).decoded(as: [CloudNodeView].self)
        XCTAssertEqual(nodes.first?.name, "vps-prod")
        XCTAssertEqual(nodes.first?.isNode, true)
        XCTAssertEqual(nodes.first?.copies, 4)
        let requests = try XCTUnwrap(vector["requests"])
            .decoded(as: [CloudShareRequest].self)
        XCTAssertEqual(requests.first?.isPending, true)
        XCTAssertEqual(requests.first?.hint, "stripe live key")
        XCTAssertNil(requests.first?.shareId)
        let adopt = try XCTUnwrap(vector["adopt"]).decoded(as: AdoptReport.self)
        XCTAssertEqual(adopt.adopted.count, 2)
        XCTAssertEqual(adopt.projects, ["billing"])
        XCTAssertEqual(adopt.itemShares, 1)
    }
}
