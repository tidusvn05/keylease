import Foundation

import KeyLeaseCore

/// What the app last saw on one remote node.
struct RemoteVaultState: Equatable {
    var approvals: [ApprovalRecord] = []
    var trusts: [TrustRecord] = []
    var error: UserMessage?
    var loaded = false

    var pendingCount: Int { approvals.filter(\.decidableNow).count }
}

/// Paired headless vault nodes this Mac approves for (ADR 0005 mode B).
@MainActor @Observable
final class RemoteVaultsController {
    private(set) var vaults: [RemoteVault] = []
    private(set) var states: [String: RemoteVaultState] = [:]
    /// Raised with each node's pending approvals after a refresh.
    var onApprovals: (@MainActor ([ApprovalRecord], String) -> Void)?

    var pendingCount: Int { states.values.reduce(0) { $0 + $1.pendingCount } }

    func state(_ vault: RemoteVault) -> RemoteVaultState {
        states[vault.name] ?? RemoteVaultState()
    }

    /// Re-reads the profiles under `~/.keylease/remotes/`, including ones
    /// paired with `keylease remote add`.
    func reloadProfiles() {
        vaults = RemoteApproverStore.list()
        let names = Set(vaults.map(\.name))
        states = states.filter { names.contains($0.key) }
    }

    func refreshAll() async {
        reloadProfiles()
        for vault in vaults {
            await refresh(vault)
        }
    }

    func refresh(_ vault: RemoteVault) async {
        let client = RemoteApproverClient(vault: vault)
        var next = state(vault)
        do {
            async let approvals = client.approvals()
            async let trusts = client.trusts()
            next.approvals = try await approvals
            next.trusts = try await trusts
            next.error = nil
            next.loaded = true
            onApprovals?(next.approvals, vault.name)
        } catch {
            next.error = UserMessage(error)
        }
        states[vault.name] = next
    }

    func pair(name: String, url: String, code: String, deviceName: String)
        async throws
    {
        let vault = try await RemoteApproverClient.pair(
            name: name, url: url, code: code, deviceName: deviceName)
        reloadProfiles()
        await refresh(vault)
    }

    func decide(
        _ approval: ApprovalRecord, on vault: RemoteVault, approve: Bool,
        trust: TrustDecision?
    ) async throws {
        defer { Task { await self.refresh(vault) } }
        try await RemoteApproverClient(vault: vault)
            .decide(approval, approve: approve, trust: trust)
    }

    func revoke(_ trust: TrustRecord, on vault: RemoteVault) async {
        do {
            try await RemoteApproverClient(vault: vault).revokeTrust(trust)
        } catch {
            states[vault.name, default: RemoteVaultState()].error =
                UserMessage(error)
        }
        await refresh(vault)
    }

    func remove(_ vault: RemoteVault) {
        do {
            try RemoteApproverStore.remove(vault)
        } catch {
            states[vault.name, default: RemoteVaultState()].error =
                UserMessage(error)
            return
        }
        reloadProfiles()
    }
}
