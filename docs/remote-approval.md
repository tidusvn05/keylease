# Approving a headless vault from another device

Step 5 of [ADR 0005](adr/0005-agent-trust-and-secret-use.md) (mode B). A VPS
running `keylease serve` has no desktop to approve on. Pair an **approver
device** with it — the macOS app or the `keylease remote` CLI on your
laptop — and approve the VPS agents' requests from there.

The approver API exposes **no vault access**: it can pair a device, list and
decide pending approvals, and list and revoke trusts. Nothing else.

## On the VPS

Serve the approver API on loopback and put TLS in front of it:

```sh
keylease --db /var/lib/keylease/vault.sqlite serve \
  --approver-listen 127.0.0.1:7443
```

```caddyfile
vault.example.com {
    reverse_proxy 127.0.0.1:7443
}
```

A private network (Tailscale, WireGuard) works as well. Binding the API to a
non-loopback address needs `--approver-listen-public`, because the pairing
code and approval metadata would otherwise travel unencrypted.

Create a one-time pairing code (master password; valid for 10 minutes):

```sh
keylease --db /var/lib/keylease/vault.sqlite remote pairing-code
```

## In the macOS app

Native app only (`apps/desktop-macos-app`), not the Flutter desktop app.
**Remote Vaults → Pair a remote vault**: a name, the approver URL (`https://`,
or `http://localhost` through an SSH tunnel), the pairing code and how this
Mac should appear on the node. The app generates the Ed25519 key in the login
Keychain (this device only) and writes the same `~/.keylease/remotes/NAME.json`
profile as the CLI, so remotes paired from either side show up in both; a
CLI-paired remote keeps using its `NAME.key` file.

While the local vault is unlocked, the app polls each node every 15 seconds,
notifies about new requests, and shows them with the same **Approve…** sheet as
local approvals. Every remote approval asks for Touch ID or the login password.
**Forget** deletes the key on this Mac; revoke the device on the node as well.

Listing approvals and trusts through the approver API does not count as vault
activity on the node, so a polling approver never keeps an idle node unlocked.

## On the laptop (CLI)

```sh
keylease remote add vps --url https://vault.example.com --code ABCD… --device-name laptop
keylease remote approvals vps
keylease remote decide vps APPROVAL_ID --approve
keylease remote decide vps APPROVAL_ID --approve --trust 1h --scope item
keylease remote decide vps APPROVAL_ID --deny
keylease remote trusts vps
keylease remote revoke-trust vps TRUST_ID
```

`remote add` generates an Ed25519 key in `~/.keylease/remotes/vps.key`
(mode 0600) and registers only its public key on the VPS. The trust durations
and risk-tier caps are the same as for local approvals
(`docs/agent-approvals.md`).

## How a decision is protected

- Every request is signed over
  `KEYLEASE-APPROVER-V1\nMETHOD\nPATH\nUNIX_TIME\nSHA256(body)` and must be
  within two minutes of the node's clock.
- A decision carries the pending approval's `request_digest_hex` and
  `policy_version`, re-read just before deciding. If the request changed, the
  decision is refused, so a replayed or stale decision cannot approve
  something else.
- The device is never an agent, so it cannot be the requester it approves.
- Pairing, decisions and trust revocations are audited under the device ID.

## Managing devices (on the VPS)

```sh
keylease --db /var/lib/keylease/vault.sqlite remote devices
keylease --db /var/lib/keylease/vault.sqlite remote revoke-device DEVICE_ID
```

A revoked device's signatures stop working immediately. Trusts it granted stay
until they expire; revoke them too if the device was lost.

## Not done yet

- The mobile app does not speak this protocol yet. The macOS app keeps the
  key in the Keychain, not the Secure Enclave (which has no Ed25519).
- No push: approvers poll. The Mac polls only while its own vault is
  unlocked.
- Remote unlock (ADR 0005 section 8) is not implemented; unlock the VPS as
  described in `docs/agent-approvals.md`.
