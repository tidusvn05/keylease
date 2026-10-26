# Approving a headless vault from another device

Step 5 of [ADR 0005](adr/0005-agent-trust-and-secret-use.md) (mode B). A VPS
running `keylease serve` has no desktop to approve on. Pair an **approver
device** with it — today the `keylease remote` CLI on your laptop; the macOS app
can implement the same protocol — and approve the VPS agents' requests from
there.

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

## On the laptop

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

- The macOS and mobile apps do not speak this protocol yet; they need a
  "Remote vaults" settings pane that does what `keylease remote` does, keeping
  the key in the Keychain / Secure Enclave.
- No push: the approver polls `remote approvals`.
- Remote unlock (ADR 0005 section 8) is not implemented; unlock the VPS as
  described in `docs/agent-approvals.md`.
