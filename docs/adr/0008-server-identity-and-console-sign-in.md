# ADR 0008: Server identity and console sign-in

Status: accepted (P2 step 1)

## Context

`keylease-server` already knows who its users are: the relay (ADR 0006) has
**accounts**, each with one **owner** member (the owner's device) and any
number of **node** members (VPSes), all identified by Ed25519 keys. The v2
plan adds a web console (KeyLease Console). It needs a way for a person to
sign in from a browser that does not hold a device key, without adding
passwords that the server would have to protect.

## Decision

1. **User = relay account; device = relay member.** No separate user table:
   the account is the user, the owner member is the user's primary device, and
   nodes are workload devices. Organizations (P3) group accounts later.
2. **First sign-in by device link.** The owner device runs
   `keylease cloud console`: it picks a random 32-byte token, signs
   `POST /v1/relay/console-links` with its relay key and the token's SHA-256
   (valid at most 15 minutes), and prints `…/console/#login=TOKEN`. The token
   travels in the URL fragment, so it never reaches server logs or `Referer`
   headers; the console exchanges it once (`POST /v1/console/session`).
3. **Passkeys for later sign-ins.** A signed-in console registers WebAuthn
   credentials bound to the host of `KEYLEASE_SERVER_PUBLIC_URL`: ES256 only,
   `none` attestation, user presence required, discoverable credentials, the
   signature counter checked when the authenticator keeps one. Challenges are
   single use and expire after five minutes. Without a public URL only device
   links work.
4. **Sessions** are random 256-bit cookies (`kl_session`; HttpOnly, Secure,
   SameSite=Strict, 12 hours), stored as SHA-256 hashes and revocable.
   State-changing console requests also need the header
   `x-keylease-console: 1`, which a cross-site page cannot send without a
   CORS preflight the server does not allow.
5. **Console scope (v1):** the account, its devices (nodes can be revoked;
   the owner device cannot), passkeys, sign-out. It sees metadata, never
   vault plaintext: Private projects stay end-to-end encrypted.

## Consequences

- No passwords on the server; losing every passkey only means signing in
  again from the owner device.
- A stolen session cookie gives what the console gives: listing and revoking
  nodes and passkeys, not secrets.
- RS256-only authenticators (some Windows Hello configurations) cannot
  register yet; adding RS256 is a contained change in `webauthn.rs`.
- Approvals signed with passkeys (plan section 5) build on these credentials
  in a later step.
