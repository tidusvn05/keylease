# ADR 0001: versioned envelope and key hierarchy

Status: accepted

Use a random 256-bit Account Root Key (ARK). A master password is processed by
Argon2id and HKDF domain separation to create a Password Unlock Key that wraps
the ARK. Each vault owns a random Vault Key wrapped by the ARK. Each item owns a
random Item Key wrapped by the Vault Key. Item payloads use XChaCha20-Poly1305.

All serialized envelopes carry a version and algorithm. Associated data binds
the purpose, account ID, vault ID, item ID, revision and schema version as
applicable. Nonces and item keys are freshly random. A password change creates a
new password slot and re-wraps only the ARK. Key-slot structure permits a future
device secret or recovery wrapping method without item rewrites.

The initial Argon2id profile is 64 MiB, 3 iterations and one lane. Parameters
are serialized per slot so they can be upgraded. Production releases require an
external crypto review and migration tests before storing real user data.
