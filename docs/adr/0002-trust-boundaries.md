# ADR 0002: Edge and managed trust modes

Status: accepted

Phase 1 supports `edge_local` only. Connection credentials are encrypted by the
local vault and are usable only inside the local service/connector runtime.
Cloud control-plane components, when introduced, receive ciphertext, versioned
policy metadata and redacted audit events but no decryption keys.

`managed_gateway` is a distinct future opt-in trust mode. It will require clear
UI/API disclosure and an isolated runtime capable of using credentials. The
system must fail closed and must not silently change execution location.
