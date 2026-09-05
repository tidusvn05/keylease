# ADR 0003: one command and policy boundary

Status: accepted

All clients construct the versioned requests in `keylease-core` and call
`KeyLeaseService`. The service validates schema, authenticates the actor,
canonicalizes connector resources, invokes the policy engine, consumes an
approval/lease, performs the mutation or connector action and appends an audit.

SQLite is the single-writer transaction boundary. CLI, Flutter, future MCP and
import/export code may not open the store directly in production composition.
This keeps authorization behavior transport-independent and permits storage and
KDBX implementations to change without modifying domain/service tests.
