# Teams: organizations, roles and project access

A self-hosted `keylease-server` can hold **organizations**: teams whose members
each sign in to the [console](console.md) with their own account (v2 plan,
P3). Everything here is in the console under **Organizations**.

## Roles

| Organization role | Can |
|---|---|
| Owner | everything; change owners and admins; there is always at least one owner |
| Admin | invite members and viewers, create projects, grant project access; every project |
| Member | the projects granted to them, with the granted role |
| Viewer | the projects granted to them, read only |

Project roles are **read**, **write** and **admin** (an admin of a project
grants access to it). Owners and admins are admins of every project.

## Getting people in

1. Create an organization (you become its owner).
2. **Invite** with a role: the console shows a one-time code, valid 7 days.
3. The new member signs in to the console with their own account
   (`keylease cloud console` on their device) and uses **Join with an invite
   code**.

Removing a member removes their project access; anyone may leave, except the
last owner.

## Projects

Organization projects have environments like personal ones (dev, staging,
production; production protected), and their secrets are stored on the server
(see Managed secrets below).

## Managed secrets

With `KEYLEASE_KMS_ROOT_KEY_FILE` set on the server (32 random bytes, unpadded
base64, mode 0600; back it up apart from the database), each organization
project has **Secrets** in the console: KEY=VALUE per environment, encrypted
with the project's data key, which the root key wraps
([ADR 0010](adr/0010-managed-projects-and-kms.md)).

- **read** lists and reveals (each reveal is audited), **write** sets,
  deletes and restores old versions, **admin** rotates the data key and reads
  the audit.
- Every change is a new version: **History** shows them and **Restore** makes
  an old one current again.
- The server can decrypt Managed secrets; keep what its operator must not see
  in a Private project.

```sh
head -c 32 /dev/urandom | base64 | tr -d '=' > kms_root_key && chmod 600 kms_root_key
KEYLEASE_KMS_ROOT_KEY_FILE=/run/keylease-secrets/kms_root_key
```

## Change requests in protected environments

In a protected environment (production by default), a change by someone who
is not a project admin (set, delete or restore) does not apply at once: it
becomes a **change request**, shown on the Secrets page as "Waiting for
approval". Another project admin approves it (the change is then recorded as
the requester's) or rejects it. Nobody approves their own change, and
project admins change protected environments directly. Proposals, approvals
and rejections are in the project's audit.
