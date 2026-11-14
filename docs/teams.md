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
production; production protected). Storing their secrets on the server
(Managed projects, encrypted with the server's key) comes with the next step;
until then, members keep a project's items in their own vaults and share them
with bundles or the relay.
