-- Personal devices (v2 plan, step 10): an owner's other devices join with a
-- `device` invite and sync two-way with the owner device.

ALTER TABLE relay_members DROP CONSTRAINT relay_members_role_check;
ALTER TABLE relay_members
    ADD CONSTRAINT relay_members_role_check CHECK (role IN ('owner', 'node', 'device'));
ALTER TABLE relay_invites
    ADD COLUMN role TEXT NOT NULL DEFAULT 'node' CHECK (role IN ('node', 'device'));
