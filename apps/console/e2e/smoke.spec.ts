import { expect, type Page, test } from "@playwright/test";

// The preview server has no keylease-server behind it, so the API is mocked.
async function mockApi(page: Page, signedIn: boolean) {
  await page.route("**/healthz", (route) =>
    route.fulfill({ json: { ok: true, service: "keylease-server", contract_version: "1" } }),
  );
  await page.route("**/v1/console/sso", (route) => route.fulfill({ json: { enabled: false } }));
  await page.route("**/v1/console/me", (route) =>
    signedIn
      ? route.fulfill({
          json: { account_id: "acct_test", owner_device: "laptop", passkeys: 1, passkeys_available: true },
        })
      : route.fulfill({ status: 403, json: { error: "not signed in" } }),
  );
}

test("shows the sign-in screen without a session", async ({ page }) => {
  await mockApi(page, false);
  await page.goto("/");
  await expect(page.getByText("Sign in to KeyLease")).toBeVisible();
});

test("navigates between console pages", async ({ page }) => {
  await mockApi(page, true);
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await page.getByRole("button", { name: "EN", exact: true }).click();
  await page.getByRole("link", { name: "Approvals" }).click();
  await expect(page).toHaveURL(/\/approvals$/);
  await expect(page.getByRole("heading", { name: "Approvals" })).toBeVisible();
});

test("lists a node's pending approvals", async ({ page }) => {
  await mockApi(page, true);
  const now = new Date().toISOString();
  await page.route("**/v1/console/approvals", (route) =>
    route.fulfill({
      json: {
        nodes: [
          {
            member_id: "member_node_1",
            name: "vps-1",
            role: "node",
            reported_at: now,
            approvals: [
              {
                id: "ap-1",
                request_digest_hex: "ab".repeat(32),
                policy_version: 3,
                state: "pending",
                expires_at: new Date(Date.now() + 600_000).toISOString(),
                agent_id: "agent-claude",
                action: "ssh:sign",
                resource: "kl://vault/item/1",
                purpose: "deploy the site",
              },
            ],
          },
        ],
        decisions: [],
      },
    }),
  );
  await page.goto("/approvals");
  await page.getByRole("button", { name: "EN", exact: true }).click();
  await expect(page.getByText("vps-1")).toBeVisible();
  await expect(page.getByText("ssh:sign")).toBeVisible();
  await expect(page.getByText("agent-claude")).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Deny" })).toBeVisible();
});
