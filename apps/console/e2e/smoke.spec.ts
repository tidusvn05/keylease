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
  await page.getByRole("button", { name: "EN" }).click();
  await page.getByRole("link", { name: "Approvals" }).click();
  await expect(page).toHaveURL(/\/approvals$/);
  await expect(page.getByRole("heading", { name: "Approvals" })).toBeVisible();
});
