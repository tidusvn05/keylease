import { expect, test } from "@playwright/test";

test("navigates between console pages", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await page.getByRole("button", { name: "EN" }).click();
  await page.getByRole("link", { name: "Approvals" }).click();
  await expect(page).toHaveURL(/\/approvals$/);
  await expect(page.getByRole("heading", { name: "Approvals" })).toBeVisible();
});
