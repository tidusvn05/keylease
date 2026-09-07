// Run against the local preview. Uses an installed Playwright or PLAYWRIGHT_MODULE.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, colorScheme: 'light', permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  const output = fs.mkdtempSync(path.join(os.tmpdir(), 'keylease-prototype-'));
  let checks = 0;
  async function check(name, operation) { await operation(); checks++; console.log(`PASS ${name}`); }
  const scenario = value => page.locator('#scenario').selectOption(value);
  const action = name => page.locator(`[data-action="${name}"]`);
  try {
    await page.goto(process.env.PROTOTYPE_URL || 'http://127.0.0.1:4173');
    await check('initial three-pane layout', async () => { assert.equal(await page.locator('.entry-row').count(), 9); assert.equal(await page.locator('#detail h2').textContent(), 'GitHub'); });
    await page.screenshot({ path: path.join(output, 'vault-light.png') });
    await check('search and empty result', async () => { await page.locator('#search').fill('linear'); assert.equal(await page.locator('.entry-row').count(), 1); assert.equal(await page.locator('#detail h2').textContent(), 'Linear'); await page.locator('#search').fill('does-not-exist'); assert.equal(await page.locator('.entry-row').count(), 0); await action('clear-search').click(); });
    await check('keyboard search and row navigation', async () => { await page.keyboard.press('Meta+f'); assert.equal(await page.locator('#search').evaluate(e => e === document.activeElement), true); await page.locator('.entry-row').first().focus(); await page.keyboard.press('ArrowDown'); assert.equal(await page.locator('#detail h2').textContent(), 'Google Workspace'); });
    await page.locator('[data-entry="github"]').click();
    await check('reveal and real demo clipboard', async () => { await action('reveal').click(); assert.match(await page.locator('#detail').textContent(), /Demo-only/); await action('copy-password').click(); assert.equal(await page.evaluate(() => navigator.clipboard.readText()), 'Demo-only!47-sample'); await action('reveal').click(); assert.doesNotMatch(await page.locator('#detail').textContent(), /Demo-only/); });
    await check('edit cancellation protects draft', async () => { await action('edit').click(); await page.locator('[name="title"]').fill('Unsaved'); await page.getByRole('button', { name: 'Cancel', exact: true }).click(); assert.equal(await page.locator('#discard-warning').count(), 1); await page.locator('#keep-editing').click(); assert.equal(await page.locator('[name="title"]').inputValue(), 'Unsaved'); await page.keyboard.press('Escape'); await page.locator('#discard-changes').click(); assert.equal(await page.locator('#detail h2').textContent(), 'GitHub'); });
    await check('create and escape user text', async () => { await page.locator('#new-button').click(); await page.locator('[name="title"]').fill('Sample <login>'); await page.locator('[name="username"]').fill('demo@example.com'); await page.locator('[name="password"]').fill('Fictional-password-1'); await page.getByRole('button', { name: 'Save item', exact: true }).click(); assert.equal(await page.locator('#detail h2').textContent(), 'Sample <login>'); });
    await check('edit and save', async () => { await action('edit').click(); await page.locator('[name="notes"]').fill('Updated demo notes'); await page.getByRole('button', { name: 'Save item', exact: true }).click(); assert.equal(await page.locator('.note').textContent(), 'Updated demo notes'); });
    await check('delete confirmation', async () => { await action('more').click(); await action('delete').click(); await page.getByRole('button', { name: 'Delete item', exact: true }).click(); assert.equal(await page.locator('.entry-row').count(), 5); });
    await check('approval review and decision', async () => { await page.locator('[data-page="approvals"]').click(); await action('approve').first().click(); assert.match(await page.locator('#dialog').textContent(), /Read this file once/); await page.getByRole('button', { name: 'Approve once', exact: true }).click(); assert.equal(await page.locator('.approval-card').count(), 1); await action('deny').click(); await page.getByRole('button', { name: 'Deny request', exact: true }).click(); assert.equal(await page.locator('.approval-card').count(), 0); });
    await check('connection disconnect and reconnect', async () => { await page.locator('[data-page="connections"]').click(); await action('manage-connection').first().click(); await page.getByRole('button', { name: 'Disconnect…', exact: true }).click(); await page.getByRole('button', { name: 'Disconnect', exact: true }).click(); assert.match(await page.locator('.connection-card').first().textContent(), /Disconnected/); await action('manage-connection').first().click(); await page.getByRole('button', { name: 'Reconnect demo', exact: true }).click(); assert.doesNotMatch(await page.locator('.connection-card').first().textContent(), /Disconnected/); });
    await check('activity filters reflect actions', async () => { await page.locator('[data-page="activity"]').click(); assert.match(await page.locator('tbody').textContent(), /Request approved/); await page.locator('[data-filter="Denied"]').click(); assert.doesNotMatch(await page.locator('tbody').textContent(), /Allowed/); });
    await check('settings cancel and save', async () => { await page.locator('#settings-button').click(); await page.locator('[name="appearance"]').selectOption('dark'); await page.getByRole('button', { name: 'Cancel', exact: true }).click(); assert.equal(await page.locator('html').getAttribute('data-theme'), 'light'); await page.locator('#settings-button').click(); await page.locator('[name="appearance"]').selectOption('dark'); await page.getByRole('button', { name: 'Save changes' }).click(); assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark'); });
    await scenario('ready');
    await page.screenshot({ path: path.join(output, 'vault-dark.png') });
    await check('lock removes details and wrong password gives recovery', async () => { await page.locator('#lock-button').click(); assert.equal(await page.locator('#detail').count(), 0); await page.locator('#master-password').fill('wrong'); await page.getByRole('button', { name: 'Unlock vault', exact: true }).click(); assert.match(await page.locator('#unlock-error').textContent(), /did not work/); await page.locator('#master-password').fill('demo'); await page.getByRole('button', { name: 'Unlock vault', exact: true }).click(); assert.equal(await page.locator('.entry-row').count(), 9); });
    await check('onboarding, offline, permissions and empty states', async () => { await scenario('setup'); await action('choose-demo-client').click(); assert.equal(await page.locator('#scenario').inputValue(), 'locked'); await scenario('offline'); await action('retry').click(); assert.equal(await page.locator('#scenario').inputValue(), 'locked'); await scenario('denied'); assert.match(await page.locator('#workspace').textContent(), /Permission needed/); await scenario('empty'); assert.equal(await page.locator('.entry-row').count(), 0); assert.match(await page.locator('#entry-list').textContent(), /A fresh start/); });
    await scenario('ready'); await page.locator('#theme-toggle').click();
    await check('800×600 list/detail adaptation', async () => { await page.setViewportSize({ width: 800, height: 600 }); assert.equal(await page.locator('#detail').isVisible(), false); await page.locator('[data-entry="github"]').click(); assert.equal(await page.locator('#detail').isVisible(), true); assert.equal(await page.locator('.entry-panel').isVisible(), false); await page.screenshot({ path: path.join(output, 'vault-800.png') }); await action('back').click(); assert.equal(await page.locator('.entry-panel').isVisible(), true); });
    await check('no horizontal page overflow across preview sizes and routes', async () => {
      for (const width of [390, 800, 1280]) {
        await page.setViewportSize({ width, height: width === 800 ? 600 : 800 });
        for (const value of ['ready', 'locked', 'setup', 'offline', 'denied', 'empty']) { await scenario(value); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `${width} ${value}`); }
        await scenario('ready');
        for (const route of ['connections', 'approvals', 'activity']) {
          if (!await page.locator(`[data-page="${route}"]`).isVisible()) await page.locator('#show-sidebar').click();
          await page.locator(`[data-page="${route}"]`).click();
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `${width} ${route}`);
          assert.equal(await page.locator('.page').evaluate(e => e.scrollWidth <= e.clientWidth), true, `${width} ${route} internal overflow`);
        }
      }
    });
    await check('no runtime exceptions', async () => assert.deepEqual(errors, []));
    console.log(JSON.stringify({ checks, browser: browser.version(), screenshots: output }, null, 2));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
