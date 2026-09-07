/* Local design prototype. All records and credentials are fictional. No RPC. */
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const escapeHTML = (value = '') => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const paths = {
  key: '<circle cx="8" cy="8" r="5"/><path d="m12 12 9 9m-5-5 3-3m-6 0 3-3"/>',
  vault: '<rect x="4" y="3" width="16" height="18" rx="3"/><circle cx="12" cy="12" r="4"/><path d="M12 8v8m-4-4h8"/>',
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  folder: '<path d="M3 7V5a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/>',
  star: '<path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2-5.6-3-5.6 3 1.1-6.2L3 9.6l6.2-.9Z"/>',
  link: '<path d="m10 13 4-4m-5 6-2 2a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0m2 2 2-2a4 4 0 0 1 6 6l-4 4a4 4 0 0 1-6 0" transform="translate(1 0)"/>',
  shield: '<path d="M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7Z"/><path d="m8 12 3 3 5-6"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  settings: '<path d="m9 3-1 3-3 1-2 3 2 2-1 3 3 2 1 3h4l1-3 3-1 3-3-2-2 1-3-3-2-1-3Z" transform="translate(1 0)"/><circle cx="12" cy="12" r="3"/>',
  sidebar: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  copy: '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
  eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
  eyeoff: '<path d="m3 3 18 18M10 5h2c6 0 10 7 10 7a20 20 0 0 1-3 4M6 6a21 21 0 0 0-4 6s4 7 10 7c2 0 4-1 5-2"/>',
  external: '<path d="M14 3h7v7m0-7L10 14m0-10H5a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h13a2 2 0 0 0 2-2v-5"/>',
  chevron: '<path d="m9 5 7 7-7 7"/>',
  back: '<path d="m14 5-7 7 7 7"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1 1m12 12 1 1M5 19l1-1M18 6l1-1"/>',
  moon: '<path d="M20 14A9 9 0 0 1 10 3a9 9 0 1 0 10 11Z"/>',
  more: '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>',
  warning: '<path d="m12 3 10 18H2Z"/><path d="M12 9v5m0 3v.1"/>',
  refresh: '<path d="M20 10a8 8 0 1 0-1 8M20 3v7h-7"/>',
  trash: '<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7"/>',
  monitor: '<rect x="3" y="3" width="18" height="13" rx="2"/><path d="M8 21h8m-4-5v5"/>',
};
function icon(name, className = '') { return `<svg class="icon ${className}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.key}</svg>`; }
function paintIcons() { $$('[data-icon]').forEach(el => { el.innerHTML = icon(el.dataset.icon); }); }
function ib(name, label, action, extra = '') { return `<button class="icon-button" aria-label="${escapeHTML(label)}" title="${escapeHTML(label)}" data-action="${action}" ${extra}>${icon(name)}</button>`; }
function brand(entry, large = false) { return `<span class="brand-icon ${escapeHTML(entry.color || '')}${large ? ' large' : ''}" aria-hidden="true">${escapeHTML(entry.mark || entry.title.slice(0, 1))}</span>`; }

const seedEntries = [
  { id: 'github', title: 'GitHub', username: 'alex@northstar.example', url: 'https://github.com', group: 'Work', mark: 'GH', color: 'ink', favorite: true, notes: 'Primary account for engineering.\nRecovery codes are stored in the team’s offline backup.', totp: true },
  { id: 'google', title: 'Google Workspace', username: 'alex@northstar.example', url: 'https://workspace.google.com', group: 'Work', mark: 'G', color: 'blue', favorite: true, notes: 'Workspace administrator account.', totp: true },
  { id: 'linear', title: 'Linear', username: 'alex@northstar.example', url: 'https://linear.app', group: 'Work', mark: 'L', color: 'blue', favorite: false, notes: 'Product planning and issue tracking.' },
  { id: 'notion', title: 'Notion', username: 'alex@northstar.example', url: 'https://notion.so', group: 'Work', mark: 'N', color: '', favorite: false, notes: 'Team knowledge base.' },
  { id: 'figma', title: 'Figma', username: 'alex@northstar.example', url: 'https://figma.com', group: 'Work', mark: 'F', color: 'red', favorite: false, notes: 'Design workspace.' },
  { id: 'aws', title: 'AWS Console', username: 'alex.admin', url: 'https://aws.amazon.com', group: 'Infrastructure', mark: 'a', color: 'orange', favorite: false, notes: 'Development environment. Use a scoped connection for automation.', totp: true },
  { id: 'cloudflare', title: 'Cloudflare', username: 'alex@northstar.example', url: 'https://dash.cloudflare.com', group: 'Infrastructure', mark: 'C', color: 'orange', favorite: false, notes: 'DNS and edge configuration.' },
  { id: 'apple', title: 'Apple Account', username: 'alex@personal.example', url: 'https://account.apple.com', group: 'Personal', mark: 'A', color: '', favorite: true, notes: 'Personal devices and subscriptions.' },
  { id: 'spotify', title: 'Spotify', username: 'alex@personal.example', url: 'https://spotify.com', group: 'Personal', mark: 'S', color: 'green', favorite: false, notes: 'Personal account.' },
];
let entries = structuredClone(seedEntries);
let requests = [
  { id: 'req-1', client: 'Build assistant', initials: 'BA', action: 'Read a repository file', resource: 'northstar / website', detail: 'README.md', scope: 'Read this file once', reason: 'Check setup instructions before preparing the build.', expires: Date.now() + 9 * 60000 },
  { id: 'req-2', client: 'Release assistant', initials: 'RA', action: 'Read a login username', resource: 'GitHub', detail: 'Work vault', scope: 'Username only · one request', reason: 'Confirm the account used for the release.', expires: Date.now() + 14 * 60000 },
];
let activities = [
  { action: 'Vault unlocked', resource: 'Personal vault', client: 'This Mac', result: 'Allowed', time: 'Just now' },
  { action: 'Connection checked', resource: 'Google Workspace', client: 'This Mac', result: 'Allowed', time: '2 minutes ago' },
  { action: 'Password copied', resource: 'GitHub', client: 'This Mac', result: 'Allowed', time: '12 minutes ago' },
  { action: 'File access blocked', resource: 'Private roadmap', client: 'Build assistant', result: 'Denied', time: '25 minutes ago' },
  { action: 'Item updated', resource: 'Linear', client: 'This Mac', result: 'Allowed', time: '1 hour ago' },
];
let state = { page: 'vault', group: 'All items', selected: 'github', query: '', sort: 'recent', scenario: 'ready', revealed: false, totp: false, mobileDetail: false, activityFilter: 'All events' };
let theme = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
let dialogReturnFocus = null;
let dialogCleanup = null;
let dialogCancelGuard = null;
let toastTimer;
let secretTimer;
const connectionStatus = { google: true, github: true };
function notify(text) { const el = $('#toast'); el.textContent = text; el.classList.add('visible'); clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove('visible'), 3200); }
function setTheme(value) { theme = value; document.documentElement.dataset.theme = theme; $('#theme-toggle').innerHTML = icon(theme === 'dark' ? 'sun' : 'moon'); $('#theme-toggle').setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} appearance`); }
function log(action, resource, result = 'Allowed', client = 'This Mac') { activities.unshift({ action, resource, result, client, time: 'Just now' }); }
function visibleEntries() { return (state.scenario === 'empty' ? [] : entries).filter(e => (state.group === 'All items' || (state.group === 'Favorites' ? e.favorite : e.group === state.group)) && `${e.title} ${e.username} ${e.url}`.toLowerCase().includes(state.query.toLowerCase())).sort(state.sort === 'name' ? (a, b) => a.title.localeCompare(b.title) : () => 0); }
function currentEntry() { return entries.find(e => e.id === state.selected); }
function navButton(name, glyph, page, count) { const selected = state.page === page && (page !== 'vault' || state.group === name); return `<button class="nav-item ${selected ? 'selected' : ''}" data-page="${page}" data-group="${name}" ${selected ? 'aria-current="page"' : ''}>${icon(glyph)}<span>${name}</span>${count !== undefined ? `<span class="count ${page === 'approvals' && count ? 'badge' : ''}">${count}</span>` : ''}</button>`; }
function renderNav() {
  const empty = state.scenario === 'empty';
  $('#navigation').innerHTML = navButton('All items', 'grid', 'vault', empty ? 0 : entries.length) + navButton('Favorites', 'star', 'vault', empty ? 0 : entries.filter(e => e.favorite).length) + '<div class="nav-section">Groups</div>' + ['Work', 'Personal', 'Infrastructure'].map(g => navButton(g, 'folder', 'vault')).join('') + '<div class="nav-section">Workspace</div>' + navButton('Connections', 'link', 'connections') + navButton('Approvals', 'shield', 'approvals', requests.length) + navButton('Activity', 'clock', 'activity');
  const ready = ['ready', 'empty'].includes(state.scenario);
  $('#service-status').innerHTML = `<i class="status-dot ${['offline', 'setup'].includes(state.scenario) ? 'offline' : ''}"></i>${state.scenario === 'offline' ? 'Service unavailable' : state.scenario === 'setup' ? 'Setup needed' : ready ? 'Connected · Vault unlocked' : 'Connected · Vault protected'}`;
}
function render() {
  renderNav();
  const available = ['ready', 'empty'].includes(state.scenario);
  $('#page-title').textContent = state.page === 'vault' ? state.group : ({ connections: 'Connections', approvals: 'Approvals', activity: 'Activity' }[state.page]);
  $('#page-subtitle').textContent = ({ vault: 'Personal vault', connections: 'Account access for your assistants', approvals: 'You decide what happens next', activity: 'A record of access and changes' }[state.page]);
  $('#new-button').hidden = !available || state.page !== 'vault';
  $('#lock-button').disabled = !available;
  $('#scenario').value = state.scenario;
  $('#workspace').classList.toggle('show-detail', state.mobileDetail);
  if (!available) renderState();
  else if (state.page === 'vault') renderVault();
  else if (state.page === 'connections') renderConnections();
  else if (state.page === 'approvals') renderApprovals();
  else renderActivity();
}
function renderVault() {
  $('#workspace').innerHTML = `<section class="entry-panel" aria-label="Vault items"><div class="search-wrap"><div class="search-field">${icon('search')}<input id="search" type="search" autocomplete="off" aria-label="Search vault" placeholder="Search your vault" value="${escapeHTML(state.query)}"><kbd>⌘ F</kbd></div></div><div class="list-caption"><span id="result-count"></span><select id="sort" aria-label="Sort items"><option value="recent">Recently used</option><option value="name">Name A–Z</option></select></div><div id="entry-list" class="entry-list" aria-label="Items"></div><div class="panel-footer">${icon('shield')} Only you control access</div></section><div class="resizer list-resizer" role="separator" tabindex="0" aria-label="Item list width" aria-orientation="vertical" aria-valuemin="235" aria-valuemax="400" aria-valuenow="306"></div><section id="detail" class="detail-panel" aria-label="Item details"></section>`;
  $('#sort').value = state.sort;
  renderEntries(); renderDetail();
  $('#search').addEventListener('input', event => { state.query = event.target.value; renderEntries(); renderDetail(); });
  $('#sort').addEventListener('change', event => { state.sort = event.target.value; renderEntries(); });
  $('#entry-list').addEventListener('keydown', event => {
    if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
    const buttons = $$('.entry-row'); if (!buttons.length) return;
    event.preventDefault(); const index = buttons.indexOf(document.activeElement);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1 : Math.max(0, Math.min(buttons.length - 1, index + (event.key === 'ArrowUp' ? -1 : 1)));
    selectEntry(buttons[next].dataset.entry, false); $(`[data-entry="${buttons[next].dataset.entry}"]`).focus();
  });
  setupResizer($('.list-resizer'), '--list-width', 235, 400);
}
function renderEntries() {
  const visible = visibleEntries();
  if (!visible.some(e => e.id === state.selected)) { state.selected = visible[0]?.id || null; state.revealed = false; state.totp = false; }
  $('#result-count').textContent = `${visible.length} ${visible.length === 1 ? 'item' : 'items'}`;
  $('#entry-list').innerHTML = visible.length ? visible.map(e => `<button class="entry-row ${state.selected === e.id ? 'selected' : ''}" data-entry="${escapeHTML(e.id)}" ${state.selected === e.id ? 'aria-current="true"' : ''}>${brand(e)}<span class="entry-copy"><strong>${escapeHTML(e.title)}</strong><small>${escapeHTML(e.username)}</small></span>${e.favorite ? icon('star', 'star') : ''}</button>`).join('') : `<div class="empty">${icon(state.query ? 'search' : 'vault')}<h3>${state.query ? 'No items found' : 'A fresh start'}</h3><p>${state.query ? 'Try a different name or account.' : 'Add your first login to this vault.'}</p><button data-action="${state.query ? 'clear-search' : 'new'}">${state.query ? 'Clear search' : 'Add an item'}</button></div>`;
}
function selectEntry(id, openDetail = true) { state.selected = id; state.revealed = false; state.totp = false; state.mobileDetail = openDetail; renderEntries(); renderDetail(); $('#workspace').classList.toggle('show-detail', state.mobileDetail); }
function field(label, value, actions = '', className = '') { return `<div class="field-row"><div class="field-content"><span class="field-label">${label}</span><span class="field-value ${className}">${value}</span></div><div class="field-actions">${actions}</div></div>`; }
function renderDetail() {
  const entry = currentEntry();
  if (!entry || !visibleEntries().length) { $('#detail').innerHTML = `<div class="empty">${icon('vault')}<h3>${state.query ? 'Nothing matches your search' : 'Your vault, at a glance'}</h3><p>${state.query ? 'Search by title, username or website.' : 'Select an item to see its details.'}</p></div>`; return; }
  $('#detail').innerHTML = `<div class="detail-topline"><div class="breadcrumb"><button class="quiet back-button" data-action="back">${icon('back')}Items</button>${icon('folder')}${escapeHTML(entry.group)}${icon('chevron')}Login</div><div class="detail-actions">${ib('star', entry.favorite ? 'Remove from favorites' : 'Add to favorites', 'favorite', `aria-pressed="${entry.favorite}"`)}<button data-action="edit">Edit</button>${ib('more', 'More item actions', 'more')}</div></div><div class="detail-heading">${brand(entry, true)}<div><h2>${escapeHTML(entry.title)}</h2><p>${escapeHTML(entry.url.replace(/^https?:\/\//, ''))}</p></div></div><div class="section-label">Login details</div><div class="field-group">${field('Username', escapeHTML(entry.username), ib('copy', 'Copy username', 'copy-user'))}${field('Password', state.revealed ? escapeHTML(entry.password || 'Demo-only!47-sample') : '••••••••••••••', ib(state.revealed ? 'eyeoff' : 'eye', state.revealed ? 'Hide password' : 'Reveal password', 'reveal') + ib('copy', 'Copy password', 'copy-password'), `mono secret ${state.revealed ? 'revealed' : ''}`)}${field('Website', escapeHTML(entry.url), ib('copy', 'Copy website', 'copy-url'), 'website')}</div>${entry.totp ? `<div class="section-label">Two-factor authentication</div><div class="field-group">${field('One-time password', state.totp ? '482 916 <span class="muted">· Demo code</span>' : 'Available on request', state.totp ? ib('copy', 'Copy demo code', 'copy-totp') : '<button data-action="totp">Show code</button>', 'mono')}</div>` : ''}<div class="section-label">Notes</div><div class="note">${escapeHTML(entry.notes || 'No notes added.')}</div><div class="item-meta"><span>Updated ${entry.updated || 'September 5, 2026'}<br>Created August 28, 2026</span><button class="link-button" data-action="history">${icon('clock')}View history</button></div>`;
}
function renderConnections() {
  const cards = [{ id: 'google', title: 'Google Workspace', mark: 'G', color: 'blue', account: 'alex@northstar.example', resources: ['Product documents', 'Release checklist'], subtitle: '2 selected files · Read access' }, { id: 'github', title: 'GitHub', mark: 'GH', color: 'ink', account: 'northstar', resources: ['northstar / website'], subtitle: '1 repository · Scoped access' }];
  $('#workspace').innerHTML = `<section class="page"><div class="page-inner"><div class="page-intro"><div><h2>Connected accounts</h2><p>Give assistants access to specific resources. Your account credentials stay protected.</p></div><button class="primary" data-action="add-connection">${icon('plus')}Add connection</button></div>${cards.map(c => `<article class="connection-card"><div class="connection-head">${brand(c)}<div><h3>${c.title}</h3><p>${c.account}</p></div><span class="pill ${connectionStatus[c.id] ? '' : 'warning'}">${icon(connectionStatus[c.id] ? 'check' : 'warning')}${connectionStatus[c.id] ? 'Connected' : 'Disconnected'}</span></div>${c.resources.map(r => `<span class="resource">${icon('folder')}${r}</span>`).join('')}<div class="connection-bottom"><span>${c.subtitle}</span><div class="button-row"><button data-action="test-connection" data-id="${c.id}">${icon('refresh')}Check connection</button><button data-action="manage-connection" data-id="${c.id}">Manage</button></div></div></article>`).join('')}<p class="muted" style="font-size:12px;line-height:1.7;margin-top:22px">${icon('shield')} Assistants still need permission for each protected action.</p></div></section>`;
}
function renderApprovals() {
  $('#workspace').innerHTML = `<section class="page"><div class="page-inner"><div class="page-intro"><div><h2>Requests for your approval</h2><p>Review the action and resource before allowing access. Each approval applies to one exact request.</p></div><span class="pill neutral">${requests.length} pending</span></div>${requests.length ? requests.map(r => `<article class="approval-card"><div class="approval-main"><div class="approval-title">${brand({ title: r.client, mark: r.initials, color: 'blue' })}<div><h3>${r.client}</h3><p>${r.action}</p></div><span class="pill warning">${r.expires > Date.now() ? `Expires in ${Math.ceil((r.expires - Date.now()) / 60000)} min` : 'Expired'}</span></div><dl class="request-summary"><dt>Resource</dt><dd><strong>${r.resource}</strong> / ${r.detail}</dd><dt>Access</dt><dd>${r.scope}</dd><dt>Reason</dt><dd>${r.reason}</dd></dl></div><div class="approval-footer"><span>No ongoing access is granted.</span><div class="button-row"><button data-action="deny" data-id="${r.id}">Deny</button><button class="primary" data-action="approve" data-id="${r.id}" ${r.expires <= Date.now() ? 'disabled' : ''}>Review & approve</button></div></div></article>`).join('') : `<div class="empty">${icon('shield')}<h3>You're all caught up</h3><p>New requests will appear here when an assistant needs your permission.</p></div>`}</div></section>`;
}
function renderActivity() {
  const filtered = activities.filter(a => state.activityFilter === 'All events' || a.result === 'Denied');
  $('#workspace').innerHTML = `<section class="page"><div class="page-inner"><div class="page-intro"><div><h2>Activity</h2><p>See what was accessed, by whom, and what you allowed.</p></div><span class="pill neutral">Today</span></div><div class="filters">${['All events', 'Denied'].map(f => `<button data-filter="${f}" class="${state.activityFilter === f ? 'selected' : ''}" aria-pressed="${state.activityFilter === f}">${f}</button>`).join('')}</div><div class="table-wrap"><table><thead><tr><th>Action / resource</th><th>Client</th><th>Result</th><th>When</th></tr></thead><tbody>${filtered.map(a => `<tr><td>${escapeHTML(a.action)}<small>${escapeHTML(a.resource)}</small></td><td>${escapeHTML(a.client)}</td><td><span class="pill ${a.result === 'Denied' ? 'warning' : ''}">${a.result}</span></td><td class="muted">${a.time}</td></tr>`).join('')}</tbody></table></div></div></section>`;
}
function renderState() {
  let content;
  if (state.scenario === 'locked') content = `<div class="app-mark">${icon('lock')}</div><h2>Welcome back</h2><p>Unlock your personal vault to access your items.</p><form id="unlock-form"><label for="master-password">Master password</label><input id="master-password" type="password" placeholder="Enter demo password" autocomplete="off" required><button class="primary" type="submit">${icon('lock')}Unlock vault</button><div id="unlock-error" class="form-error" role="alert"></div></form><p class="state-footnote">Prototype: enter <strong>demo</strong>. Do not enter a real password.</p>`;
  else if (state.scenario === 'setup') content = `<div class="app-mark">${icon('key')}</div><h2>Make yourself at home</h2><p>Connect this app to your local KeyLease service, then unlock your vault.</p><div class="setup-step">${icon('check')}<div>Local service found<span>Running on this Mac</span></div></div><div class="setup-step">${icon('shield')}<div>Authorize this desktop app<span>Choose the client file issued by KeyLease</span></div></div><button class="primary" data-action="choose-demo-client">Use demo client file</button><p class="state-footnote">Prototype uses a sample authorization file. No files are read.</p>`;
  else if (state.scenario === 'offline') content = `<div class="app-mark">${icon('monitor')}</div><h2>Can't reach KeyLease</h2><p>Your vault hasn't been opened. Make sure the local service is running, then try connecting again.</p><div class="button-row" style="justify-content:center"><button data-action="connection-help">Connection help</button><button class="primary" data-action="retry">${icon('refresh')}Try again</button></div><p class="state-footnote">Demo: Try again simulates a service recovery.</p>`;
  else content = `<div class="app-mark">${icon('shield')}</div><h2>Permission needed</h2><p>This desktop client isn't allowed to read vault items. Choose an authorized client file or ask your administrator to review its access.</p><button class="primary" data-action="settings">Review connection settings</button><p class="state-footnote">Your vault and existing permissions are unchanged.</p>`;
  $('#workspace').innerHTML = `<section class="state-page"><div class="state-card">${content}</div></section>`;
  if ($('#unlock-form')) $('#unlock-form').addEventListener('submit', e => { e.preventDefault(); if ($('#master-password').value !== 'demo') { $('#unlock-error').textContent = 'That password did not work. Use “demo” for this prototype.'; return; } $('#master-password').value = ''; state.scenario = 'ready'; log('Vault unlocked', 'Personal vault'); render(); notify('Your vault is unlocked'); });
}
function showDialog(title, body, footer = '', onSubmit = null) {
  const dialog = $('#dialog');
  if (!dialog.open) dialogReturnFocus = document.activeElement;
  if (dialogCleanup) { dialogCleanup(); dialogCleanup = null; }
  dialog.innerHTML = `<form id="dialog-form"><header class="dialog-header"><h2 id="dialog-title">${escapeHTML(title)}</h2>${ib('close', 'Close dialog', 'close-dialog', 'type="button"')}</header><div class="dialog-body">${body}</div><footer class="dialog-footer">${footer || '<button type="button" data-action="close-dialog">Done</button>'}</footer></form>`;
  if (!dialog.open) dialog.showModal();
  $('#dialog-form').addEventListener('submit', e => { e.preventDefault(); onSubmit?.(e); });
}
function closeDialog() { $('#dialog').close(); $('#dialog').innerHTML = ''; if (dialogCleanup) { dialogCleanup(); dialogCleanup = null; } if (dialogReturnFocus?.isConnected) dialogReturnFocus.focus(); }
function confirmAction(title, body, buttonText, callback, destructive = false) {
  showDialog(title, `<p>${body}</p>`, `<button type="button" data-action="close-dialog">Cancel</button><button type="submit" class="${destructive ? 'danger-fill' : 'primary'}">${buttonText}</button>`, () => { closeDialog(); callback(); });
}
function editor(isNew) {
  const entry = isNew ? { title: '', username: '', url: '', group: ['Work', 'Personal', 'Infrastructure'].includes(state.group) ? state.group : 'Work', notes: '' } : currentEntry();
  const body = `<label>Title<input name="title" required maxlength="100" value="${escapeHTML(entry.title)}" placeholder="e.g. GitHub" autofocus></label><label>Username<input name="username" maxlength="150" value="${escapeHTML(entry.username)}" placeholder="name@example.com"></label><label>Password<input name="password" type="password" ${isNew ? 'required' : ''} placeholder="${isNew ? 'Use a fictional password' : 'Leave blank to keep current password'}" autocomplete="new-password"><span class="help-text">Demo data only. Do not enter a real credential.</span></label><label>Website<input name="url" type="url" value="${escapeHTML(entry.url)}" placeholder="https://example.com"></label><label>Group<select name="group">${['Work', 'Personal', 'Infrastructure'].map(g => `<option ${entry.group === g ? 'selected' : ''}>${g}</option>`).join('')}</select></label><label>Notes<textarea name="notes" maxlength="2000">${escapeHTML(entry.notes)}</textarea></label>`;
  showDialog(isNew ? 'New login' : `Edit ${entry.title}`, body, '<button type="button" data-action="close-dialog">Cancel</button><button class="primary" type="submit">Save item</button>', () => {
    const values = Object.fromEntries(new FormData($('#dialog-form'))); values.title = values.title.trim();
    if (!values.title) { $('[name="title"]').setCustomValidity('Enter an item name.'); $('[name="title"]').reportValidity(); return; }
    if (!values.password) delete values.password;
    if (isNew) { const added = { ...values, id: `demo-${Date.now()}`, mark: values.title.slice(0, 1).toUpperCase(), color: 'blue', favorite: false, updated: 'just now' }; entries.unshift(added); state.selected = added.id; state.scenario = 'ready'; }
    else { Object.assign(entry, values, { updated: 'just now' }); }
    state.group = values.group; state.query = ''; state.mobileDetail = true; state.revealed = false;
    log(isNew ? 'Item created' : 'Item updated', values.title); closeDialog(); render(); notify(isNew ? 'Item added to your vault' : 'Changes saved');
  });
  const input = $('[name="title"]'); input.addEventListener('input', () => input.setCustomValidity(''));
  let dirty = false; $('#dialog-form').addEventListener('input', () => { dirty = true; });
  const guard = e => {
    if (!dirty || (e.type === 'click' && !e.target.closest('[data-action="close-dialog"]'))) return;
    e.preventDefault(); e.stopImmediatePropagation();
    if ($('#discard-warning')) return;
    $('.dialog-footer').insertAdjacentHTML('beforebegin', '<div id="discard-warning" class="dialog-body"><p>Discard your unsaved changes?</p><div class="button-row"><button type="button" id="keep-editing">Keep editing</button><button type="button" id="discard-changes" class="danger">Discard changes</button></div></div>');
    $('#keep-editing').onclick = () => { $('#discard-warning').remove(); input.focus(); };
    $('#discard-changes').onclick = closeDialog;
    $('#keep-editing').focus();
  };
  $('#dialog').addEventListener('click', guard, true);
  dialogCancelGuard = e => { if (dirty) guard(e); else closeDialog(); };
  dialogCleanup = () => { $('#dialog').removeEventListener('click', guard, true); dialogCancelGuard = null; };
}
function settings() {
  showDialog('Settings', `<div class="settings-row"><div>Appearance<small>Choose how KeyLease looks</small></div><select name="appearance" aria-label="Appearance"><option value="light" ${theme === 'light' ? 'selected' : ''}>Light</option><option value="dark" ${theme === 'dark' ? 'selected' : ''}>Dark</option></select></div><div class="settings-row"><div>Local connection<small>${state.scenario === 'offline' ? 'Service unavailable' : 'This Mac · Connected'}</small></div><span class="pill neutral">Local only</span></div><div class="settings-row"><div>Clipboard<small>Production target: clear after 30 seconds</small></div>${icon('shield')}</div><details><summary>Advanced connection settings</summary><p>Production will use the native file picker and registered client permissions. This prototype never reads a token or connects to a service.</p><label style="margin-top:15px">Client file<input value="desktop-demo.client" readonly></label></details><p style="margin-top:20px">Only appearance is editable in this prototype.</p>`, '<button type="button" data-action="close-dialog">Cancel</button><button class="primary" type="submit">Save changes</button>', () => { setTheme($('[name="appearance"]').value); closeDialog(); notify('Appearance updated'); });
}
function decide(id, approve) {
  const request = requests.find(r => r.id === id); if (!request) return;
  showDialog(approve ? 'Approve this request?' : 'Deny this request?', `<p><strong>${request.client}</strong> wants to ${request.action.toLowerCase()}.</p><div class="field-group">${field('Resource', `${request.resource} / ${request.detail}`)}${field('Access', request.scope)}</div><p style="margin-top:16px">${approve ? 'Allows this action once. This does not grant ongoing access.' : 'The assistant will not be allowed to perform this request.'}</p><details><summary>Request details</summary><p>Demo request ${request.id}. In production, this confirmation must remain bound to the exact request digest and expiry.</p></details>`, `<button type="button" data-action="close-dialog">Cancel</button><button class="${approve ? 'primary' : 'danger-fill'}" type="submit">${approve ? 'Approve once' : 'Deny request'}</button>`, () => {
    if (request.expires <= Date.now()) { closeDialog(); notify('This request has expired. No access was granted.'); renderApprovals(); return; }
    requests = requests.filter(r => r.id !== id); log(approve ? 'Request approved' : 'Request denied', request.resource, approve ? 'Allowed' : 'Denied', request.client); closeDialog(); render(); notify(approve ? 'Request approved once' : 'Request denied');
  });
}
async function copy(value, label) {
  try { await navigator.clipboard.writeText(value); notify(`${label} copied · demo data`); log(`${label} copied`, currentEntry()?.title || 'Demo'); }
  catch { showDialog(`Copy ${label.toLowerCase()}`, `<p>Your browser did not allow clipboard access. Select and copy the demo value below.</p><input id="copy-fallback" aria-label="Demo value to copy" readonly value="${escapeHTML(value)}" style="width:100%">`); $('#copy-fallback').select(); }
}
function lock() { closeDialog(); clearTimeout(secretTimer); state.scenario = 'locked'; state.revealed = false; state.totp = false; state.query = ''; state.mobileDetail = false; render(); $('#master-password')?.focus(); }
function setScenario(value) { closeDialog(); clearTimeout(secretTimer); state.scenario = value; state.page = 'vault'; state.group = 'All items'; state.query = ''; state.revealed = false; state.totp = false; state.mobileDetail = false; render(); }
const actions = {
  new: () => editor(true), edit: () => editor(false), settings, 'close-dialog': closeDialog,
  back: () => { state.mobileDetail = false; $('#workspace').classList.remove('show-detail'); $(`[data-entry="${state.selected}"]`)?.focus(); },
  'clear-search': () => { state.query = ''; renderVault(); $('#search').focus(); },
  favorite: () => { const e = currentEntry(); e.favorite = !e.favorite; render(); },
  reveal: () => { state.revealed = !state.revealed; clearTimeout(secretTimer); renderDetail(); $('[data-action="reveal"]')?.focus(); if (state.revealed) secretTimer = setTimeout(() => { state.revealed = false; if (state.page === 'vault' && ['ready', 'empty'].includes(state.scenario)) renderDetail(); }, 15000); },
  totp: () => { state.totp = true; renderDetail(); },
  'copy-user': () => copy(currentEntry().username, 'Username'),
  'copy-password': () => copy(currentEntry().password || 'Demo-only!47-sample', 'Password'),
  'copy-url': () => copy(currentEntry().url, 'Website'),
  'copy-totp': () => copy('482916', 'Demo code'),
  history: () => showDialog('Item history', '<p>Earlier versions of this item.</p><div class="field-group">' + field('September 5, 2026 · Current version', 'Notes updated · This Mac') + field('August 28, 2026', 'Login created · This Mac') + '</div><p style="margin-top:16px">Sample history for design review. Password values are not shown.</p>'),
  more: () => showDialog('Item actions', `<p>${escapeHTML(currentEntry().title)}</p><button class="danger" type="button" data-action="delete">${icon('trash')}Delete item…</button>`),
  delete: () => { const e = currentEntry(); confirmAction(`Delete ${e.title}?`, 'This removes the demo item from this vault. Reset the prototype to restore all sample data.', 'Delete item', () => { entries = entries.filter(x => x.id !== e.id); log('Item deleted', e.title); render(); notify('Item deleted'); }, true); },
  'choose-demo-client': () => { state.scenario = 'locked'; render(); notify('Demo client connected'); },
  retry: () => { state.scenario = 'locked'; render(); notify('Connection restored. Unlock your vault to continue.'); },
  'connection-help': () => showDialog('Connect to the local service', '<p>KeyLease desktop needs its local service to be running. In the current app, start the service with <code>keylease serve --start-locked</code>, then choose the registered client file in Settings.</p><p>If the service is already running, check that this app is using the same local connection. This prototype does not start any process.</p>'),
  approve: el => decide(el.dataset.id, true), deny: el => decide(el.dataset.id, false),
  'add-connection': () => showDialog('Add a connection', '<p>Choose the account you want to connect.</p><label>Provider<select name="provider"><option>Google Workspace</option><option>GitHub</option></select></label><p>In the real app, Google authorization opens in your browser; GitHub uses a scoped token. This preview shows the next step with demo data.</p>', '<button type="button" data-action="close-dialog">Cancel</button><button class="primary" type="submit">Preview setup</button>', () => { const provider = $('[name="provider"]').value; showDialog(`Connect ${provider}`, `<p>${provider === 'Google Workspace' ? 'Authorize your Google account in the system browser, then select the files this connection can access.' : 'Provide a scoped GitHub token, then select the repositories this connection can access.'}</p><div class="field-group">${field('Account', 'alex@northstar.example')}${field('Access', provider === 'Google Workspace' ? 'Selected files only' : 'northstar / website')}</div><p style="margin-top:16px">Demo only: no authorization is sent and no token is collected.</p>`, '<button type="button" data-action="close-dialog">Cancel</button><button type="submit" class="primary">Connect demo account</button>', () => { connectionStatus[provider === 'Google Workspace' ? 'google' : 'github'] = true; closeDialog(); render(); notify('Demo account connected'); }); }),
  'test-connection': el => { const id = el.dataset.id; notify(connectionStatus[id] ? 'Demo connection is healthy' : 'Account disconnected. Open Manage to reconnect.'); log('Connection checked', id === 'google' ? 'Google Workspace' : 'GitHub', connectionStatus[id] ? 'Allowed' : 'Denied'); },
  'manage-connection': el => { const id = el.dataset.id; showDialog(id === 'google' ? 'Google Workspace access' : 'GitHub access', `<p>Only the resources listed below are available to this connection.</p><div class="field-group">${field('Authorized resources', id === 'google' ? 'Product documents<br>Release checklist' : 'northstar / website')}${field('Access', 'Read only')}</div><p style="margin-top:16px">Disconnecting stops further access through this demo connection.</p>`, `<button type="button" data-action="close-dialog">Done</button><button type="submit" class="${connectionStatus[id] ? 'danger' : 'primary'}">${connectionStatus[id] ? 'Disconnect…' : 'Reconnect demo'}</button>`, () => { if (!connectionStatus[id]) { connectionStatus[id] = true; closeDialog(); render(); notify('Demo connection restored'); return; } confirmAction('Disconnect account?', 'Assistants will lose access through this connection. You can reconnect later.', 'Disconnect', () => { connectionStatus[id] = false; render(); notify('Demo account disconnected'); }, true); }); },
};
document.addEventListener('click', event => {
  const nav = event.target.closest('[data-page]');
  if (nav) { state.page = nav.dataset.page; state.group = nav.dataset.group; state.query = ''; state.revealed = false; state.totp = false; state.mobileDetail = false; render(); if (innerWidth <= 650) $('#window').classList.add('sidebar-hidden'); return; }
  const entry = event.target.closest('[data-entry]'); if (entry) { selectEntry(entry.dataset.entry); return; }
  const filter = event.target.closest('[data-filter]'); if (filter) { state.activityFilter = filter.dataset.filter; renderActivity(); return; }
  const target = event.target.closest('[data-action]'); if (target && actions[target.dataset.action]) { if (target.dataset.action !== 'close-dialog') event.preventDefault(); actions[target.dataset.action](target); }
});
$('#dialog').addEventListener('cancel', event => { event.preventDefault(); if (dialogCancelGuard) dialogCancelGuard(event); else closeDialog(); });
$('#scenario').addEventListener('change', event => setScenario(event.target.value));
$('#theme-toggle').onclick = () => setTheme(theme === 'light' ? 'dark' : 'light');
$('#settings-button').onclick = settings;
$('#new-button').onclick = () => editor(true);
$('#lock-button').onclick = lock;
$('#sidebar-toggle').onclick = () => $('#window').classList.toggle('sidebar-hidden');
$('#show-sidebar').onclick = () => $('#window').classList.remove('sidebar-hidden');
$('#reset').onclick = () => location.reload();
document.addEventListener('keydown', event => {
  if (!(event.metaKey || event.ctrlKey) || $('#dialog').open) return;
  if (!['ready', 'empty'].includes(state.scenario)) return;
  if (event.key.toLowerCase() === 'f') { event.preventDefault(); if (state.page !== 'vault') { state.page = 'vault'; state.group = 'All items'; render(); } state.mobileDetail = false; $('#workspace').classList.remove('show-detail'); $('#search')?.focus(); }
  if (event.key.toLowerCase() === 'n') { event.preventDefault(); state.page = 'vault'; render(); editor(true); }
  if (event.key === ',') { event.preventDefault(); settings(); }
});
function setupResizer(el, variable, min, max) {
  if (!el) return;
  function apply(width) { const v = Math.round(Math.max(min, Math.min(max, width))); document.documentElement.style.setProperty(variable, `${v}px`); el.setAttribute('aria-valuenow', v); }
  el.addEventListener('pointerdown', event => { const start = event.clientX; const initial = parseFloat(getComputedStyle(document.documentElement).getPropertyValue(variable)); el.setPointerCapture(event.pointerId); const move = e => apply(initial + e.clientX - start); const stop = () => { el.removeEventListener('pointermove', move); el.removeEventListener('pointerup', stop); el.removeEventListener('pointercancel', stop); }; el.addEventListener('pointermove', move); el.addEventListener('pointerup', stop); el.addEventListener('pointercancel', stop); });
  el.addEventListener('keydown', event => { if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return; event.preventDefault(); const initial = parseFloat(getComputedStyle(document.documentElement).getPropertyValue(variable)); apply(initial + (event.key === 'ArrowRight' ? 10 : -10)); });
}
document.addEventListener('visibilitychange', () => { if (document.hidden) { state.revealed = false; state.totp = false; if (state.page === 'vault' && ['ready', 'empty'].includes(state.scenario) && $('#detail')) renderDetail(); } });
$('#sidebar-toggle').innerHTML = icon('sidebar'); $('#show-sidebar').innerHTML = icon('sidebar'); $('#lock-button').innerHTML = icon('lock');
paintIcons(); setTheme(theme); setupResizer($('.sidebar-resizer'), '--sidebar-width', 180, 280);
if (innerWidth <= 650) $('#window').classList.add('sidebar-hidden');
render();
