/* ================================================================
   IMPACT II — app.js (ES module entry point)
   ================================================================ */

import { Router, toggleSidebar, initSidebarState, loadStatus, refreshCache } from '/static/js/router.js';
import { Auth, API } from '/static/js/api.js';

/* ── Expose globals needed by inline onclick= handlers in HTML ── */
window.toggleSidebar = toggleSidebar;
window.refreshCache  = refreshCache;
window.logout        = logout;

/* ── Page registration (lazy dynamic imports) ─────────────────── */
const PAGES = {
  dashboard:        () => import('/static/pages/dashboard.js'),
  devices:          () => import('/static/pages/devices.js'),
  'ip-lookup':      () => import('/static/pages/ip-lookup.js'),
  ise:              () => import('/static/pages/ise.js'),
  firewall:         () => import('/static/pages/firewall.js'),
  'command-runner': () => import('/static/pages/command-runner.js'),
  import:           () => import('/static/pages/import.js'),
  reports:          () => import('/static/pages/reports.js'),
};

for (const [name, loader] of Object.entries(PAGES)) {
  Router.register(name, async (el) => {
    const mod = await loader();
    mod.mount(el);
  });
}

/* ── Login ──────────────────────────────────────────────────────── */
function renderLogin(errorMsg) {
  document.getElementById('sidebar').style.display = 'none';
  const main = document.getElementById('main');
  main.style.marginLeft = '0';
  main.innerHTML = `
    <div class="login-container">
      <div class="login-card">
        <div class="login-header">
          <div class="login-logo">II</div>
          <div style="margin-left:12px">
            <div class="login-title">IMPACT II</div>
            <div class="login-subtitle">TSA Network Operations</div>
          </div>
        </div>
        <div class="login-body">
          ${errorMsg ? `<div class="alert alert-danger alert-sm"><strong>⚠️ Error:</strong> ${errorMsg}</div>` : ''}
          <form id="login-form" autocomplete="on">
            <div class="mb-3">
              <label for="login-user" class="form-label">Username</label>
              <input id="login-user" class="form-control" type="text" placeholder="Enter your username" autocomplete="username">
            </div>
            <div class="mb-3">
              <label for="login-pass" class="form-label">Password</label>
              <input id="login-pass" class="form-control" type="password" placeholder="Enter your password" autocomplete="current-password">
            </div>
            <button id="login-btn" type="submit" class="btn btn-primary w-100">Sign In</button>
          </form>
        </div>
      </div>
    </div>`;

  const form = document.getElementById('login-form');
  const btn  = document.getElementById('login-btn');

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const username = document.getElementById('login-user').value.trim();
    const password = document.getElementById('login-pass').value;
    if (!username || !password) return;

    window._bootstrapping = true;
    btn.disabled    = true;
    btn.textContent = 'Signing in…';

    try {
      const r = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        window._bootstrapping = false;
        renderLogin(data.detail || 'Login failed — check your credentials');
        return;
      }
      Auth.save(data.token, data.username);
      bootApp();
    } catch (e) {
      window._bootstrapping = false;
      renderLogin('Network error — please try again');
    }
  });

  // Listen for auth expiry (API._handle401 fires this)
  window.addEventListener('impact:logout', () => renderLogin(), { once: true });
}

/* ── Warmup ─────────────────────────────────────────────────────── */
function renderWarmup() {
  const STEPS = [
    { id: 'devices',  label: 'Catalyst Center',   sub: 'Device inventory' },
    { id: 'sites',    label: 'Catalyst Center',   sub: 'Site hierarchy' },
    { id: 'sitemap',  label: 'Catalyst Center',   sub: 'Device → site map' },
    { id: 'ise',      label: 'Cisco ISE',          sub: 'Policy & endpoint data' },
    { id: 'panorama', label: 'Palo Alto Panorama', sub: 'Firewall policies' },
  ];

  document.getElementById('content').innerHTML = `
    <div style="display:flex;align-items:center;justify-content:center;min-height:calc(100vh - 56px);background:var(--bg-secondary)">
      <div class="card" style="width:520px;padding:36px 40px">
        <div style="text-align:center;margin-bottom:28px">
          <div style="font-size:22px;font-weight:700;color:var(--cisco-blue);margin-bottom:6px">Connecting to Network Systems</div>
          <div style="font-size:13px;color:var(--text-light)">Authenticating and loading data for ${Auth.username()}</div>
        </div>
        <div style="display:flex;flex-direction:column;gap:10px">
          ${STEPS.map(s => `
            <div id="ws-${s.id}" style="display:flex;align-items:center;gap:14px;padding:12px 16px;border-radius:8px;background:var(--bg-secondary);border:1px solid var(--border)">
              <span id="wi-${s.id}" style="font-size:20px;min-width:24px;text-align:center">⏳</span>
              <div style="flex:1;min-width:0">
                <div style="font-size:13px;font-weight:600;color:var(--text-primary)">${s.label}</div>
                <div id="wm-${s.id}" style="font-size:12px;color:var(--text-light);margin-top:2px">${s.sub}</div>
              </div>
            </div>
          `).join('')}
        </div>
        <div id="warm-ready" style="display:none;text-align:center;margin-top:24px;font-size:14px;font-weight:600;color:var(--success)">
          ✅ All systems ready — launching dashboard…
        </div>
      </div>
    </div>`;

  let launched = false;

  const streamTimeout = setTimeout(() => {
    if (!launched) { launched = true; setTimeout(initApp, 500); }
  }, 8000);

  API.stream('/warm', {}, ev => {
    if (ev.type === 'error') return;

    if (ev.step === 'done') {
      clearTimeout(streamTimeout);
      if (launched) return;
      launched = true;
      const el = document.getElementById('warm-ready');
      if (el) el.style.display = '';
      setTimeout(initApp, 1500);
      return;
    }

    const icon  = { loading: '⏳', done: '✅', cached: '✅', error: '❌' }[ev.status] || '⏳';
    const bg    = { done: '#f0fdf4', cached: '#f0fdf4', error: '#fff1f2' }[ev.status];
    const rowEl = document.getElementById(`ws-${ev.step}`);
    const icEl  = document.getElementById(`wi-${ev.step}`);
    const msgEl = document.getElementById(`wm-${ev.step}`);
    if (rowEl && bg) rowEl.style.background = bg;
    if (icEl)  icEl.textContent  = icon;
    if (msgEl) msgEl.textContent = ev.message;
  }, () => {
    clearTimeout(streamTimeout);
    if (!launched) { launched = true; setTimeout(initApp, 500); }
  });
}

/* ── Boot flow ──────────────────────────────────────────────────── */
let _bootCalled = false;

function bootApp() {
  if (_bootCalled) return;
  _bootCalled = true;

  document.getElementById('sidebar').style.display = '';
  initSidebarState();

  const main = document.getElementById('main');
  main.style.marginLeft = '';
  main.innerHTML = `
    <header id="topbar">
      <span id="page-title">Loading…</span>
      <div id="topbar-actions">
        <span style="font-size:13px;color:var(--text-light);margin-right:12px">👤 ${Auth.username()}</span>
        <button class="btn btn-outline-secondary btn-sm" style="margin-right:8px" onclick="refreshCache()">🔄 Refresh Cache</button>
        <button class="btn btn-outline-secondary btn-sm" onclick="logout()">Sign Out</button>
      </div>
    </header>
    <div id="content"></div>`;

  renderWarmup();
}

function initApp() {
  window._bootstrapping = false;

  // Wire up sidebar nav clicks
  document.querySelectorAll('.nav-item[data-page]').forEach(el => {
    el.addEventListener('click', () => Router.go(el.dataset.page));
  });

  Router.init();
  loadStatus();
  setInterval(loadStatus, 60_000);
}

async function logout() {
  try { await API.post('/auth/logout', {}); } catch {}
  Auth.clear();
  _bootCalled = false;
  renderLogin();
}

/* ── Bootstrap (runs on page load) ─────────────────────────────── */
(async () => {
  // Dev mode: auto-login with the server-issued dev token
  try {
    const dm = await fetch('/api/dev-mode').then(r => r.json());
    if (dm.enabled) {
      Auth.save(dm.token, dm.username);
      bootApp();
      return;
    }
  } catch {}

  const token = Auth.token();
  if (token) {
    try {
      const r = await fetch('/api/auth/me', { headers: { Authorization: `Bearer ${token}` } });
      if (r.ok) {
        const { username } = await r.json();
        Auth.save(token, username);
        bootApp();
        return;
      }
    } catch {}
    Auth.clear();
  }
  renderLogin();
})();
