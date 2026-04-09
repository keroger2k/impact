/* ============================================================
   IMPACT II — SPA JavaScript
   Vanilla JS, no build step, no frameworks.
   Hash-based routing: #/dashboard, #/devices, etc.
   ============================================================ */

'use strict';

/* ── Auth token store ───────────────────────────────────────── */
const Auth = {
  token() { return localStorage.getItem('impact_token'); },
  username() { return localStorage.getItem('impact_user'); },
  save(token, username) {
    localStorage.setItem('impact_token', token);
    localStorage.setItem('impact_user', username);
  },
  clear() {
    localStorage.removeItem('impact_token');
    localStorage.removeItem('impact_user');
  },
  headers() {
    const t = this.token();
    return t ? { 'Authorization': `Bearer ${t}` } : {};
  },
};

/* ── API client ─────────────────────────────────────────────── */
const API = {
  _handle401() {
    Auth.clear();
    // Only re-render login if we're not already bootstrapping (avoid clearing form during login)
    if (!window._bootstrapping) {
      renderLogin();
    }
  },
  async get(path) {
    const r = await fetch(`/api${path}`, { headers: Auth.headers() });
    if (r.status === 401) { this._handle401(); throw new Error('Not authenticated'); }
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || r.statusText); }
    return r.json();
  },
  async post(path, body) {
    const r = await fetch(`/api${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...Auth.headers() },
      body: JSON.stringify(body),
    });
    if (r.status === 401) { this._handle401(); throw new Error('Not authenticated'); }
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || r.statusText); }
    return r.json();
  },
  stream(path, body, onEvent, onDone) {
    /* POST then read the SSE stream line by line */
    fetch(`/api${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...Auth.headers() },
      body: JSON.stringify(body),
    }).then(async r => {
      if (r.status === 401) { this._handle401(); if (onDone) onDone(); return; }
      const reader = r.body.getReader();
      const dec    = new TextDecoder();
      let buf      = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop();
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try { onEvent(JSON.parse(line.slice(6))); } catch {}
          }
        }
      }
      if (onDone) onDone();
    }).catch(err => {
      onEvent({ type: 'error', message: err.message });
      if (onDone) onDone();
    });
  }
};

/* ── Router ─────────────────────────────────────────────────── */
const Router = {
  current: null,
  routes: {},

  register(name, renderFn) { this.routes[name] = renderFn; },

  navigate(page) {
    window.location.hash = `/${page}`;
  },

  init() {
    const handle = () => {
      const hash = window.location.hash.slice(2) || 'dashboard';
      this.render(hash);
    };
    window.addEventListener('hashchange', handle);
    handle();

    document.querySelectorAll('.nav-item').forEach(el => {
      el.addEventListener('click', () => {
        this.navigate(el.dataset.page);
      });
    });
  },

  render(page) {
    this.current = page;
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.page === page);
    });

    const titles = {
      dashboard: 'Dashboard',
      devices: 'Device Inventory',
      'ip-lookup': 'IP Address Lookup',
      ise: 'Cisco ISE',
      firewall: '🔥 Security Policy Lookup',
      'command-runner': 'Command Runner',
      import: 'Device Management',
      reports: 'Reports & Exports',
    };
    document.getElementById('page-title').textContent = titles[page] || page;

    const fn = this.routes[page];
    const el = document.getElementById('content');
    if (fn) {
      el.innerHTML = '<div class="empty-state"><div class="spinner spinner-lg"></div></div>';
      fn(el);
    } else {
      el.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🗺️</div><div class="empty-state-title">Page not found</div><div class="empty-state-desc">${page}</div></div>`;
    }
  }
};

/* ── Sidebar Toggle ─────────────────────────────────────────── */
function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  const main = document.getElementById('main');
  const isCollapsed = sidebar.classList.contains('collapsed');
  
  if (isCollapsed) {
    sidebar.classList.remove('collapsed');
    main.style.marginLeft = 'var(--sidebar-w)';
    localStorage.setItem('sidebar-collapsed', 'false');
  } else {
    sidebar.classList.add('collapsed');
    main.style.marginLeft = '70px';
    localStorage.setItem('sidebar-collapsed', 'true');
  }
}

/* ── Initialize Sidebar State ───────────────────────────────── */
function initSidebarState() {
  const collapsed = localStorage.getItem('sidebar-collapsed') === 'true';
  const sidebar = document.getElementById('sidebar');
  const main = document.getElementById('main');
  
  if (collapsed && sidebar) {
    sidebar.classList.add('collapsed');
    main.style.marginLeft = '70px';
  } else if (main) {
    main.style.marginLeft = 'var(--sidebar-w)';
  }
}

/* ── Toast ──────────────────────────────────────────────────── */
function toast(msg, type = 'info', ms = 3500) {
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  const icons = { success: '✅', error: '❌', warn: '⚠️', info: 'ℹ️' };
  el.innerHTML = `<span>${icons[type] || ''}</span><span>${msg}</span>`;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => el.remove(), ms);
}

/* ── Table helper ───────────────────────────────────────────── */
function makeTable(cols, rows, onRowClick) {
  if (!rows.length) {
    return `<div class="empty-state"><div class="empty-state-icon">📭</div>
      <div class="empty-state-title">No results</div></div>`;
  }
  const head = cols.map(c =>
    `<th data-col="${c.key}">${c.label}<span class="sort-arrow">↕</span></th>`
  ).join('');

  const body = rows.map((r, i) =>
    `<tr data-idx="${i}">${cols.map(c => {
      const raw = r[c.key];
      const val = c.render ? c.render(raw, r) : (raw ?? '—');
      return `<td class="${c.mono ? 'mono' : ''}">${val}</td>`;
    }).join('')}</tr>`
  ).join('');

  return `<table class="table table-striped table-hover table-sm"><thead class="table-dark"><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function bindTableSort(container, cols, rows, onRowClick) {
  let sortCol = null, sortDir = 1;

  const rebind = () => {
    container.querySelectorAll('tbody tr').forEach((tr, idx) => {
      tr.addEventListener('click', () => {
        container.querySelectorAll('tbody tr').forEach(r => r.classList.remove('selected'));
        tr.classList.add('selected');
        if (onRowClick) onRowClick(rows[parseInt(tr.dataset.idx)], tr);
      });
    });
    container.querySelectorAll('thead th').forEach(th => {
      th.addEventListener('click', () => {
        const col = th.dataset.col;
        if (sortCol === col) sortDir *= -1;
        else { sortCol = col; sortDir = 1; }
        rows.sort((a, b) => {
          const av = a[col] ?? '', bv = b[col] ?? '';
          return String(av).localeCompare(String(bv), undefined, { numeric: true }) * sortDir;
        });
        rows.forEach((r, i) => { /* re-index */
          const tr = container.querySelector(`tbody tr:nth-child(${i + 1})`);
          if (tr) tr.dataset.idx = String(i);
        });
        container.querySelectorAll('thead th').forEach(h => h.classList.remove('sorted'));
        th.classList.add('sorted');
        const tbody = container.querySelector('tbody');
        tbody.innerHTML = rows.map((r, i) =>
          `<tr data-idx="${i}">${cols.map(c => {
            const raw = r[c.key];
            const val = c.render ? c.render(raw, r) : (raw ?? '—');
            return `<td class="${c.mono ? 'mono' : ''}">${val}</td>`;
          }).join('')}</tr>`
        ).join('');
        rebind();
      });
    });
  };
  rebind();
}

/* ── KV detail rows ─────────────────────────────────────────── */
function kvRow(label, value) {
  return `<div class="kv-row"><span class="kv-label">${label}</span><span class="kv-value">${value ?? '—'}</span></div>`;
}

/* ── Reachability badge ─────────────────────────────────────── */
function reachBadge(status) {
  if (status === 'Reachable') return `<span class="badge text-bg-success">✅ Reachable</span>`;
  return `<span class="badge text-bg-danger">🔴 ${status || 'Unknown'}</span>`;
}

/* ── Format timestamp ───────────────────────────────────────── */
function fmtTs(ts) {
  if (!ts) return '—';
  try { return new Date(parseInt(ts)).toLocaleString(); } catch { return ts; }
}

/* ── Modal ──────────────────────────────────────────────────── */
function showModal(title, bodyHtml, wide = false) {
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';
  backdrop.innerHTML = `
    <div class="modal ${wide ? 'wide' : ''}">
      <div class="modal-header">
        <span class="modal-title">${title}</span>
        <button class="modal-close" onclick="this.closest('.modal-backdrop').remove()">✕</button>
      </div>
      <div class="modal-body">${bodyHtml}</div>
    </div>`;
  backdrop.addEventListener('click', e => { if (e.target === backdrop) backdrop.remove(); });
  document.body.appendChild(backdrop);
  return backdrop;
}

/* ── System status ──────────────────────────────────────────── */
async function loadStatus() {
  try {
    const s = await API.get('/status');
    const set = (id, ok, detail) => {
      document.getElementById(id).className = `status-dot ${ok ? 'ok' : 'err'}`;
      document.getElementById(`${id}-txt`).textContent = detail;
    };
    set('st-dnac', s.dnac?.ok,     `DNAC — ${s.dnac?.detail || '?'}`);
    set('st-ise',  s.ise?.ok,      `ISE — ${s.ise?.detail || '?'}`);
    set('st-pan',  s.panorama?.ok, `Panorama — ${s.panorama?.detail || '?'}`);
  } catch {}
}

async function refreshCache() {
  toast('Refreshing cache…', 'info');
  try {
    await API.post('/dnac/cache/refresh', {});
    toast('Cache refreshed', 'success');
    loadStatus();
  } catch (e) { toast(e.message, 'error'); }
}

/* ── Cache bar helpers ──────────────────────────────────────── */
function fmtAge(ts) {
  const sec = Math.floor(Date.now() / 1000 - ts);
  if (sec < 60)    return `${sec}s ago`;
  if (sec < 3600)  return `${Math.floor(sec / 60)}m ago`;
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60);
  return m ? `${h}h ${m}m ago` : `${h}h ago`;
}

async function initCacheBar(barEl, infoUrl, refreshUrl, onRefresh) {
  if (!barEl) return;
  try {
    const info  = await API.get(infoUrl);
    const setAt = info.oldest_at ?? info.devices?.set_at;
    barEl.innerHTML = setAt
      ? `<span class="cache-ts">Cached ${fmtAge(setAt)}</span>
         <button class="btn btn-xs cache-refresh-btn">↻ Refresh</button>`
      : `<span class="cache-ts cache-ts-warn">Not yet cached</span>`;
    barEl.querySelector('.cache-refresh-btn')?.addEventListener('click', async () => {
      barEl.innerHTML = '<span class="cache-ts cache-ts-warn">Refreshing…</span>';
      try { await API.post(refreshUrl, {}); } catch {}
      onRefresh();
    });
  } catch {}
}

/* ================================================================
   PAGES
   ================================================================ */

/* ── Dashboard ──────────────────────────────────────────────── */
Router.register('dashboard', async (el) => {
  try {
    const [stats, status] = await Promise.all([
      API.get('/dnac/devices/stats'),
      API.get('/status'),
    ]);

    const pct    = stats.pct_reachable ?? 0;
    const pctBar = `<div class="progress-outer"><div class="progress-inner" style="width:${pct}%"></div></div>`;

    el.innerHTML = `
      <div class="kpi-row cols-4">
        <div class="kpi-card">
          <div class="kpi-label">Total Devices</div>
          <div class="kpi-value">${stats.total?.toLocaleString() ?? '—'}</div>
        </div>
        <div class="kpi-card success">
          <div class="kpi-label">Reachable</div>
          <div class="kpi-value">${stats.reachable?.toLocaleString() ?? '—'}</div>
          <div class="kpi-sub">${pct}% of inventory</div>
        </div>
        <div class="kpi-card danger">
          <div class="kpi-label">Unreachable</div>
          <div class="kpi-value">${stats.unreachable?.toLocaleString() ?? '—'}</div>
          <div class="kpi-sub">${pctBar}</div>
        </div>
        <div class="kpi-card teal">
          <div class="kpi-label">Systems Online</div>
          <div class="kpi-value">${[status.dnac, status.ise, status.panorama].filter(s => s?.ok).length}/3</div>
          <div class="kpi-sub">DNAC · ISE · Panorama</div>
        </div>
      </div>

      <div class="grid-2 mb-4">
        <div class="card">
          <div class="card-header"><span class="card-title">Top Platforms</span></div>
          <div class="card-body p-0">
            <table class="table table-striped table-hover table-sm">
              <thead class="table-dark"><tr><th>Platform</th><th>Count</th></tr></thead>
              <tbody>
                ${(stats.platforms || []).map(([p, c]) =>
                  `<tr><td>${p}</td><td><strong>${c}</strong></td></tr>`
                ).join('')}
              </tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Software Versions</span></div>
          <div class="card-body p-0">
            <table class="table table-striped table-hover table-sm">
              <thead class="table-dark"><tr><th>Version</th><th>Count</th></tr></thead>
              <tbody>
                ${(stats.versions || []).map(([v, c]) =>
                  `<tr><td class="mono">${v}</td><td><strong>${c}</strong></td></tr>`
                ).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header"><span class="card-title">Devices by Role</span></div>
        <div class="card-body p-0">
          <table class="table table-striped table-hover table-sm">
            <thead class="table-dark"><tr><th>Role</th><th>Count</th></tr></thead>
            <tbody>
              ${(stats.roles || []).map(([r, c]) =>
                `<tr><td>${r}</td><td><strong>${c}</strong></td></tr>`
              ).join('')}
            </tbody>
          </table>
        </div>
      </div>`;
  } catch (e) {
    el.innerHTML = `<div class="alert alert-danger">Failed to load dashboard: ${e.message}</div>`;
  }
});

/* ── Devices ────────────────────────────────────────────────── */
Router.register('devices', async (el) => {
  el.innerHTML = `
    <div class="table-wrap">
      <div class="table-toolbar">
        <div class="search-input"><input class="input" id="dev-hostname" placeholder="Hostname…" style="width:160px"></div>
        <div class="search-input"><input class="input" id="dev-ip" placeholder="IP address…" style="width:140px"></div>
        <input class="input" id="dev-platform" placeholder="Platform…" style="width:130px">
        <input class="input" id="dev-site" placeholder="Site…" style="width:150px">
        <select class="select" id="dev-reach" style="width:130px">
          <option value="">All reachability</option>
          <option value="reachable">Reachable</option>
          <option value="unreachable">Unreachable</option>
        </select>
        <button class="btn btn-primary" id="dev-search">Search</button>
        <span class="table-count" id="dev-count"></span>
        <div class="cache-bar" id="dev-cache-bar"></div>
      </div>
      <div id="dev-table"><div class="empty-state"><div class="spinner spinner-lg"></div></div></div>
    </div>
    <div id="dev-detail" class="mt-4"></div>`;

  const cols = [
    { key: 'hostname',            label: 'Hostname' },
    { key: 'managementIpAddress', label: 'Mgmt IP', mono: true },
    { key: 'platformId',          label: 'Platform' },
    { key: 'softwareVersion',     label: 'IOS Version', mono: true },
    { key: 'role',                label: 'Role' },
    { key: 'siteName',            label: 'Site' },
    { key: 'reachabilityStatus',  label: 'Status',
      render: v => reachBadge(v) },
    { key: 'lastContactFormatted', label: 'Last Contact' },
  ];

  const PAGE_SIZE = 50;
  let allDevices = [], devPage = 0, devSortCol = null, devSortDir = 1;

  function renderDeviceTable() {
    const tableEl = document.getElementById('dev-table');
    const total      = allDevices.length;
    const totalPages = Math.ceil(total / PAGE_SIZE) || 1;
    const start      = devPage * PAGE_SIZE;
    const pageItems  = allDevices.slice(start, start + PAGE_SIZE);

    if (!total) {
      tableEl.innerHTML = `<div class="empty-state"><div class="empty-state-icon">📭</div>
        <div class="empty-state-title">No results</div></div>`;
      return;
    }

    const head = cols.map(c =>
      `<th data-col="${c.key}" class="${devSortCol === c.key ? 'sorted' : ''}">${c.label}<span class="sort-arrow">↕</span></th>`
    ).join('');
    const body = pageItems.map((r, i) =>
      `<tr data-idx="${start + i}">${cols.map(c => {
        const raw = r[c.key];
        const val = c.render ? c.render(raw, r) : (raw ?? '—');
        return `<td class="${c.mono ? 'mono' : ''}">${val}</td>`;
      }).join('')}</tr>`
    ).join('');

    const showStart = start + 1, showEnd = Math.min(start + PAGE_SIZE, total);
    tableEl.innerHTML = `
      <table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>
      <div class="pagination">
        <button class="btn btn-ghost btn-sm" id="dev-prev" ${devPage === 0 ? 'disabled' : ''}>← Prev</button>
        <span class="pagination-info">Showing ${showStart}–${showEnd} of ${total.toLocaleString()}</span>
        <button class="btn btn-ghost btn-sm" id="dev-next" ${devPage >= totalPages - 1 ? 'disabled' : ''}>Next →</button>
      </div>`;

    tableEl.querySelectorAll('tbody tr').forEach(tr => {
      tr.addEventListener('click', () => {
        tableEl.querySelectorAll('tbody tr').forEach(r => r.classList.remove('selected'));
        tr.classList.add('selected');
        showDeviceDetail(allDevices[parseInt(tr.dataset.idx)]);
      });
    });

    tableEl.querySelectorAll('thead th').forEach(th => {
      th.addEventListener('click', () => {
        const col = th.dataset.col;
        if (devSortCol === col) devSortDir *= -1;
        else { devSortCol = col; devSortDir = 1; }
        allDevices.sort((a, b) => {
          const av = a[col] ?? '', bv = b[col] ?? '';
          return String(av).localeCompare(String(bv), undefined, { numeric: true }) * devSortDir;
        });
        devPage = 0;
        renderDeviceTable();
      });
    });

    document.getElementById('dev-prev')?.addEventListener('click', () => { devPage--; renderDeviceTable(); });
    document.getElementById('dev-next')?.addEventListener('click', () => { devPage++; renderDeviceTable(); });
  }

  async function doSearch() {
    const params = new URLSearchParams({
      hostname:     document.getElementById('dev-hostname').value,
      ip:           document.getElementById('dev-ip').value,
      platform:     document.getElementById('dev-platform').value,
      site:         document.getElementById('dev-site').value,
      reachability: document.getElementById('dev-reach').value,
      limit:        2000,
    });
    const tableEl = document.getElementById('dev-table');
    tableEl.innerHTML = '<div class="empty-state"><div class="spinner spinner-lg"></div></div>';
    try {
      const data = await API.get(`/dnac/devices?${params}`);
      allDevices  = data.items;
      devPage     = 0;
      document.getElementById('dev-count').textContent = `${data.total.toLocaleString()} device(s)`;
      renderDeviceTable();
    } catch (e) {
      tableEl.innerHTML = `<div class="alert alert-danger">${e.message}</div>`;
    }
  }

  document.getElementById('dev-search').addEventListener('click', doSearch);
  ['dev-hostname','dev-ip','dev-platform','dev-site'].forEach(id => {
    document.getElementById(id)?.addEventListener('keydown', e => { if (e.key === 'Enter') doSearch(); });
  });
  doSearch();

  function showDeviceDetail(device) {
    const detEl   = document.getElementById('dev-detail');
    const devId   = device.id;
    const dnacUrl = `${window.location.origin.replace(':8000','')}/dna/provision/devices/inventory/device-details?deviceId=${devId}`;

    detEl.innerHTML = `
      <div class="detail-panel">
        <div class="detail-header">
          <span style="font-size:18px">${device.reachabilityStatus === 'Reachable' ? '✅' : '🔴'}</span>
          <div>
            <div class="detail-hostname">${device.hostname || '—'}</div>
            <div style="font-size:11px;opacity:.7">${device.managementIpAddress} · ${device.platformId}</div>
          </div>
          <div class="ml-auto flex gap-2 items-center">
            <button class="btn btn-secondary btn-sm" onclick="loadConfig('${devId}','${device.hostname}')">📄 Config</button>
            <a class="btn btn-ghost btn-sm" href="${dnacUrl}" target="_blank">🔗 Open in DNAC</a>
          </div>
        </div>
        <div class="detail-body">
          <div class="detail-grid">
            <div class="detail-section">
              <div class="detail-section-title">Identity</div>
              ${kvRow('Hostname', device.hostname)}
              ${kvRow('Management IP', `<code>${device.managementIpAddress}</code>`)}
              ${kvRow('Platform', device.platformId)}
              ${kvRow('IOS Version', device.softwareVersion)}
              ${kvRow('Serial', device.serialNumber)}
              ${kvRow('Vendor', device.vendor)}
              ${kvRow('Site', device.siteName)}
            </div>
            <div class="detail-section">
              <div class="detail-section-title">Status</div>
              ${kvRow('Reachability', reachBadge(device.reachabilityStatus))}
              ${kvRow('Role', device.role)}
              ${kvRow('Uptime', device.upTime)}
              ${kvRow('Last Contact', device.lastContactFormatted)}
              ${kvRow('Device ID', `<code style="font-size:10px">${device.id}</code>`)}
              ${device.reachabilityFailureReason ? kvRow('Failure', `<span class="badge text-bg-danger">${device.reachabilityFailureReason}</span>`) : ''}
            </div>
          </div>
          <div id="config-area-${devId}"></div>
        </div>
      </div>`;

    detEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  window.loadConfig = async function(devId, hostname) {
    const area = document.getElementById(`config-area-${devId}`);
    area.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';
    try {
      const data = await API.get(`/dnac/devices/${devId}/config`);
      area.innerHTML = `
        <hr class="divider">
        <div class="section-header">
          <div class="section-title">Running Config — ${hostname}</div>
          <div class="flex gap-2">
            <input class="input" id="cfg-filter-${devId}" placeholder="Filter lines…" style="width:200px">
            <button class="btn btn-ghost btn-sm" onclick="downloadConfig('${hostname}','${devId}')">⬇️ Download</button>
          </div>
        </div>
        <div class="code-wrap">
          <div class="code-toolbar">📄 ${hostname} · ${data.cached ? 'cached' : 'live'}</div>
          <pre class="code-block" id="cfg-pre-${devId}">${escHtml(data.config)}</pre>
        </div>`;

      document.getElementById(`cfg-filter-${devId}`).addEventListener('input', e => {
        const q     = e.target.value.toLowerCase();
        const lines = data.config.split('\n');
        const shown = q ? lines.filter(l => l.toLowerCase().includes(q)) : lines;
        document.getElementById(`cfg-pre-${devId}`).textContent = shown.join('\n');
      });

      window._configs = window._configs || {};
      window._configs[devId] = { text: data.config, hostname };

    } catch (err) {
      area.innerHTML = `<div class="alert alert-danger">${err.message}</div>`;
    }
  };

  window.downloadConfig = function(hostname, devId) {
    const c = (window._configs || {})[devId];
    if (!c) return;
    dlText(c.text, `${hostname}_config.txt`);
  };

  initCacheBar(
    el.querySelector('#dev-cache-bar'),
    '/dnac/cache/info',
    '/dnac/cache/refresh',
    () => Router.go('devices')
  );
});

/* ── IP Lookup ──────────────────────────────────────────────── */
Router.register('ip-lookup', async (el) => {
  el.innerHTML = `
    <div class="card max-w-[700px] mb-4">
      <div class="card-header"><span class="card-title">🔍 IP Address Lookup</span></div>
      <div class="card-body">
        <div class="input-row">
          <div class="form-group">
            <label class="form-label">IP Address</label>
            <input class="input" id="ip-input" placeholder="e.g. 10.47.31.195">
          </div>
          <button class="btn btn-primary mt-5" id="ip-go">Look up</button>
        </div>
      </div>
    </div>
    <div id="ip-result"></div>`;

  async function doLookup() {
    const ip    = document.getElementById('ip-input').value.trim();
    const resEl = document.getElementById('ip-result');
    if (!ip) return;
    resEl.innerHTML = '<div class="empty-state"><div class="spinner spinner-lg"></div></div>';
    try {
      const data = await API.get(`/dnac/ip-lookup/${encodeURIComponent(ip)}`);
      if (!data.found) {
        resEl.innerHTML = `
          <div class="alert alert-warn">⚠️ No interface found for <strong>${ip}</strong> in DNAC.
          The address may be a secondary IP, loopback, or not yet synced.</div>`;
        return;
      }
      resEl.innerHTML = data.interfaces.map(r => {
        const iface  = r.interface || {};
        const device = r.device   || {};
        return `
          <div class="grid-2 mb-4">
            <div class="card">
              <div class="card-header"><span class="card-title">🔌 Interface</span>
                <span style="color:var(--text-secondary);font-size:12px;margin-left:8px">${iface.portName || ''}</span>
              </div>
              <div class="card-body">
                ${kvRow('IP Address', `<code>${ip}</code>`)}
                ${kvRow('Subnet', iface.subnet)}
                ${kvRow('MAC Address', iface.macAddress)}
                ${kvRow('VLAN', iface.vlanId)}
                ${kvRow('Description', iface.description)}
                ${kvRow('Admin Status', iface.adminStatus)}
                ${kvRow('Oper Status', iface.operStatus)}
                ${kvRow('Speed', iface.speed)}
              </div>
            </div>
            <div class="card">
              <div class="card-header">
                <span>${device.reachabilityStatus === 'Reachable' ? '✅' : '🔴'}</span>
                <span class="card-title">${device.hostname || 'Unknown Device'}</span>
              </div>
              <div class="card-body">
                ${kvRow('Management IP', `<code>${device.managementIpAddress}</code>`)}
                ${kvRow('Platform', device.platformId)}
                ${kvRow('IOS Version', device.softwareVersion)}
                ${kvRow('Serial', device.serialNumber)}
                ${kvRow('Role', device.role)}
                ${kvRow('Site', r.siteName)}
                ${kvRow('Uptime', device.upTime)}
                ${kvRow('Last Contact', device.lastContactFormatted)}
                ${kvRow('Reachability', reachBadge(device.reachabilityStatus))}
              </div>
            </div>
          </div>`;
      }).join('');
    } catch (e) {
      resEl.innerHTML = `<div class="alert alert-danger">${e.message}</div>`;
    }
  }

  document.getElementById('ip-go').addEventListener('click', doLookup);
  document.getElementById('ip-input').addEventListener('keydown', e => { if (e.key === 'Enter') doLookup(); });
});

/* ── ISE ────────────────────────────────────────────────────── */
Router.register('ise', async (el) => {
  el.innerHTML = `
    <div class="d-flex gap-3 align-items-center mb-0">
      <ul class="nav nav-tabs flex-grow-1" id="ise-tabs" role="tablist" style="margin-bottom: 0;">
        <li class="nav-item" role="presentation">
          <button class="nav-link active" id="ise-nads-tab" data-bs-toggle="tab" data-bs-target="#ise-nads" type="button" role="tab" aria-controls="ise-nads" aria-selected="true">NADs</button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="ise-endpoints-tab" data-bs-toggle="tab" data-bs-target="#ise-endpoints" type="button" role="tab" aria-controls="ise-endpoints" aria-selected="false">Endpoints</button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="ise-trustsec-tab" data-bs-toggle="tab" data-bs-target="#ise-trustsec" type="button" role="tab" aria-controls="ise-trustsec" aria-selected="false">TrustSec</button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="ise-identity-tab" data-bs-toggle="tab" data-bs-target="#ise-identity" type="button" role="tab" aria-controls="ise-identity" aria-selected="false">Identity</button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="ise-policy-tab" data-bs-toggle="tab" data-bs-target="#ise-policy" type="button" role="tab" aria-controls="ise-policy" aria-selected="false">Policy</button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="ise-admin-tab" data-bs-toggle="tab" data-bs-target="#ise-admin" type="button" role="tab" aria-controls="ise-admin" aria-selected="false">Admin</button>
        </li>
      </ul>
      <div class="cache-bar" id="ise-cache-bar"></div>
    </div>
    <div class="tab-content" id="ise-content" style="padding-top: 16px;">
      <div class="tab-pane fade show active" id="ise-nads" role="tabpanel" aria-labelledby="ise-nads-tab"></div>
      <div class="tab-pane fade" id="ise-endpoints" role="tabpanel" aria-labelledby="ise-endpoints-tab"></div>
      <div class="tab-pane fade" id="ise-trustsec" role="tabpanel" aria-labelledby="ise-trustsec-tab"></div>
      <div class="tab-pane fade" id="ise-identity" role="tabpanel" aria-labelledby="ise-identity-tab"></div>
      <div class="tab-pane fade" id="ise-policy" role="tabpanel" aria-labelledby="ise-policy-tab"></div>
      <div class="tab-pane fade" id="ise-admin" role="tabpanel" aria-labelledby="ise-admin-tab"></div>
    </div>`;

  // Set up Bootstrap tab event listeners
  const tabMap = {
    'ise-nads': renderNads,
    'ise-endpoints': renderEndpoints,
    'ise-trustsec': renderTrustsec,
    'ise-identity': renderIdentity,
    'ise-policy': renderPolicy,
    'ise-admin': renderAdmin,
  };

  // Attach click handlers to tab buttons
  Object.entries(tabMap).forEach(([paneId, renderFn]) => {
    const button = document.getElementById(paneId + '-tab');
    if (button) {
      button.addEventListener('click', (e) => {
        e.preventDefault();
        const pane = document.getElementById(paneId);
        if (pane) {
          // Update button states
          document.querySelectorAll('#ise-tabs .nav-link').forEach(btn => {
            btn.classList.remove('active');
            btn.setAttribute('aria-selected', 'false');
          });
          button.classList.add('active');
          button.setAttribute('aria-selected', 'true');
          
          // Hide all panes
          document.querySelectorAll('#ise-content .tab-pane').forEach(p => {
            p.classList.remove('show', 'active');
          });
          // Show this pane
          pane.classList.add('show', 'active');
          // Render content
          renderFn(pane);
        }
      });
    }
  });

  // Load initial tab
  renderNads(document.getElementById('ise-nads'));

  initCacheBar(
    el.querySelector('#ise-cache-bar'),
    '/ise/cache/info',
    '/ise/cache/refresh',
    () => Router.go('ise')
  );

  /* NADs */
  async function renderNads(area) {
    area.innerHTML = `
      <div class="table-wrap">
        <div class="table-toolbar">
          <div class="search-input"><input class="form-control form-control-sm" id="nad-search" placeholder="Search by name or IP…" style="width:220px"></div>
          <button class="btn btn-primary btn-sm" id="nad-go">Search</button>
          <span class="table-count" id="nad-count"></span>
        </div>
        <div id="nad-table"></div>
      </div>
      <div id="nad-detail" class="mt-4"></div>`;

    const cols = [
      { key: 'name', label: 'Name' },
      { key: 'description', label: 'Description' },
    ];

    async function doNadSearch() {
      const q = document.getElementById('nad-search').value;
      const tEl = document.getElementById('nad-table');
      tEl.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';
      try {
        const d = await API.get(`/ise/nads?search=${encodeURIComponent(q)}`);
        document.getElementById('nad-count').textContent = `${d.total} device(s)`;
        tEl.innerHTML = makeTable(cols, d.items, nad => loadNadDetail(nad));
        bindTableSort(tEl, cols, d.items, nad => loadNadDetail(nad));
      } catch (e) { tEl.innerHTML = `<div class="alert alert-danger">${e.message}</div>`; }
    }

    document.getElementById('nad-go').addEventListener('click', doNadSearch);
    document.getElementById('nad-search').addEventListener('keydown', e => { if (e.key === 'Enter') doNadSearch(); });

    async function loadNadDetail(nad) {
      const detEl = document.getElementById('nad-detail');
      detEl.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';
      try {
        const d    = await API.get(`/ise/nads/${nad.id}`);
        const ips  = (d.NetworkDeviceIPList || []).map(e => `${e.ipaddress}/${e.mask}`).join(', ') || '—';
        const grps = (d.NetworkDeviceGroupList || []).join(', ') || '—';
        const rad  = d.authenticationSettings || {};
        const tac  = d.tacacsSettings || {};
        const snmp = d.snmpsettings || {};
        detEl.innerHTML = `
          <div class="detail-panel">
            <div class="detail-header"><span class="detail-hostname">🖥️ ${d.name}</span></div>
            <div class="detail-body">
              <div class="detail-grid">
                <div class="detail-section">
                  <div class="detail-section-title">Identity</div>
                  ${kvRow('IP / Mask', ips)}
                  ${kvRow('Profile', d.profileName)}
                  ${kvRow('Model', d.modelName)}
                  ${kvRow('Groups', grps)}
                  ${kvRow('CoA Port', d.coaPort)}
                </div>
                <div class="detail-section">
                  <div class="detail-section-title">RADIUS</div>
                  ${kvRow('Protocol', rad.networkProtocol)}
                  ${kvRow('Secret', rad.radiusSharedSecret ? '*** (set)' : 'Not set')}
                  <div class="detail-section-title mt-3">TACACS</div>
                  ${kvRow('Secret', tac.sharedSecret ? '*** (set)' : 'Not set')}
                  ${kvRow('Connect Mode', tac.connectModeOptions)}
                  <div class="detail-section-title mt-3">SNMP</div>
                  ${kvRow('Version', snmp.version)}
                  ${kvRow('Poll Interval', snmp.pollingInterval ? `${snmp.pollingInterval}s` : '—')}
                </div>
              </div>
            </div>
          </div>`;
      } catch(e) { detEl.innerHTML = `<div class="alert alert-danger">${e.message}</div>`; }
    }
  }

  /* Endpoints */
  async function renderEndpoints(area) {
    area.innerHTML = `
      <div class="table-wrap">
        <div class="table-toolbar">
          <div class="search-input"><input class="input" id="ep-mac" placeholder="MAC address (partial OK)…" style="width:240px"></div>
          <button class="btn btn-primary" id="ep-go">Search</button>
          <span class="table-count" id="ep-count"></span>
        </div>
        <div id="ep-table"></div>
      </div>
      <div id="ep-detail" class="mt-4"></div>`;

    document.getElementById('ep-go').addEventListener('click', async () => {
      const mac = document.getElementById('ep-mac').value.trim();
      if (!mac || mac.length < 2) { toast('Enter at least 2 characters', 'warn'); return; }
      const tEl = document.getElementById('ep-table');
      tEl.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';
      try {
        const d = await API.get(`/ise/endpoints?mac=${encodeURIComponent(mac)}`);
        document.getElementById('ep-count').textContent = `${d.total} endpoint(s)`;
        const cols = [{ key: 'name', label: 'MAC Address', mono: true }, { key: 'description', label: 'Description' }];
        tEl.innerHTML = makeTable(cols, d.items, ep => loadEpDetail(ep));
        bindTableSort(tEl, cols, d.items, ep => loadEpDetail(ep));
        if (d.items.length === 1) loadEpDetail(d.items[0]);
      } catch (e) { tEl.innerHTML = `<div class="alert alert-danger">${e.message}</div>`; }
    });

    async function loadEpDetail(ep) {
      const detEl = document.getElementById('ep-detail');
      detEl.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';
      try {
        const d   = await API.get(`/ise/endpoints/${ep.id}`);
        const mfc = d.mfcAttributes || {};
        const mfcVal = k => { const v = mfc[k]; return Array.isArray(v) && v.length ? v[0] : '—'; };
        detEl.innerHTML = `
          <div class="detail-panel">
            <div class="detail-header"><span class="detail-hostname">💻 ${d.mac || ep.name}</span></div>
            <div class="detail-body">
              <div class="detail-grid">
                <div class="detail-section">
                  <div class="detail-section-title">Endpoint</div>
                  ${kvRow('Portal User', d.portalUser)}
                  ${kvRow('Identity Store', d.identityStore)}
                  ${kvRow('Profile ID', d.profileId)}
                  ${kvRow('Group ID', d.groupId)}
                  ${kvRow('Static Profile', d.staticProfileAssignment)}
                  ${kvRow('Static Group', d.staticGroupAssignment)}
                </div>
                <div class="detail-section">
                  <div class="detail-section-title">MFC Profiler</div>
                  ${kvRow('Endpoint Type', mfcVal('mfcDeviceType'))}
                  ${kvRow('Manufacturer', mfcVal('mfcHardwareManufacturer'))}
                  ${kvRow('Model', mfcVal('mfcHardwareModel'))}
                  ${kvRow('Operating System', mfcVal('mfcOperatingSystem'))}
                </div>
              </div>
              <p style="font-size:11px;color:var(--text-secondary);margin-top:12px">
                ℹ️ Full authentication attributes (AAA-Server, AD-*, Posture) available once OpenAPI is enabled on ISE.
              </p>
            </div>
          </div>`;
      } catch(e) { detEl.innerHTML = `<div class="alert alert-danger">${e.message}</div>`; }
    }
  }

  /* TrustSec */
  async function renderTrustsec(area) {
    area.innerHTML = `
      <ul class="nav nav-tabs mb-3" id="ts-tabs" role="tablist">
        <li class="nav-item" role="presentation">
          <button class="nav-link active" id="ts-sgts-tab" data-bs-toggle="tab" data-bs-target="#ts-sgts" type="button" role="tab" aria-controls="ts-sgts" aria-selected="true">SGTs</button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="ts-sgacls-tab" data-bs-toggle="tab" data-bs-target="#ts-sgacls" type="button" role="tab" aria-controls="ts-sgacls" aria-selected="false">SGACLs</button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="ts-egress-tab" data-bs-toggle="tab" data-bs-target="#ts-egress" type="button" role="tab" aria-controls="ts-egress" aria-selected="false">Egress Matrix</button>
        </li>
      </ul>
      <div class="tab-content" id="ts-content">
        <div class="tab-pane fade show active" id="ts-sgts" role="tabpanel" aria-labelledby="ts-sgts-tab"></div>
        <div class="tab-pane fade" id="ts-sgacls" role="tabpanel" aria-labelledby="ts-sgacls-tab"></div>
        <div class="tab-pane fade" id="ts-egress" role="tabpanel" aria-labelledby="ts-egress-tab"></div>
      </div>`;

    const tsTabs = {
      'ts-sgts': renderSgts,
      'ts-sgacls': renderSgacls,
      'ts-egress': renderEgress,
    };

    Object.entries(tsTabs).forEach(([tabId, renderFn]) => {
      const button = document.getElementById(tabId + '-tab');
      if (button) {
        button.addEventListener('click', (e) => {
          e.preventDefault();
          // Update button states
          document.querySelectorAll('#ts-tabs .nav-link').forEach(btn => {
            btn.classList.remove('active');
            btn.setAttribute('aria-selected', 'false');
          });
          button.classList.add('active');
          button.setAttribute('aria-selected', 'true');
          
          // Hide all panes
          document.querySelectorAll('#ts-content .tab-pane').forEach(p => {
            p.classList.remove('show', 'active');
          });
          // Show this pane
          const pane = document.getElementById(tabId);
          pane.classList.add('show', 'active');
          // Render content
          renderFn(pane);
        });
      }
    });

    // Load initial tab
    renderSgts(document.getElementById('ts-sgts'));

    async function renderSgts(a) {
      a.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';
      try {
        const d = await API.get('/ise/sgts');
        const cols = [
          { key: 'name', label: 'Name' },
          { key: 'value', label: 'Tag Value' },
          { key: 'propagateToApic', label: 'To APIC', render: v => v ? 'Yes' : 'No' },
          { key: 'description', label: 'Description' },
        ];
        a.innerHTML = `<div class="table-wrap">${makeTable(cols, d.items)}</div>`;
        bindTableSort(a.querySelector('.table-wrap'), cols, d.items, null);
      } catch(e) { a.innerHTML = `<div class="alert alert-danger">${e.message}</div>`; }
    }

    async function renderSgacls(a) {
      a.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';
      try {
        const d = await API.get('/ise/sgacls');
        const cols = [
          { key: 'name', label: 'Name' },
          { key: 'ipVersion', label: 'IP Version' },
          { key: 'description', label: 'Description' },
        ];
        a.innerHTML = `<div class="table-wrap">${makeTable(cols, d.items)}</div>`;
        bindTableSort(a.querySelector('.table-wrap'), cols, d.items, null);
      } catch(e) { a.innerHTML = `<div class="alert alert-danger">${e.message}</div>`; }
    }

    async function renderEgress(a) {
      a.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';
      try {
        const d = await API.get('/ise/egress-matrix');
        const cols = [
          { key: 'sourceSgtId', label: 'Src SGT' },
          { key: 'destinationSgtId', label: 'Dst SGT' },
          { key: 'matrixCellStatus', label: 'Status' },
          { key: 'defaultRule', label: 'Default Rule' },
        ];
        a.innerHTML = `<div class="table-wrap">${makeTable(cols, d.items)}</div>`;
        bindTableSort(a.querySelector('.table-wrap'), cols, d.items, null);
      } catch(e) { a.innerHTML = `<div class="alert alert-danger">${e.message}</div>`; }
    }
  }

  /* Identity */
  async function renderIdentity(area) {
    area.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';
    try {
      const d = await API.get('/ise/identity-groups');
      const cols = [
        { key: 'name', label: 'Name' },
        { key: 'parent', label: 'Parent' },
        { key: 'description', label: 'Description' },
      ];
      area.innerHTML = `<div class="table-wrap">${makeTable(cols, d.items)}</div>`;
      bindTableSort(area.querySelector('.table-wrap'), cols, d.items, null);
    } catch(e) { area.innerHTML = `<div class="alert alert-danger">${e.message}</div>`; }
  }

  /* Policy */
  async function renderPolicy(area) {
    area.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';
    try {
      const d = await API.get('/ise/policy-sets');
      const cols = [
        { key: 'name', label: 'Policy Set' },
        { key: 'description', label: 'Description' },
      ];
      area.innerHTML = `
        <div class="table-wrap">${makeTable(cols, d.items, ps => loadPolicyDetail(ps))}</div>
        <div id="ps-detail" class="mt-4"></div>`;
      bindTableSort(area.querySelector('.table-wrap'), cols, d.items, ps => loadPolicyDetail(ps));
      if (!d.items.length) {
        area.innerHTML = `<div class="alert alert-info">ℹ️ No policy sets returned — ensure OpenAPI is enabled on ISE (Administration → System → Settings → API Settings).</div>`;
      }
    } catch(e) { area.innerHTML = `<div class="alert alert-danger">${e.message}</div>`; }

    async function loadPolicyDetail(ps) {
      const detEl = document.getElementById('ps-detail');
      if (!detEl) return;
      detEl.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';
      try {
        const d = await API.get(`/ise/policy-sets/${ps.id}/auth-rules`);
        const cols = [
          { key: 'rank', label: 'Rank' },
          { key: 'name', label: 'Rule Name' },
          { key: 'state', label: 'State' },
          { key: 'identitySourceName', label: 'Identity Source' },
        ];
        detEl.innerHTML = `
          <div class="card">
            <div class="card-header"><span class="card-title">Auth Rules — ${ps.name}</span></div>
            <div class="card-body p-0">${makeTable(cols, d.items)}</div>
          </div>`;
      } catch(e) { detEl.innerHTML = `<div class="alert alert-danger">${e.message}</div>`; }
    }
  }

  /* Admin */
  async function renderAdmin(area) {
    area.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';
    try {
      const d = await API.get('/ise/deployment-nodes');
      const cols = [
        { key: 'hostname', label: 'Hostname' },
        { key: 'ipAddress', label: 'IP', mono: true },
        { key: 'fqdn', label: 'FQDN' },
        { key: 'nodeType', label: 'Type' },
      ];
      area.innerHTML = `<div class="table-wrap">${makeTable(cols, d.items)}</div>`;
      bindTableSort(area.querySelector('.table-wrap'), cols, d.items, null);
    } catch(e) { area.innerHTML = `<div class="alert alert-danger">${e.message}</div>`; }
  }
});

/* ── Firewall ───────────────────────────────────────────────── */
Router.register('firewall', async (el) => {
  let deviceGroups = [];
  let managedDevices = [];
  
  try { 
    const d = await API.get('/firewall/device-groups'); 
    deviceGroups = d.items || []; 
    console.log('Loaded device groups:', deviceGroups);
  } catch (e) { 
    console.error('Failed to load device groups:', e);
  }
  
  try { 
    const d = await API.get('/firewall/devices'); 
    managedDevices = d.items || []; 
    console.log('Loaded managed devices:', managedDevices);
  } catch (e) { 
    console.error('Failed to load managed devices:', e);
  }

  // Create tabbed interface
  el.innerHTML = `
    <ul class="nav nav-tabs mb-3" id="fw-tabs" role="tablist">
      <li class="nav-item" role="presentation">
        <button class="nav-link active" id="fw-lookup-tab" data-bs-toggle="tab" data-bs-target="#fw-lookup" type="button" role="tab" aria-controls="fw-lookup" aria-selected="true">Policy Lookup</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="fw-bydevice-tab" data-bs-toggle="tab" data-bs-target="#fw-bydevice" type="button" role="tab" aria-controls="fw-bydevice" aria-selected="false">By Device</button>
      </li>
    </ul>
    
    <div class="tab-content" id="fw-content">
      <!-- Lookup Tab -->
      <div class="tab-pane fade show active" id="fw-lookup" role="tabpanel" aria-labelledby="fw-lookup-tab">
        <div class="card mb-4">
          <div class="card-header d-flex justify-content-between align-items-center">
            <span class="card-title">Security Policy Lookup</span>
            <div class="cache-bar" id="fw-cache-bar"></div>
          </div>
          <div class="card-body">
            <div style="display:grid;grid-template-columns:1fr 1fr 120px 120px auto;gap:12px;align-items:flex-end">
              <div class="form-group m-0">
                <label class="form-label">Source IP</label>
                <input class="form-control form-control-sm" id="fw-src" placeholder="10.47.31.195">
              </div>
              <div class="form-group m-0">
                <label class="form-label">Destination IP</label>
                <input class="form-control form-control-sm" id="fw-dst" placeholder="10.16.97.122">
              </div>
              <div class="form-group m-0">
                <label class="form-label">Protocol</label>
                <select class="form-select form-select-sm" id="fw-proto">
                  <option value="any">Any</option>
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
              </div>
              <div class="form-group m-0">
                <label class="form-label">Dest Port</label>
                <input class="form-control form-control-sm" id="fw-port" placeholder="443">
              </div>
              <button class="btn btn-primary btn-sm" id="fw-go">🔍 Search</button>
          </div>
          <div class="mt-3">
            <div class="form-check form-check-inline">
              <input type="checkbox" class="form-check-input" id="fw-disabled">
              <label class="form-check-label" for="fw-disabled">Include disabled rules</label>
            </div>
            <div class="form-check form-check-inline">
              <input type="checkbox" class="form-check-input" id="fw-all" checked>
              <label class="form-check-label" for="fw-all">Show all matches</label>
            </div>
            ${deviceGroups.length ? `
            <div class="dg-select d-inline-block" id="fw-dg-wrap">
              <button type="button" class="btn btn-outline-secondary btn-sm" id="fw-dg-btn">
                <span id="fw-dg-label">All device groups</span>
              </button>
              <div class="dg-select-panel" id="fw-dg-panel" hidden>
                <label class="dg-select-item dg-select-all-item">
                  <input type="checkbox" id="fw-dg-all" checked>
                  <span>All device groups</span>
                </label>
                <div class="dg-select-divider"></div>
                <div class="dg-select-items">
                  ${deviceGroups.map(dg => `
                    <label class="dg-select-item">
                      <input type="checkbox" class="fw-dg-cb" value="${dg}" checked>
                      <span>${dg}</span>
                    </label>`).join('')}
                </div>
              </div>
            </div>` : ''}
          </div>
        </div>
      </div>
      <div id="fw-result"></div>
    </div>

      <!-- By Device Tab -->
      <div class="tab-pane fade" id="fw-bydevice" role="tabpanel" aria-labelledby="fw-bydevice-tab">
        <div class="card mb-4">
          <div class="card-header d-flex justify-content-between align-items-center">
            <span class="card-title">Firewall Policies</span>
            <div class="cache-bar" id="fw-dev-cache-bar"></div>
          </div>
          <div class="card-body">
            <div class="form-group">
              <label class="form-label">Select Firewall Device</label>
              <select class="form-select form-select-sm" id="fw-device-select">
                <option value="">-- Choose a firewall --</option>
                ${managedDevices.map(d => {
                  const haStatus = d.ha_state ? ` [${d.ha_state.toUpperCase()}]` : '';
                  return `<option value="${d.serial}">${d.hostname || d.serial} (${d.model || 'Unknown'})${haStatus} · ${d.device_group}</option>`;
                }).join('')}
              </select>
            </div>
          </div>
        </div>
        <div id="fw-device-result"></div>
      </div>
    </div>
  `;

  // Setup cache bars
  initCacheBar(
    el.querySelector('#fw-cache-bar'),
    '/firewall/cache/info',
    '/firewall/cache/refresh',
    () => Router.go('firewall')
  );
  
  initCacheBar(
    el.querySelector('#fw-dev-cache-bar'),
    '/firewall/cache/info',
    '/firewall/cache/refresh',
    () => Router.go('firewall')
  );

  // Setup firewall tab click handlers
  const lookupBtn = document.getElementById('fw-lookup-tab');
  const byDeviceBtn = document.getElementById('fw-bydevice-tab');
  
  if (lookupBtn) {
    lookupBtn.addEventListener('click', (e) => {
      e.preventDefault();
      document.querySelectorAll('#fw-tabs .nav-link').forEach(btn => {
        btn.classList.remove('active');
        btn.setAttribute('aria-selected', 'false');
      });
      lookupBtn.classList.add('active');
      lookupBtn.setAttribute('aria-selected', 'true');
      
      document.querySelectorAll('#fw-content .tab-pane').forEach(p => {
        p.classList.remove('show', 'active');
      });
      document.getElementById('fw-lookup').classList.add('show', 'active');
    });
  }
  
  if (byDeviceBtn) {
    byDeviceBtn.addEventListener('click', (e) => {
      e.preventDefault();
      document.querySelectorAll('#fw-tabs .nav-link').forEach(btn => {
        btn.classList.remove('active');
        btn.setAttribute('aria-selected', 'false');
      });
      byDeviceBtn.classList.add('active');
      byDeviceBtn.setAttribute('aria-selected', 'true');
      
      document.querySelectorAll('#fw-content .tab-pane').forEach(p => {
        p.classList.remove('show', 'active');
      });
      document.getElementById('fw-bydevice').classList.add('show', 'active');
    });
  }

  // Setup device group selector for lookup tab
  if (deviceGroups.length) {
    const wrap    = el.querySelector('#fw-dg-wrap');
    const btn     = el.querySelector('#fw-dg-btn');
    const panel   = el.querySelector('#fw-dg-panel');
    const lbl     = el.querySelector('#fw-dg-label');
    const allCb   = el.querySelector('#fw-dg-all');
    const itemCbs = () => [...el.querySelectorAll('.fw-dg-cb')];

    function updateLabel() {
      const checked = itemCbs().filter(cb => cb.checked);
      lbl.textContent = checked.length === deviceGroups.length || checked.length === 0
        ? 'All device groups'
        : `${checked.length} of ${deviceGroups.length} groups`;
    }

    btn.addEventListener('click', () => { panel.hidden = !panel.hidden; });

    document.addEventListener('click', function outsideClick(e) {
      if (!wrap.contains(e.target)) { panel.hidden = true; }
    });

    allCb.addEventListener('change', () => {
      itemCbs().forEach(cb => cb.checked = allCb.checked);
      updateLabel();
    });

    el.querySelector('.dg-select-items').addEventListener('change', () => {
      const all = itemCbs();
      allCb.checked       = all.every(cb => cb.checked);
      allCb.indeterminate = !allCb.checked && all.some(cb => cb.checked);
      updateLabel();
    });
  }

  // Setup lookup button
  document.getElementById('fw-go').addEventListener('click', async () => {
    const src  = document.getElementById('fw-src').value.trim();
    const dst  = document.getElementById('fw-dst').value.trim();
    const port = document.getElementById('fw-port').value.trim();
    const res  = document.getElementById('fw-result');

    if (!src || !dst) { toast('Enter source and destination IP', 'warn'); return; }
    res.innerHTML = '<div class="empty-state"><div class="spinner spinner-lg"></div><p style="margin-top:12px;color:var(--text-secondary)">Loading rules from Panorama (cached after first run)…</p></div>';

    const checkedDgs = [...el.querySelectorAll('.fw-dg-cb:checked')].map(cb => cb.value);
    const body = {
      src_ip: src, dst_ip: dst,
      dst_port: port ? parseInt(port) : null,
      protocol: document.getElementById('fw-proto').value,
      include_disabled: document.getElementById('fw-disabled').checked,
      show_all: document.getElementById('fw-all').checked,
      device_groups: checkedDgs.length === deviceGroups.length || checkedDgs.length === 0 ? [] : checkedDgs,
    };

    try {
      const data  = await API.post('/firewall/lookup', body);
      const portLabel = port ? `:${port}` : ' (any port)';
      const decisColor = data.traffic_decision === 'allow' ? 'var(--success)' : 'var(--danger)';

      if (!data.match_count) {
        res.innerHTML = `
          <div class="alert alert-warn">⚠️ No rules match <strong>${src} → ${dst}${portLabel}</strong>. Traffic hits the implicit deny.</div>
          <div style="font-size:12px;color:var(--text-secondary);margin-top:8px">${data.rules_searched.toLocaleString()} rules searched.</div>`;
        return;
      }

      const cols = [
        { key: '_icon', label: '',
          render: (_, r) => r.action === 'allow' ? '✅' : '🔴' },
        { key: 'name', label: 'Rule Name',
          render: (v, r) => r.first_match ? `⭐ ${v}` : v },
        { key: 'device_group', label: 'Device Group' },
        { key: 'rulebase', label: 'Rulebase' },
        { key: 'action', label: 'Action',
          render: v => `<span class="badge ${v === 'allow' ? 'text-bg-success' : 'text-bg-danger'}">${v.toUpperCase()}</span>` },
        { key: 'source', label: 'Source',
          render: v => fmtList(v) },
        { key: 'destination', label: 'Destination',
          render: v => fmtList(v) },
        { key: 'service', label: 'Service',
          render: v => fmtList(v) },
      ];

      const rows = data.matches.map(m => ({ ...m, _icon: '' }));

      const kpis = `
        <div class="kpi-row cols-4 mb-4">
          <div class="kpi-card"><div class="kpi-label">Rules Searched</div><div class="kpi-value">${data.rules_searched.toLocaleString()}</div></div>
          <div class="kpi-card"><div class="kpi-label">Matching Rules</div><div class="kpi-value">${data.match_count}</div></div>
          <div class="kpi-card ${data.traffic_decision === 'allow' ? 'success' : 'danger'}">
            <div class="kpi-label">Traffic Decision</div>
            <div class="kpi-value" style="font-size:20px;color:${decisColor}">${data.traffic_decision.toUpperCase()}</div>
          </div>
          <div class="kpi-card"><div class="kpi-label">Flow</div><div class="kpi-value" style="font-size:13px;padding-top:4px">${src} → ${dst}${portLabel}</div></div>
        </div>`;

      res.innerHTML = `
        ${kpis}
        <div class="table-wrap" id="fw-table">
          <div class="table-toolbar"><span class="table-count">${data.match_count} rule(s) matched — click a row for detail</span></div>
          ${makeTable(cols, rows, rule => showRuleDetail(rule, data))}
        </div>
        <div id="fw-rule-detail" class="mt-4"></div>`;

      bindTableSort(document.getElementById('fw-table'), cols, rows, rule => showRuleDetail(rule, data));

      const firstMatchRow = document.querySelector('#fw-table tbody tr');
      if (firstMatchRow) { firstMatchRow.classList.add('selected'); showRuleDetail(rows[0], data); }

    } catch (e) {
      res.innerHTML = `<div class="alert alert-danger">${e.message}</div>`;
    }
  });

  // Setup device selector for by-device tab
  document.getElementById('fw-device-select').addEventListener('change', async (e) => {
    const serial = e.target.value;
    const res = document.getElementById('fw-device-result');
    
    if (!serial) {
      res.innerHTML = '<div class="empty-state"><p style="color:var(--text-secondary)">Select a firewall to view its policies</p></div>';
      return;
    }
    
    res.innerHTML = '<div class="empty-state"><div class="spinner spinner-lg"></div><p style="margin-top:12px;color:var(--text-secondary)">Loading virtual systems…</p></div>';
    
    try {
      // Fetch vsys list
      const vsysData = await API.get(`/firewall/device-vsys/${serial}`);
      const vsysList = vsysData.vsys || [];
      
      if (!vsysList.length) {
        res.innerHTML = '<div class="alert alert-warn">⚠️ No virtual systems found for this device.</div>';
        return;
      }
      
      // Show vsys selector
      res.innerHTML = `
        <div class="card mb-4">
          <div class="card-body">
            <div class="form-group">
              <label class="form-label">Virtual System (VSYS)</label>
              <select class="form-select form-select-sm" id="fw-vsys-select">
                ${vsysList.map(vsys => `<option value="${vsys}">${vsys}</option>`).join('')}
              </select>
            </div>
          </div>
        </div>
        <div id="fw-vsys-policies"></div>`;
      
      // Setup vsys selector change listener
      document.getElementById('fw-vsys-select').addEventListener('change', async (evt) => {
        const vsys = evt.target.value;
        const policiesRes = document.getElementById('fw-vsys-policies');
        
        if (!vsys) return;
        
        policiesRes.innerHTML = '<div class="empty-state"><div class="spinner spinner-lg"></div><p style="margin-top:12px;color:var(--text-secondary)">Loading policies…</p></div>';
        
        try {
          const policiesData = await API.get(`/firewall/device-vsys-policies/${serial}/${vsys}`);
          const policies = policiesData.policies || [];
          
          if (!policies.length) {
            policiesRes.innerHTML = '<div class="alert alert-info">ℹ️ No policies found for ' + vsys + '.</div>';
            return;
          }
          
          // Display policy table with rule numbers
          const cols = [
            { key: 'rule_number', label: '#', width: '40px',
              render: v => `<span style="font-weight:bold;color:var(--primary)">${v}</span>` },
            { key: '_icon', label: '', width: '30px',
              render: (_, r) => r.action === 'allow' ? '✅' : '🔴' },
            { key: 'name', label: 'Rule Name', width: '200px' },
            { key: 'device_group', label: 'Context', width: '120px' },
            { key: 'rulebase', label: 'Base', width: '80px' },
            { key: 'action', label: 'Action', width: '80px',
              render: v => `<span class="badge ${v === 'allow' ? 'text-bg-success' : 'text-bg-danger'}">${v.toUpperCase()}</span>` },
            { key: 'from_zones', label: 'From', width: '120px',
              render: v => v?.length ? v.join(', ') : '—' },
            { key: 'to_zones', label: 'To', width: '120px',
              render: v => v?.length ? v.join(', ') : '—' },
            { key: 'source', label: 'Source', width: '150px',
              render: v => fmtList(v) },
            { key: 'destination', label: 'Destination', width: '150px',
              render: v => fmtList(v) },
            { key: 'application', label: 'App', width: '120px',
              render: v => fmtList(v) },
            { key: 'service', label: 'Service', width: '120px',
              render: v => fmtList(v) },
          ];
          
          const rows = policies.map(p => ({ ...p, _icon: '' }));
          
          const kpi = `
            <div class="kpi-row cols-3 mb-4">
              <div class="kpi-card"><div class="kpi-label">Total Policies</div><div class="kpi-value">${policies.length}</div></div>
              <div class="kpi-card"><div class="kpi-label">Allow Rules</div><div class="kpi-value" style="color:var(--success)">${policies.filter(p => p.action === 'allow').length}</div></div>
              <div class="kpi-card"><div class="kpi-label">Deny Rules</div><div class="kpi-value" style="color:var(--danger)">${policies.filter(p => p.action === 'deny' || p.action === 'drop').length}</div></div>
            </div>`;
          
          policiesRes.innerHTML = `
            ${kpi}
            <div class="table-wrap" id="fw-vsys-table">
              <div class="table-toolbar"><span class="table-count">${policies.length} policy(ies) — click a row for detail</span></div>
              ${makeTable(cols, rows, rule => showDevicePolicyDetail(rule))}
            </div>
            <div id="fw-vsys-rule-detail" class="mt-4"></div>`;
          
          bindTableSort(document.getElementById('fw-vsys-table'), cols, rows, rule => showDevicePolicyDetail(rule));
          
          const firstRow = document.querySelector('#fw-vsys-table tbody tr');
          if (firstRow) { firstRow.classList.add('selected'); showDevicePolicyDetail(rows[0]); }
          
        } catch (e) {
          policiesRes.innerHTML = `<div class="alert alert-danger">${e.message}</div>`;
        }
      });
      
      // Trigger initial load with first vsys
      document.getElementById('fw-vsys-select').dispatchEvent(new Event('change'));
      
    } catch (e) {
      res.innerHTML = `<div class="alert alert-danger">${e.message}</div>`;
    }
  });

  function fmtList(arr) {
    if (!arr || !arr.length) return '—';
    if (arr.includes('any')) return '<span class="badge text-bg-secondary">any</span>';
    if (arr.length <= 2) return arr.join(', ');
    return `${arr.slice(0,2).join(', ')} <span class="badge text-bg-secondary">+${arr.length-2}</span>`;
  }

  function showRuleDetail(rule, data) {
    const detEl = document.getElementById('fw-rule-detail');
    const actionCss = rule.action === 'allow' ? 'var(--success)' : 'var(--danger)';

    const resolvedRows = (names, resolved) => names
      .filter(n => n !== 'any')
      .flatMap(name => {
        const vals = resolved?.[name] || [];
        if (!vals.length) return [`<tr><td>${name}</td><td style="color:var(--text-secondary)">(unresolved)</td></tr>`];
        return vals.map(v => `<tr><td>${name}</td><td class="mono">${v}</td></tr>`);
      }).join('');

    const svcRows = (names, resolved) => names
      .filter(n => !['any','application-default'].includes(n))
      .flatMap(name => {
        const vals = resolved?.[name] || [];
        if (!vals.length) return [`<tr><td>${name}</td><td>—</td><td>—</td></tr>`];
        return vals.map(v => `<tr><td>${name}</td><td>${v.protocol?.toUpperCase()}</td><td class="mono">${v.ports}</td></tr>`);
      }).join('');

    detEl.innerHTML = `
      <div class="detail-panel">
        <div class="detail-header">
          <span style="font-size:18px">${rule.action === 'allow' ? '✅' : '🔴'}</span>
          <div>
            <div class="detail-hostname">${rule.first_match ? '⭐ ' : ''}${rule.name}</div>
            <div style="font-size:11px;opacity:.7">
              ${rule.device_group} · ${rule.rulebase}-rulebase
              ${rule.disabled ? ' · DISABLED' : ''}
            </div>
          </div>
          <span class="action-badge action-${rule.action}" style="margin-left:auto;padding:4px 12px;border-radius:3px;font-weight:700">${rule.action.toUpperCase()}</span>
        </div>
        <div class="detail-body">
          <div class="detail-grid">
            <div class="detail-section">
              <div class="detail-section-title">Traffic</div>
              ${kvRow('Source Zones', rule.from_zones?.join(', ') || '—')}
              ${kvRow('Source Addresses', fmtList(rule.source))}
              ${kvRow('Source Negate', rule.source_negate ? 'Yes' : 'No')}
              ${kvRow('Dest Zones', rule.to_zones?.join(', ') || '—')}
              ${kvRow('Dest Addresses', fmtList(rule.destination))}
              ${kvRow('Dest Negate', rule.dest_negate ? 'Yes' : 'No')}
            </div>
            <div class="detail-section">
              <div class="detail-section-title">Policy</div>
              ${kvRow('Application', fmtList(rule.application))}
              ${kvRow('Service', fmtList(rule.service))}
              ${kvRow('Security Profile', rule.profile_group)}
              ${kvRow('Log Setting', rule.log_setting)}
              ${kvRow('Tags', rule.tag?.join(', '))}
              ${kvRow('Description', rule.description)}
              ${kvRow('First Match', rule.first_match ? '<span class="badge text-bg-success">Yes — decides traffic</span>' : 'No')}
            </div>
          </div>

          ${(rule.source?.filter(n=>n!='any').length || rule.destination?.filter(n=>n!='any').length || rule.service?.filter(n=>!['any','application-default'].includes(n)).length) ? `
          <hr class="divider">
          <div class="section-title mb-3">Resolved Objects</div>
          <div class="grid-3">
            ${rule.source?.filter(n=>n!='any').length ? `
            <div>
              <div class="detail-section-title">Source Addresses</div>
              <table><thead><tr><th>Object</th><th>Resolves to</th></tr></thead>
              <tbody>${resolvedRows(rule.source, rule.resolved_source)}</tbody></table>
            </div>` : ''}
            ${rule.destination?.filter(n=>n!='any').length ? `
            <div>
              <div class="detail-section-title">Destination Addresses</div>
              <table><thead><tr><th>Object</th><th>Resolves to</th></tr></thead>
              <tbody>${resolvedRows(rule.destination, rule.resolved_destination)}</tbody></table>
            </div>` : ''}
            ${rule.service?.filter(n=>!['any','application-default'].includes(n)).length ? `
            <div>
              <div class="detail-section-title">Services</div>
              <table><thead><tr><th>Service</th><th>Proto</th><th>Port(s)</th></tr></thead>
              <tbody>${svcRows(rule.service, rule.resolved_service)}</tbody></table>
            </div>` : ''}
          </div>` : ''}
        </div>
      </div>`;
  }

  function showDevicePolicyDetail(policy) {
    const detEl = document.getElementById('fw-vsys-rule-detail');
    if (!detEl) return; // In case we're in an old context
    
    detEl.innerHTML = `
      <div class="detail-panel">
        <div class="detail-header">
          <span style="font-size:18px">${policy.action === 'allow' ? '✅' : '🔴'}</span>
          <div>
            <div class="detail-hostname">
              <span style="color:var(--primary);font-weight:bold;margin-right:8px">Rule #${policy.rule_number || '—'}</span>
              ${policy.name}
            </div>
            <div style="font-size:11px;opacity:.7">
              ${policy.device_group} · ${policy.rulebase}-rulebase
              ${policy.disabled ? ' · DISABLED' : ''}
            </div>
          </div>
          <span class="action-badge action-${policy.action}" style="margin-left:auto;padding:4px 12px;border-radius:3px;font-weight:700">${policy.action.toUpperCase()}</span>
        </div>
        <div class="detail-body">
          <div class="detail-grid">
            <div class="detail-section">
              <div class="detail-section-title">Traffic & Zones</div>
              ${kvRow('From Zones', policy.from_zones?.length ? policy.from_zones.join(', ') : '—')}
              ${kvRow('To Zones', policy.to_zones?.length ? policy.to_zones.join(', ') : '—')}
              ${kvRow('Source Addresses', fmtList(policy.source))}
              ${kvRow('Source Negate', policy.source_negate ? 'Yes' : 'No')}
              ${kvRow('Destination Addresses', fmtList(policy.destination))}
              ${kvRow('Dest Negate', policy.dest_negate ? 'Yes' : 'No')}
            </div>
            <div class="detail-section">
              <div class="detail-section-title">Application & Services</div>
              ${kvRow('Application', fmtList(policy.application))}
              ${kvRow('Service', fmtList(policy.service))}
              ${kvRow('Category', fmtList(policy.category))}
            </div>
            <div class="detail-section">
              <div class="detail-section-title">Security & Logging</div>
              ${kvRow('Action', `<span class="badge text-bg-${policy.action === 'allow' ? 'success' : 'danger'}">${policy.action.toUpperCase()}</span>`)}
              ${kvRow('Security Profile', policy.profile_group || '—')}
              ${kvRow('HIP Profiles', fmtList(policy.hip_profiles))}
              ${kvRow('Log Start', policy.log_start ? '✓' : '—')}
              ${kvRow('Log End', policy.log_end ? '✓' : '—')}
              ${kvRow('Log Setting', policy.log_setting || '—')}
            </div>
            <div class="detail-section">
              <div class="detail-section-title">Advanced</div>
              ${kvRow('Source User', fmtList(policy.source_user))}
              ${kvRow('Source User Negate', policy.source_user_negate ? 'Yes' : 'No')}
              ${kvRow('Source Device', fmtList(policy.source_device))}
              ${kvRow('Source Device Negate', policy.source_device_negate ? 'Yes' : 'No')}
              ${kvRow('Dest Device', fmtList(policy.destination_device))}
              ${kvRow('Dest Device Negate', policy.destination_device_negate ? 'Yes' : 'No')}
              ${kvRow('Schedule', policy.schedule || '—')}
              ${kvRow('QoS Type', policy.qos_type || '—')}
              ${kvRow('Tags', policy.tag?.length ? policy.tag.join(', ') : '—')}
            </div>
          </div>
          ${kvRow('Description', policy.description || '(no description)', true)}
        </div>
      </div>`;
  }
});


/* ── Command Runner ─────────────────────────────────────────── */
Router.register('command-runner', async (el) => {
  let devices = [];
  let results = [];

  const quickCmds = [
    '— Quick commands —','show version','show ip interface brief','show interfaces',
    'show ip route summary','show ip bgp summary','show cdp neighbors','show dmvpn',
    'show crypto session','show access-lists','show logging','show ntp status',
    'show processes cpu sorted | head 20','show spanning-tree summary',
    'show ip ospf neighbor','show ip eigrp neighbors',
  ];

  el.innerHTML = `
    <div class="grid-2 gap-4 items-start">
      <!-- Left: device selection -->
      <div>
        <div class="card mb-4">
          <div class="card-header"><span class="card-title">Step 1 — Devices</span></div>
          <div class="card-body">
            <div class="tabs" id="cr-input-tabs">
              <div class="tab active" data-crtab="paste">Paste IPs</div>
              <div class="tab" data-crtab="filter">Filter from DNAC</div>
            </div>
            <div id="cr-paste-panel">
              <textarea class="textarea" id="cr-ips" placeholder="One IP per line, or comma-separated&#10;10.12.4.1&#10;10.14.1.2"></textarea>
              <button class="btn btn-secondary btn-sm mt-2" onclick="parseIpList()">Parse IP list</button>
            </div>
            <div id="cr-filter-panel" style="display:none">
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px">
                <input class="input" id="cr-fhost" placeholder="Hostname…">
                <input class="input" id="cr-fip" placeholder="IP…">
                <input class="input" id="cr-fplat" placeholder="Platform…">
                <select class="select" id="cr-freach">
                  <option value="">All</option>
                  <option value="reachable">Reachable</option>
                  <option value="unreachable">Unreachable</option>
                </select>
              </div>
              <button class="btn btn-secondary btn-sm" onclick="filterDevices()">Apply filter</button>
            </div>
          </div>
        </div>

        <div class="card mb-4">
          <div class="card-header"><span class="card-title">Selected Devices</span>
            <span class="table-count" id="cr-dev-count">0 selected</span>
          </div>
          <div id="cr-dev-table" class="max-h-[220px] overflow-y-auto">
            <div class="empty-state p-5">No devices selected yet.</div>
          </div>
        </div>
      </div>

      <!-- Right: command + creds -->
      <div>
        <div class="card mb-4">
          <div class="card-header"><span class="card-title">Step 2 — Command</span></div>
          <div class="card-body">
            <div class="form-group">
              <label class="form-label">Quick commands</label>
              <select class="select" id="cr-quick">
                ${quickCmds.map(c => `<option>${c}</option>`).join('')}
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">Command</label>
              <input class="input" id="cr-cmd" placeholder="e.g. show ip interface brief">
            </div>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Step 3 — Settings</span></div>
          <div class="card-body">
            <div class="grid-2 gap-3">
              <div class="form-group m-0">
                <label class="form-label">Device type</label>
                <select class="select" id="cr-dtype">
                  <option value="auto">Auto-detect from DNAC</option>
                  <option value="cisco_ios">cisco_ios</option>
                  <option value="cisco_nxos">cisco_nxos</option>
                  <option value="cisco_asa">cisco_asa</option>
                  <option value="paloalto_panos">paloalto_panos</option>
                  <option value="linux">linux</option>
                </select>
              </div>
              <div class="form-group m-0">
                <label class="form-label">Parallel workers</label>
                <input class="input" type="number" id="cr-workers" value="10" min="1" max="30">
              </div>
              <div class="form-group m-0">
                <label class="form-label">Timeout (s)</label>
                <input class="input" type="number" id="cr-timeout" value="30" min="10" max="120">
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="mt-4 flex gap-3 items-center">
      <button class="btn btn-primary" id="cr-run" onclick="runCommands()">▶ Run</button>
      <span id="cr-run-status" style="font-size:12px;color:var(--text-secondary)"></span>
    </div>

    <div id="cr-progress" class="mt-4" style="display:none">
      <div class="progress-outer"><div class="progress-inner" id="cr-prog-bar" style="width:0%"></div></div>
      <div class="progress-label" id="cr-prog-label">Starting…</div>
      <div class="log-stream mt-2 max-h-[200px]" id="cr-log"></div>
    </div>

    <div id="cr-results" class="mt-4"></div>`;

  // Tab switching
  document.querySelectorAll('#cr-input-tabs .tab').forEach(t => {
    t.addEventListener('click', () => {
      document.querySelectorAll('#cr-input-tabs .tab').forEach(x => x.classList.remove('active'));
      t.classList.add('active');
      document.getElementById('cr-paste-panel').style.display = t.dataset.crtab === 'paste' ? '' : 'none';
      document.getElementById('cr-filter-panel').style.display = t.dataset.crtab === 'filter' ? '' : 'none';
    });
  });

  // Quick command selector
  document.getElementById('cr-quick').addEventListener('change', e => {
    const v = e.target.value;
    if (v !== '— Quick commands —') document.getElementById('cr-cmd').value = v;
  });

  window.parseIpList = async function() {
    const raw = document.getElementById('cr-ips').value;
    const ips = raw.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
    if (!ips.length) return;
    // Look up from DNAC cache
    let dnacDevices = [];
    try { const d = await API.get(`/dnac/devices?limit=2000`); dnacDevices = d.items; } catch {}
    const ipMap = {};
    dnacDevices.forEach(d => { ipMap[d.managementIpAddress] = d; });
    devices = ips.map(ip => ({
      ip, hostname: ipMap[ip]?.hostname || ip, platform: ipMap[ip]?.platformId || '',
    }));
    renderDeviceList();
  };

  window.filterDevices = async function() {
    const params = new URLSearchParams({
      hostname: document.getElementById('cr-fhost').value,
      ip: document.getElementById('cr-fip').value,
      platform: document.getElementById('cr-fplat').value,
      reachability: document.getElementById('cr-freach').value,
      limit: 500,
    });
    try {
      const d = await API.get(`/dnac/devices?${params}`);
      devices = d.items.map(dev => ({
        ip: dev.managementIpAddress, hostname: dev.hostname, platform: dev.platformId,
      }));
      renderDeviceList();
    } catch(e) { toast(e.message, 'error'); }
  };

  function renderDeviceList() {
    document.getElementById('cr-dev-count').textContent = `${devices.length} selected`;
    const tEl = document.getElementById('cr-dev-table');
    if (!devices.length) { tEl.innerHTML = '<div class="empty-state p-5">No devices.</div>'; return; }
    tEl.innerHTML = `<table>
      <thead><tr><th>Hostname</th><th>IP</th><th>Platform</th></tr></thead>
      <tbody>${devices.map(d => `<tr><td>${d.hostname}</td><td class="mono">${d.ip}</td><td>${d.platform||'—'}</td></tr>`).join('')}</tbody>
    </table>`;
  }

  window.runCommands = function() {
    const cmd = document.getElementById('cr-cmd').value.trim();
    if (!devices.length) { toast('Select devices first', 'warn'); return; }
    if (!cmd) { toast('Enter a command', 'warn'); return; }

    results = [];
    document.getElementById('cr-progress').style.display = '';
    document.getElementById('cr-results').innerHTML = '';
    document.getElementById('cr-run').disabled = true;
    document.getElementById('cr-log').innerHTML = '';

    const logEl  = document.getElementById('cr-log');
    const progEl = document.getElementById('cr-prog-bar');
    const lblEl  = document.getElementById('cr-prog-label');
    let done = 0;

    function logLine(msg, level='info') {
      const ts = new Date().toLocaleTimeString();
      logEl.innerHTML += `<div class="log-line ${level}"><span class="log-time">${ts}</span><span class="log-msg">${msg}</span></div>`;
      logEl.scrollTop = logEl.scrollHeight;
    }

    const body = {
      devices,
      command: cmd,
      device_type_override: document.getElementById('cr-dtype').value === 'auto' ? null : document.getElementById('cr-dtype').value,
      max_workers: parseInt(document.getElementById('cr-workers').value),
      timeout: parseInt(document.getElementById('cr-timeout').value),
    };

    API.stream('/commands/run', body, ev => {
      if (ev.type === 'progress') {
        done = ev.done;
        results.push(ev);
        const pct = Math.round((done / ev.total) * 100);
        progEl.style.width = pct + '%';
        lblEl.textContent = `${done}/${ev.total} complete`;
        const icon = ev.status === 'success' ? '✅' : '❌';
        logLine(`${icon} ${ev.hostname} (${ev.ip}) — ${ev.status} in ${ev.elapsed}s`, ev.status === 'success' ? 'success' : 'error');
      } else if (ev.type === 'complete') {
        renderResults(cmd);
        document.getElementById('cr-run').disabled = false;
      } else if (ev.type === 'error') {
        logLine(`Error: ${ev.message}`, 'error');
      }
    }, () => {
      document.getElementById('cr-run').disabled = false;
    });
  };

  function renderResults(cmd) {
    const resEl = document.getElementById('cr-results');
    const ok    = results.filter(r => r.status === 'success').length;
    const cols  = [
      { key: '_icon', label: '', render: (_, r) => r.status === 'success' ? '✅' : '❌' },
      { key: 'hostname', label: 'Hostname' },
      { key: 'ip', label: 'IP', mono: true },
      { key: 'platform', label: 'Platform' },
      { key: 'status', label: 'Status' },
      { key: 'elapsed', label: 'Time (s)' },
      { key: 'lines', label: 'Lines', render: (_, r) => r.output ? r.output.split('\n').length : 0 },
    ];
    const rows = results.map(r => ({ ...r, _icon: '' }));

    resEl.innerHTML = `
      <div class="kpi-row cols-4 mb-4">
        <div class="kpi-card"><div class="kpi-label">Total</div><div class="kpi-value">${results.length}</div></div>
        <div class="kpi-card success"><div class="kpi-label">Succeeded</div><div class="kpi-value">${ok}</div></div>
        <div class="kpi-card danger"><div class="kpi-label">Failed</div><div class="kpi-value">${results.length - ok}</div></div>
        <div class="kpi-card"><div class="kpi-label">Avg Time</div><div class="kpi-value">${(results.reduce((s,r)=>s+r.elapsed,0)/results.length).toFixed(1)}s</div></div>
      </div>
      <div class="table-wrap" id="cr-res-table">
        <div class="table-toolbar">
          <span class="table-count">Click a row to view output</span>
          <button class="btn btn-ghost btn-sm ml-auto" onclick="downloadAllOutput()">⬇️ Download All</button>
          <button class="btn btn-ghost btn-sm" onclick="downloadCsv()">⬇️ CSV</button>
        </div>
        ${makeTable(cols, rows, r => showOutputDetail(r))}
      </div>
      <div id="cr-out-detail" class="mt-4"></div>`;

    bindTableSort(document.getElementById('cr-res-table'), cols, rows, r => showOutputDetail(r));
  }

  function showOutputDetail(r) {
    const detEl = document.getElementById('cr-out-detail');
    detEl.innerHTML = `
      <div class="detail-panel">
        <div class="detail-header">
          <span>${r.status === 'success' ? '✅' : '❌'}</span>
          <span class="detail-hostname">${r.hostname} (${r.ip})</span>
          <span style="margin-left:auto;font-size:11px;opacity:.7">${r.elapsed}s · ${r.status}</span>
        </div>
        <div class="detail-body p-0">
          ${r.output ? `
            <div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;gap:8px">
              <input class="input max-w-[240px]" id="out-filter" placeholder="Filter lines…">
              <button class="btn btn-ghost btn-sm" onclick="dlText(document.getElementById('out-pre').textContent,'${r.hostname}_output.txt')">⬇️ Download</button>
            </div>
            <pre class="code-block" id="out-pre" style="border-radius:0;max-height:460px">${escHtml(r.output)}</pre>` :
            `<div class="alert alert-danger m-3">${r.error}</div>`}
        </div>
      </div>`;

    const filterEl = document.getElementById('out-filter');
    if (filterEl) {
      filterEl.addEventListener('input', e => {
        const q = e.target.value.toLowerCase();
        const lines = r.output.split('\n');
        document.getElementById('out-pre').textContent = q
          ? lines.filter(l => l.toLowerCase().includes(q)).join('\n')
          : r.output;
      });
    }
  }

  window.downloadAllOutput = function() {
    const text = results.map(r =>
      `${'='.repeat(60)}\nDevice: ${r.hostname} (${r.ip})\nStatus: ${r.status} | Time: ${r.elapsed}s\n${'='.repeat(60)}\n` +
      (r.output || `ERROR: ${r.error}`)
    ).join('\n\n');
    dlText(text, `command_output_${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.txt`);
  };

  window.downloadCsv = function() {
    const header = 'Hostname,IP,Platform,Status,Time_s,Error\n';
    const rows   = results.map(r =>
      [r.hostname, r.ip, r.platform, r.status, r.elapsed, r.error||''].map(v => `"${v}"`).join(',')
    ).join('\n');
    dlText(header + rows, 'command_summary.csv');
  };
});

/* ── Device Management ──────────────────────────────────────── */
Router.register('import', async (el) => {
  el.innerHTML = `
    <ul class="nav nav-tabs mb-3" id="mgmt-tabs" role="tablist">
      <li class="nav-item" role="presentation">
        <button class="nav-link active" id="mgmt-discovery-tab" data-bs-toggle="tab" data-bs-target="#mgmt-discovery" type="button" role="tab" aria-controls="mgmt-discovery" aria-selected="true">Discovery &amp; Import</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="mgmt-tag-tab" data-bs-toggle="tab" data-bs-target="#mgmt-tag" type="button" role="tab" aria-controls="mgmt-tag" aria-selected="false">Tag Devices</button>
      </li>
    </ul>
    
    <div class="tab-content" id="mgmt-content">
      <!-- Discovery Tab -->
      <div class="tab-pane fade show active" id="mgmt-discovery" role="tabpanel" aria-labelledby="mgmt-discovery-tab">
        <div id="mgmt-discovery-content"></div>
      </div>
      
      <!-- Tag Devices Tab -->
      <div class="tab-pane fade" id="mgmt-tag" role="tabpanel" aria-labelledby="mgmt-tag-tab">
        <div id="mgmt-tag-content"></div>
      </div>
    </div>`;

  // Setup tab event listeners
  const discoveryTab = el.querySelector('#mgmt-discovery-tab');
  const tagTab = el.querySelector('#mgmt-tag-tab');

  if (discoveryTab) {
    discoveryTab.addEventListener('shown.bs.tab', () => {
      renderDiscovery(document.getElementById('mgmt-discovery-content'));
    });
  }

  if (tagTab) {
    tagTab.addEventListener('shown.bs.tab', () => {
      renderTagDevices(document.getElementById('mgmt-tag-content'));
    });
  }

  // Initialize first tab content
  renderDiscovery(document.getElementById('mgmt-discovery-content'));

  /* ── Discovery tab ── */
  function renderDiscovery(area) {
    area.innerHTML = `
    <div class="card mb-4">
      <div class="card-header"><span class="card-title">Device Discovery & Import</span></div>
      <div class="card-body">
        <div class="alert alert-warning mb-4">
          ⚠️ <strong>Write operation.</strong> This discovers and assigns devices in Catalyst Center.
        </div>
        <div class="form-group">
          <label class="form-label">Device list  (site_code,ip_address — one per line)</label>
          <textarea class="form-control" id="imp-input" style="min-height:140px" placeholder="# One entry per line&#10;ATL-T1,10.16.1.1&#10;DFW-T1,10.12.4.1&#10;ORD-T1,10.14.1.2"></textarea>
        </div>
        <div class="row mb-3 g-3">
          <div class="col-md-6">
            <div class="form-group m-0">
              <label class="form-label">CLI Username</label>
              <input class="form-control form-control-sm" id="imp-cli" value="dnac-acct">
            </div>
          </div>
          <div class="col-md-6">
            <div class="form-group m-0">
              <label class="form-label">SNMP Username</label>
              <input class="form-control form-control-sm" id="imp-snmp" value="tsa_mon_user">
            </div>
          </div>
        </div>
        <button class="btn btn-primary btn-sm" id="imp-preview">Preview</button>
      </div>
    </div>
    <div id="imp-preview-area" class="mb-4"></div>
    <div id="imp-progress" style="display:none" class="mb-4">
      <div class="progress">
        <div class="progress-bar" id="imp-bar" style="width:0%"></div>
      </div>
      <div class="small text-muted mt-2" id="imp-label">Starting…</div>
      <div class="log-stream mt-2 small" id="imp-log"></div>
    </div>
    <div id="imp-results"></div>`;

    document.getElementById('imp-preview').addEventListener('click', () => {
    const raw = document.getElementById('imp-input').value;
    const lines = raw.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    const entries = lines.map(l => {
      const [site, ip] = l.split(',').map(s => s.trim());
      return { site, ip, valid: !!(site && ip) };
    });

    const prevEl = document.getElementById('imp-preview-area');
    if (!entries.length) { prevEl.innerHTML = ''; return; }

    prevEl.innerHTML = `
      <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
          <span class="card-title">Preview — ${entries.length} entries</span>
          <div>
            <label class="form-check">
              <input type="checkbox" class="form-check-input" id="imp-confirm">
              <span class="form-check-label small">I confirm I want to run this import</span>
            </label>
            <button class="btn btn-primary btn-sm" id="imp-run" disabled>🚀 Run Import</button>
          </div>
        </div>
        <div class="card-body p-0">
          <table class="table table-sm table-striped table-hover mb-0">
            <thead class="table-dark"><tr><th>Site Code</th><th>IP Address</th><th>Valid</th></tr></thead>
            <tbody>
              ${entries.map(e => `<tr>
                <td>${e.site || '<span class="badge text-bg-danger">Missing</span>'}</td>
                <td class="font-monospace" style="font-size:12px">${e.ip || '<span class="badge text-bg-danger">Missing</span>'}</td>
                <td>${e.valid ? '<span class="badge text-bg-success">✅</span>' : '<span class="badge text-bg-danger">❌</span>'}</td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>`;

    const confirmEl = document.getElementById('imp-confirm');
    const runBtn    = document.getElementById('imp-run');
    confirmEl.addEventListener('change', () => { runBtn.disabled = !confirmEl.checked; });

    runBtn.addEventListener('click', () => {
      const valid = entries.filter(e => e.valid);
      runImport(valid.map(e => ({ site_code: e.site, ip: e.ip })));
    });
  });

  function runImport(entries) {
    document.getElementById('imp-progress').style.display = '';
    document.getElementById('imp-results').innerHTML = '';

    const logEl  = document.getElementById('imp-log');
    const barEl  = document.getElementById('imp-bar');
    const lblEl  = document.getElementById('imp-label');

    function log(msg, level = 'info') {
      const ts = new Date().toLocaleTimeString();
      logEl.innerHTML += `<div class="log-line ${level}"><span class="log-time">${ts}</span><span class="log-msg">${escHtml(msg)}</span></div>`;
      logEl.scrollTop = logEl.scrollHeight;
    }

    const body = {
      entries,
      cli_username:  document.getElementById('imp-cli').value,
      snmp_username: document.getElementById('imp-snmp').value,
    };

    API.stream('/import/run', body, ev => {
      if (ev.type === 'log') {
        log(ev.message, ev.level);
      } else if (ev.type === 'progress') {
        barEl.style.width = ev.pct + '%';
        lblEl.textContent = `${ev.done}/${ev.total} processed`;
      } else if (ev.type === 'complete') {
        barEl.style.width = '100%';
        lblEl.textContent = 'Complete';
        renderImportResults(ev);
      } else if (ev.type === 'error') {
        log(`Error: ${ev.message}`, 'error');
      }
    });
  }

  function renderImportResults(ev) {
    const resEl = document.getElementById('imp-results');
    resEl.innerHTML = `
      <div class="kpi-row cols-4 mb-4">
        <div class="kpi-card"><div class="kpi-label">Total</div><div class="kpi-value">${ev.total}</div></div>
        <div class="kpi-card success"><div class="kpi-label">Discovered</div><div class="kpi-value">${ev.discovered}</div></div>
        <div class="kpi-card warn"><div class="kpi-label">Skipped</div><div class="kpi-value">${ev.skipped}</div></div>
        <div class="kpi-card danger"><div class="kpi-label">Failed</div><div class="kpi-value">${ev.failed + ev.no_site}</div></div>
      </div>
      <div class="table-wrap">
        <table class="table table-sm table-striped table-hover table-dark">
          <thead><tr><th>IP</th><th>Site</th><th>Outcome</th></tr></thead>
          <tbody>
            ${(ev.results || []).map(r => `<tr>
              <td class="font-monospace" style="font-size:12px">${r.ip}</td>
              <td>${r.site}</td>
              <td><span class="badge ${r.outcome === 'discovered' ? 'text-bg-success' : r.outcome === 'skipped_exists' ? 'text-bg-secondary' : 'text-bg-danger'}">${r.outcome}</span></td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>`;
  }
  } // end renderDiscovery

  /* ── Tag Devices tab ── */
  function renderTagDevices(area) {
    area.innerHTML = `
    <div class="card mb-4">
      <div class="card-header"><span class="card-title">Tag Devices</span></div>
      <div class="card-body">
        <div class="alert alert-warning mb-4">
          ⚠️ <strong>Write operation.</strong> This applies a tag to devices in Catalyst Center.
        </div>
        <div class="form-group">
          <label class="form-label">Tag Name</label>
          <input class="form-control form-control-sm" id="tag-name" placeholder="e.g. CRITICAL-INFRA" style="max-width:300px">
        </div>
        <div class="form-group">
          <label class="form-label">IP Addresses (one per line)</label>
          <textarea class="form-control" id="tag-ips" style="min-height:140px" placeholder="10.16.1.1&#10;10.12.4.1&#10;10.14.1.2"></textarea>
        </div>
        <button class="btn btn-primary btn-sm" id="tag-run">🏷️ Apply Tag</button>
      </div>
    </div>
    <div id="tag-progress" style="display:none" class="mb-4">
      <div class="log-stream small" id="tag-log"></div>
    </div>
    <div id="tag-results"></div>`;

    document.getElementById('tag-run').addEventListener('click', () => {
      const tagName = document.getElementById('tag-name').value.trim();
      const ips     = document.getElementById('tag-ips').value
        .split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));

      if (!tagName) { alert('Please enter a tag name.'); return; }
      if (!ips.length) { alert('Please enter at least one IP address.'); return; }

      document.getElementById('tag-progress').style.display = '';
      document.getElementById('tag-results').innerHTML = '';
      const logEl = document.getElementById('tag-log');
      logEl.innerHTML = '';

      function log(msg, level = 'info') {
        const ts = new Date().toLocaleTimeString();
        logEl.innerHTML += `<div class="log-line ${level}"><span class="log-time">${ts}</span><span class="log-msg">${escHtml(msg)}</span></div>`;
        logEl.scrollTop = logEl.scrollHeight;
      }

      API.stream('/dnac/tag-devices', { tag_name: tagName, ips }, ev => {
        if (ev.type === 'log') {
          log(ev.message, ev.level);
        } else if (ev.type === 'complete') {
          const resEl = document.getElementById('tag-results');
          resEl.innerHTML = `
            <div class="kpi-row cols-2 mb-4">
              <div class="kpi-card success"><div class="kpi-label">Tagged</div><div class="kpi-value">${ev.tagged}</div></div>
              <div class="kpi-card warn"><div class="kpi-label">Not Found</div><div class="kpi-value">${ev.skipped}</div></div>
            </div>
            ${ev.tagged ? `<div class="table-wrap">
              <table class="table table-sm table-striped table-hover table-dark">
                <thead><tr><th>Hostname</th><th>IP</th><th>Tag</th></tr></thead>
                <tbody>
                  ${(ev.results || []).map(r => `<tr>
                    <td>${r.hostname}</td>
                    <td class="font-monospace" style="font-size:12px">${r.ip}</td>
                    <td><span class="badge text-bg-info">${escHtml(ev.tag_name)}</span></td>
                  </tr>`).join('')}
                </tbody>
              </table>
            </div>` : ''}`;
        } else if (ev.type === 'error') {
          log(`Error: ${ev.message}`, 'error');
        }
      });
    });
  }

});

/* ── Reports ────────────────────────────────────────────────── */
Router.register('reports', async (el) => {
  el.innerHTML = `
    <ul class="nav nav-tabs mb-3" id="rep-tabs" role="tablist">
      <li class="nav-item" role="presentation">
        <button class="nav-link active" id="rep-inventory-tab" data-bs-toggle="tab" data-bs-target="#rep-inventory" type="button" role="tab" aria-controls="rep-inventory" aria-selected="true">Inventory Export</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="rep-unreachable-tab" data-bs-toggle="tab" data-bs-target="#rep-unreachable" type="button" role="tab" aria-controls="rep-unreachable" aria-selected="false">Unreachable</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="rep-sites-tab" data-bs-toggle="tab" data-bs-target="#rep-sites" type="button" role="tab" aria-controls="rep-sites" aria-selected="false">Sites</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="rep-config-tab" data-bs-toggle="tab" data-bs-target="#rep-config" type="button" role="tab" aria-controls="rep-config" aria-selected="false">Config Search</button>
      </li>
    </ul>
    
    <div class="tab-content" id="rep-content">
      <!-- Inventory Tab -->
      <div class="tab-pane fade show active" id="rep-inventory" role="tabpanel" aria-labelledby="rep-inventory-tab">
        <div id="rep-inventory-content"></div>
      </div>
      
      <!-- Unreachable Tab -->
      <div class="tab-pane fade" id="rep-unreachable" role="tabpanel" aria-labelledby="rep-unreachable-tab">
        <div id="rep-unreachable-content"></div>
      </div>
      
      <!-- Sites Tab -->
      <div class="tab-pane fade" id="rep-sites" role="tabpanel" aria-labelledby="rep-sites-tab">
        <div id="rep-sites-content"></div>
      </div>
      
      <!-- Config Search Tab -->
      <div class="tab-pane fade" id="rep-config" role="tabpanel" aria-labelledby="rep-config-tab">
        <div id="rep-config-content"></div>
      </div>
    </div>`;

  // Setup tab event listeners
  const inventoryTab = el.querySelector('#rep-inventory-tab');
  const unreachableTab = el.querySelector('#rep-unreachable-tab');
  const sitesTab = el.querySelector('#rep-sites-tab');
  const configTab = el.querySelector('#rep-config-tab');

  if (inventoryTab) {
    inventoryTab.addEventListener('shown.bs.tab', () => {
      renderInventory(document.getElementById('rep-inventory-content'));
    });
  }

  if (unreachableTab) {
    unreachableTab.addEventListener('shown.bs.tab', () => {
      renderUnreachable(document.getElementById('rep-unreachable-content'));
    });
  }

  if (sitesTab) {
    sitesTab.addEventListener('shown.bs.tab', () => {
      renderSites(document.getElementById('rep-sites-content'));
    });
  }

  if (configTab) {
    configTab.addEventListener('shown.bs.tab', () => {
      renderConfigSearch(document.getElementById('rep-config-content'));
    });
  }

  // Initialize first tab content
  renderInventory(document.getElementById('rep-inventory-content'));

  async function renderInventory(area) {
    area.innerHTML = '<div class="empty-state"><div class="spinner spinner-lg"></div></div>';
    try {
      const d = await API.get('/dnac/devices?limit=2000');
      const cols = [
        { key: 'hostname', label: 'Hostname' },
        { key: 'managementIpAddress', label: 'Mgmt IP', mono: true },
        { key: 'platformId', label: 'Platform' },
        { key: 'softwareVersion', label: 'Version', mono: true },
        { key: 'reachabilityStatus', label: 'Status', render: v => reachBadge(v) },
        { key: 'serialNumber', label: 'Serial', mono: true },
        { key: 'upTime', label: 'Uptime' },
        { key: 'lastContactFormatted', label: 'Last Contact' },
      ];
      area.innerHTML = `
        <div class="section-header mb-3">
          <div class="section-title">Full Inventory — ${d.total.toLocaleString()} devices</div>
          <button class="btn btn-secondary btn-sm" onclick="downloadInventoryCsv()">⬇️ Download CSV</button>
        </div>
        <div class="table-wrap">${makeTable(cols, d.items)}</div>`;
      bindTableSort(area.querySelector('.table-wrap'), cols, d.items, null);
      window._inventoryItems = d.items;
    } catch(e) { area.innerHTML = `<div class="alert alert-danger">${e.message}</div>`; }
  }

  window.downloadInventoryCsv = function() {
    const items = window._inventoryItems || [];
    const header = 'Hostname,ManagementIP,Platform,Version,Reachability,Serial,Uptime,LastContact\n';
    const rows   = items.map(d =>
      [d.hostname, d.managementIpAddress, d.platformId, d.softwareVersion,
       d.reachabilityStatus, d.serialNumber, d.upTime, d.lastContactFormatted]
      .map(v => `"${v||''}"`).join(',')
    ).join('\n');
    dlText(header + rows, `inventory_${new Date().toISOString().slice(0,10)}.csv`);
  };

  async function renderUnreachable(area) {
    area.innerHTML = '<div class="empty-state"><div class="spinner spinner-lg"></div></div>';
    try {
      const d = await API.get('/dnac/devices?reachability=unreachable&limit=2000');
      if (!d.total) { area.innerHTML = '<div class="alert alert-success">✅ All devices are reachable.</div>'; return; }
      const cols = [
        { key: 'hostname', label: 'Hostname' },
        { key: 'managementIpAddress', label: 'Mgmt IP', mono: true },
        { key: 'platformId', label: 'Platform' },
        { key: 'lastContactFormatted', label: 'Last Contact' },
        { key: 'reachabilityFailureReason', label: 'Failure Reason' },
      ];
      area.innerHTML = `
        <div class="alert alert-danger mb-3">🔴 ${d.total} unreachable device(s)</div>
        <div class="table-wrap">${makeTable(cols, d.items)}</div>`;
      bindTableSort(area.querySelector('.table-wrap'), cols, d.items, null);
    } catch(e) { area.innerHTML = `<div class="alert alert-danger">${e.message}</div>`; }
  }

  async function renderSites(area) {
    area.innerHTML = '<div class="empty-state"><div class="spinner spinner-lg"></div></div>';
    try {
      const d = await API.get('/dnac/sites');
      const cols = [
        { key: 'name', label: 'Full Path', render: v => v },
        { key: 'depth', label: 'Depth', render: (_, r) => r.name.split('/').length - 1 },
      ];
      const items = d.items.map(s => ({...s, depth: s.name.split('/').length - 1}));
      area.innerHTML = `
        <div class="section-header">
          <div class="section-title">${d.total.toLocaleString()} sites</div>
        </div>
        <div class="table-wrap">${makeTable(cols, items)}</div>`;
      bindTableSort(area.querySelector('.table-wrap'), cols, items, null);
    } catch(e) { area.innerHTML = `<div class="alert alert-danger">${e.message}</div>`; }
  }

  function renderConfigSearch(area) {
    area.innerHTML = `
      <div class="card mb-4">
        <div class="card-header"><span class="card-title">Configuration String Search</span></div>
        <div class="card-body">
          <div class="alert alert-info mb-4">
            ℹ️ Configs are pulled from DNAC (cached 10 min per device). Results appear as each
            device's config is fetched and searched in parallel.
          </div>

          <!-- Search string -->
          <div class="form-group">
            <label class="form-label">Search string <span style="color:var(--danger)">*</span></label>
            <input class="form-control form-control-sm" id="cs-query" placeholder="e.g.  summary-address  /  crypto map  /  ip route 0.0.0.0  /  aaa server">
          </div>

          <!-- Device filters -->
          <div class="row g-3 mb-3">
            <div class="col-lg-4">
              <div class="form-group m-0">
                <label class="form-label">Hostname contains</label>
                <input class="form-control form-control-sm" id="cs-hostname" placeholder="e.g.  ATL  or  router">
              </div>
            </div>
            <div class="col-lg-4">
              <div class="form-group m-0">
                <label class="form-label">Management IP contains</label>
                <input class="form-control form-control-sm" id="cs-ip" placeholder="e.g.  10.16">
              </div>
            </div>
            <div class="col-lg-4">
              <div class="form-group m-0">
                <label class="form-label">Platform contains</label>
                <input class="form-control form-control-sm" id="cs-platform" placeholder="e.g.  C9300  or  ISR">
              </div>
            </div>
            <div class="col-lg-4">
              <div class="form-group m-0">
                <label class="form-label">Role contains</label>
                <input class="form-control form-control-sm" id="cs-role" placeholder="e.g.  ACCESS  or  DISTRIBUTION">
              </div>
            </div>
            <div class="col-lg-4">
              <div class="form-group m-0">
                <label class="form-label">Device family contains</label>
                <input class="form-control form-control-sm" id="cs-family" placeholder="e.g.  Switches  or  Routers">
              </div>
            </div>
            <div class="col-lg-4">
              <div class="form-group m-0">
                <label class="form-label">Reachability</label>
                <select class="form-select form-select-sm" id="cs-reach">
                  <option value="Reachable">Reachable only (recommended)</option>
                  <option value="unreachable">Unreachable only</option>
                  <option value="">All devices</option>
                </select>
              </div>
            </div>
          </div>

          <div class="d-flex align-items-flex-end gap-3">
            <div class="form-group m-0">
              <label class="form-label">Max devices to search</label>
              <input class="form-control form-control-sm" type="number" id="cs-max" value="500" min="1" max="2700" style="width:100px">
            </div>
            <div class="d-flex gap-2">
              <button class="btn btn-primary btn-sm" id="cs-run">🔍 Search Configs</button>
              <button class="btn btn-outline-secondary btn-sm" id="cs-clear">Clear</button>
            </div>
            <span id="cs-status" style="font-size:12px;color:var(--text-secondary);margin-top:20px"></span>
          </div>
        </div>
      </div>

      <div id="cs-results"></div>`;

    document.getElementById('cs-clear').addEventListener('click', () => {
      ['cs-query','cs-hostname','cs-ip','cs-platform','cs-role','cs-family'].forEach(id => {
        document.getElementById(id).value = '';
      });
      document.getElementById('cs-reach').value = 'Reachable';
      document.getElementById('cs-max').value = '500';
      document.getElementById('cs-results').innerHTML = '';
      document.getElementById('cs-status').textContent = '';
    });

    document.getElementById('cs-query').addEventListener('keydown', e => {
      if (e.key === 'Enter') document.getElementById('cs-run').click();
    });

    document.getElementById('cs-run').addEventListener('click', async () => {
      const query = document.getElementById('cs-query').value.trim();
      if (!query || query.length < 2) {
        toast('Enter at least 2 characters to search', 'warn'); return;
      }

      const runBtn  = document.getElementById('cs-run');
      const statusEl = document.getElementById('cs-status');
      const resEl   = document.getElementById('cs-results');
      runBtn.disabled = true;
      statusEl.textContent = 'Searching…';
      resEl.innerHTML = `
        <div class="card">
          <div class="card-body" style="text-align:center;padding:32px">
            <div class="spinner spinner-lg mx-auto mb-3"></div>
            <div style="color:var(--text-secondary);font-size:13px">
              Fetching and searching device configs from DNAC.<br>
              Configs are cached — subsequent searches on the same devices are instant.
            </div>
          </div>
        </div>`;

      const body = {
        search_string:  query,
        hostname:       document.getElementById('cs-hostname').value.trim() || null,
        ip:             document.getElementById('cs-ip').value.trim()       || null,
        platform:       document.getElementById('cs-platform').value.trim() || null,
        role:           document.getElementById('cs-role').value.trim()     || null,
        device_family:  document.getElementById('cs-family').value.trim()   || null,
        reachability:   document.getElementById('cs-reach').value,
        max_devices:    parseInt(document.getElementById('cs-max').value) || 500,
      };

      try {
        const data = await API.post('/dnac/config-search', body);
        runBtn.disabled = false;
        statusEl.textContent = `${data.total_matches} device(s) matched in ${data.devices_matched_filter} searched`;
        renderConfigResults(resEl, data, query);
      } catch (e) {
        runBtn.disabled = false;
        statusEl.textContent = '';
        resEl.innerHTML = `<div class="alert alert-danger">❌ ${e.message}</div>`;
      }
    });

    function renderConfigResults(resEl, data, query) {
      if (!data.total_matches) {
        resEl.innerHTML = `
          <div class="card">
            <div class="card-body">
              <div class="empty-state">
                <div class="empty-state-icon">🔍</div>
                <div class="empty-state-title">No matches found</div>
                <div class="empty-state-desc">
                  "${escHtml(query)}" was not found in any config across
                  ${data.devices_matched_filter.toLocaleString()} device(s).
                </div>
              </div>
            </div>
          </div>`;
        return;
      }

      // Summary metrics
      const kpis = `
        <div class="kpi-row cols-4 mb-4">
          <div class="kpi-card">
            <div class="kpi-label">Devices filtered</div>
            <div class="kpi-value">${data.devices_matched_filter.toLocaleString()}</div>
          </div>
          <div class="kpi-card success">
            <div class="kpi-label">Devices with match</div>
            <div class="kpi-value">${data.total_matches.toLocaleString()}</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Total matching lines</div>
            <div class="kpi-value">${data.total_matching_lines.toLocaleString()}</div>
          </div>
          <div class="kpi-card teal">
            <div class="kpi-label">Search string</div>
            <div class="kpi-value" style="font-size:14px;padding-top:4px"><code>${escHtml(query)}</code></div>
          </div>
        </div>`;

      // Summary table — clickable rows expand to show matching lines
      const summaryRows = data.results.map((r, i) => `
        <tr data-idx="${i}" onclick="toggleCsDetail(${i})" style="cursor: pointer;">
          <td>${r.hostname}</td>
          <td class="font-monospace" style="font-size:12px">${r.ip || '—'}</td>
          <td>${r.platform || '—'}</td>
          <td>${r.role || '—'}</td>
          <td><strong>${r.match_count}</strong></td>
          <td style="text-align:right"><span class="badge text-bg-secondary">▼</span></td>
        </tr>
        <tr id="cs-detail-${i}" style="display:none">
          <td colspan="6" style="padding:0;background:var(--bg)">
            <div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center">
              <input class="form-control form-control-sm" id="cs-line-filter-${i}" placeholder="Filter these lines…" style="max-width:260px"
                oninput="filterCsLines(${i})">
              <button class="btn btn-outline-secondary btn-sm" onclick="downloadCsDevice(${i})">⬇️ Download</button>
              <span style="font-size:11px;color:var(--text-secondary)">${r.match_count} line(s) match</span>
            </div>
            <pre class="code-block" id="cs-pre-${i}" style="border-radius:0;margin:0;max-height:360px">${
              r.lines.map(l => `<span style="color:var(--text-light);user-select:none;margin-right:10px">${String(l.line_num).padStart(4)}</span>${highlightMatch(escHtml(l.text), escHtml(query))}`).join('\n')
            }</pre>
          </td>
        </tr>`
      ).join('');

      resEl.innerHTML = `
        ${kpis}
        <div class="table-wrap">
          <div class="table-toolbar d-flex justify-content-between align-items-center">
            <span class="table-count">${data.total_matches} device(s) with matches — click a row to expand</span>
            <button class="btn btn-outline-secondary btn-sm" onclick="downloadCsAll()">⬇️ Download CSV</button>
          </div>
          <table class="table table-sm table-striped table-hover table-dark">
            <thead><tr>
              <th>Hostname</th><th>IP</th><th>Platform</th><th>Role</th>
              <th>Match Count</th><th></th>
            </tr></thead>
            <tbody id="cs-tbody">${summaryRows}</tbody>
          </table>
        </div>`;

      // Store for download
      window._csData = data;
      window._csQuery = query;
    }

    window.toggleCsDetail = function(idx) {
      const row = document.getElementById(`cs-detail-${idx}`);
      if (!row) return;
      const open = row.style.display !== 'none';
      row.style.display = open ? 'none' : '';
      // Update arrow indicator on the parent row
      const parentRow = document.querySelector(`#cs-tbody tr[data-idx="${idx}"]`);
      const badge = parentRow?.querySelector('.badge');
      if (badge) badge.textContent = open ? '▼' : '▲';
      if (!open) row.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    };

    window.filterCsLines = function(idx) {
      const q   = document.getElementById(`cs-line-filter-${idx}`)?.value.toLowerCase() || '';
      const pre = document.getElementById(`cs-pre-${idx}`);
      const data = window._csData;
      if (!pre || !data) return;
      const r   = data.results[idx];
      const lines = q
        ? r.lines.filter(l => l.text.toLowerCase().includes(q))
        : r.lines;
      pre.innerHTML = lines.map(l =>
        `<span style="color:var(--text-light);user-select:none;margin-right:10px">${String(l.line_num).padStart(4)}</span>${highlightMatch(escHtml(l.text), escHtml(window._csQuery))}`
      ).join('\n');
    };

    window.downloadCsDevice = function(idx) {
      const data = window._csData;
      if (!data) return;
      const r    = data.results[idx];
      const text = `Device: ${r.hostname} (${r.ip})\nSearch: "${data.search_string}"\n${'='.repeat(60)}\n` +
        r.lines.map(l => `${String(l.line_num).padStart(5)}: ${l.text}`).join('\n');
      dlText(text, `${r.hostname}_matches.txt`);
    };

    window.downloadCsAll = function() {
      const data = window._csData;
      if (!data) return;
      const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
      const header = 'Hostname,IP,Platform,Role,Line Number,Match Text\n';
      const rows = data.results.flatMap(r =>
        r.lines.map(l => [r.hostname, r.ip, r.platform, r.role, l.line_num, l.text].map(esc).join(','))
      ).join('\n');
      dlText(header + rows, `config_search_${new Date().toISOString().slice(0,10)}.csv`);
    };

    function highlightMatch(html, query) {
      // Case-insensitive highlight — wrap matches in a span
      const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
      return html.replace(regex, `<mark style="background:#fbbf24;color:#1c1917;border-radius:2px;padding:0 1px">$1</mark>`);
    }
  }
});

/* ── Utilities ──────────────────────────────────────────────── */
function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function dlText(text, filename) {
  const a   = document.createElement('a');
  a.href    = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ── Login ──────────────────────────────────────────────────── */
function renderLogin(errorMsg) {
  // Hide the sidebar, expand main to full width
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

    console.log('[LOGIN] Form submitted for user:', username);
    window._bootstrapping = true;  // Prevent 401 handlers from clearing form
    btn.disabled   = true;
    btn.textContent = 'Signing in…';

    try {
      console.log('[LOGIN] Sending authentication request');
      const r = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        console.log('[LOGIN] Authentication failed:', data.detail || 'Check credentials');
        window._bootstrapping = false;
        renderLogin(data.detail || 'Login failed — check your credentials');
        return;
      }
      console.log('[LOGIN] Authentication successful, saving token and calling bootApp()');
      Auth.save(data.token, data.username);
      bootApp();
    } catch (e) {
      console.error('[LOGIN] Network error:', e);
      window._bootstrapping = false;
      renderLogin('Network error — please try again');
    }
  });
}

let _bootAppCalled = false;

function bootApp() {
  if (_bootAppCalled) {
    console.log('[BOOT] bootApp() already called, skipping duplicate');
    return;
  }
  _bootAppCalled = true;
  console.log('[BOOT] bootApp() called, rendering warmup...');
  
  try {
    document.getElementById('sidebar').style.display = '';
    initSidebarState();  // Restore sidebar state
    const main = document.getElementById('main');
    main.style.gridColumn = '';
    main.innerHTML = `
      <header id="topbar">
        <span id="page-title">Loading…</span>
        <div id="topbar-actions">
          <span style="font-size:13px;color:var(--text-light);margin-right:12px">👤 ${Auth.username()}</span>
          <button class="btn btn-ghost btn-sm" onclick="logout()">Sign Out</button>
        </div>
      </header>
      <div id="content"></div>`;

    console.log('[BOOT] About to call renderWarmup()');
    renderWarmup();
  } catch (err) {
    console.error('[BOOT] Error in bootApp():', err);
    _bootAppCalled = false;
  }
}

function renderWarmup() {
  console.log('[WARMUP] Starting cache warmup process...');
  
  try {
    // Validate API.stream exists
    if (!API || typeof API.stream !== 'function') {
      console.error('[WARMUP] API.stream not available!', { API: !!API, stream: typeof API?.stream });
      document.getElementById('content').innerHTML = `<div style="padding:40px;color:red;font-family:monospace">ERROR: API.stream not available</div>`;
      setTimeout(initApp, 100);
      return;
    }

    const STEPS = [
      { id: 'devices',  label: 'Catalyst Center',    sub: 'Device inventory' },
      { id: 'sites',    label: 'Catalyst Center',    sub: 'Site hierarchy' },
      { id: 'sitemap',  label: 'Catalyst Center',    sub: 'Device → site map' },
      { id: 'ise',      label: 'Cisco ISE',           sub: 'Policy & endpoint data' },
      { id: 'panorama', label: 'Palo Alto Panorama',  sub: 'Firewall policies' },
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
          <div id="warm-debug" style="margin-top:20px;padding:12px;border-radius:6px;background:#f5f5f5;border:1px solid #ddd;font-family:monospace;font-size:11px;color:#666;max-height:100px;overflow-y:auto;display:none"></div>
          <div id="warm-ready" style="display:none;text-align:center;margin-top:24px;font-size:14px;font-weight:600;color:var(--success)">
            ✅ All systems ready — launching dashboard…
          </div>
        </div>
      </div>`;

    const debugEl = document.getElementById('warm-debug');
    const addDebugLine = (text) => {
      debugEl.style.display = '';
      debugEl.innerHTML += text + '<br>';
      debugEl.scrollTop = debugEl.scrollHeight;
    };

    addDebugLine('[' + new Date().toLocaleTimeString() + '] Starting API.stream() call...');
    addDebugLine('Auth headers: ' + JSON.stringify(Auth.headers()));

    let launched = false;
    let streamComplete = false;
    let eventCount = 0;
    let streamStarted = false;

    const streamTimeout = setTimeout(() => {
      if (!streamStarted) {
        addDebugLine('[TIMEOUT] Stream did not start within 5 seconds');
        if (!launched) {
          launched = true;
          setTimeout(initApp, 500);
        }
      }
    }, 5000);

    API.stream('/warm', {}, ev => {
      streamStarted = true;
      eventCount++;
      console.log(`[WARMUP] Event ${eventCount}:`, ev);
      addDebugLine(`Event ${eventCount}: ${JSON.stringify(ev).substring(0, 100)}`);
      
      // Handle error events from the stream
      if (ev.type === 'error') {
        console.error('[WARMUP] Stream error:', ev.message);
        addDebugLine('ERROR: ' + (ev.message || 'Unknown error'));
        return;
      }

      if (ev.step === 'done') {
        console.log('[WARMUP] Cache warmup complete!');
        clearTimeout(streamTimeout);
        streamComplete = true;
        if (launched) return;
        launched = true;
        const el = document.getElementById('warm-ready');
        if (el) el.style.display = '';
        setTimeout(initApp, 1500);
        return;
      }

      const icon = { loading: '⏳', done: '✅', cached: '✅', error: '❌' }[ev.status] || '⏳';
      const bg   = { done: '#f0fdf4', cached: '#f0fdf4', error: '#fff1f2' }[ev.status];
      const rowEl = document.getElementById(`ws-${ev.step}`);
      const icEl  = document.getElementById(`wi-${ev.step}`);
      const msgEl = document.getElementById(`wm-${ev.step}`);
      if (rowEl && bg) rowEl.style.background = bg;
      if (icEl)  icEl.textContent  = icon;
      if (msgEl) msgEl.textContent = ev.message;
    }, () => {
      console.log('[WARMUP] Stream ended. streamComplete:', streamComplete, 'eventCount:', eventCount);
      clearTimeout(streamTimeout);
      addDebugLine(`[${new Date().toLocaleTimeString()}] Stream ended (${eventCount} events, complete: ${streamComplete})`);
      if (!launched) {
        launched = true;
        setTimeout(initApp, 500);
      }
    });
  } catch (err) {
    console.error('[WARMUP] Error in renderWarmup():', err, err.stack);
    document.getElementById('content').innerHTML = `<div style="padding:40px;color:red;font-family:monospace">ERROR: ${err.message}</div>`;
    setTimeout(initApp, 100);
  }
}

function initApp() {
  console.log('[INIT] initApp() called, about to call startApp()');
  try {
    startApp();
  } catch (err) {
    console.error('[INIT] Error in startApp():', err);
  }
}

function startApp() {
  console.log('[BOOT] Starting app initialization...');
  window._bootstrapping = false;  // Allow 401 handlers to work again now that app is loaded
  
  try {
    // Add Refresh Cache button now that we're in the app
    const actions = document.getElementById('topbar-actions');
    if (actions && !actions.querySelector('[data-refresh]')) {
      const btn = document.createElement('button');
      btn.className = 'btn btn-ghost btn-sm';
      btn.dataset.refresh = '1';
      btn.style.marginRight = '8px';
      btn.textContent = '🔄 Refresh Cache';
      btn.onclick = refreshCache;
      actions.prepend(btn);
    }
    
    console.log('[BOOT] Initializing router...');
    Router.init();
    console.log('[BOOT] Loading system status...');
    loadStatus();
    setInterval(loadStatus, 60_000);
    console.log('[BOOT] App fully initialized');
  } catch (err) {
    console.error('[BOOT] Error in startApp():', err, err.stack);
  }
}

async function logout() {
  try { await API.post('/auth/logout', {}); } catch {}
  Auth.clear();
  renderLogin();
}

/* ── Bootstrap ──────────────────────────────────────────────── */
(async () => {
  const token = Auth.token();
  console.log('[BOOTSTRAP] Page load, checking for existing token:', !!token);
  
  if (token) {
    // Validate the stored token
    try {
      const r = await fetch('/api/auth/me', { headers: { 'Authorization': `Bearer ${token}` } });
      if (r.ok) {
        const { username } = await r.json();
        console.log('[BOOTSTRAP] Token valid, username:', username);
        Auth.save(token, username);   // refresh stored username
        bootApp();
        return;
      }
      console.log('[BOOTSTRAP] Token invalid, status:', r.status);
    } catch (err) {
      console.error('[BOOTSTRAP] Error validating token:', err);
    }
    Auth.clear();
  }
  console.log('[BOOTSTRAP] Rendering login form');
  renderLogin();
})();
