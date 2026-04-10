/* ============================================================
   IMPACT II — Router + sidebar (ES module)
   ============================================================ */

import { API } from './api.js';

export const Router = {
  current: null,
  routes:  {},

  register(name, mountFn) { this.routes[name] = mountFn; },
  go(page)      { window.location.hash = `/${page}`; },
  navigate(page){ this.go(page); },

  init() {
    const handle = () => {
      const hash = window.location.hash.slice(2) || 'dashboard';
      this.render(hash);
    };
    window.addEventListener('hashchange', handle);
    handle();
  },

  render(page) {
    const fn = this.routes[page];
    if (!fn) { this.render('dashboard'); return; }

    document.querySelectorAll('.nav-item').forEach(el =>
      el.classList.toggle('active', el.dataset.page === page)
    );

    const titles = {
      dashboard:        'Dashboard',
      devices:          'Device Inventory',
      'ip-lookup':      'IP Lookup',
      ise:              'Cisco ISE',
      firewall:         'Firewall Policies',
      'command-runner': 'Command Runner',
      import:           'Device Management',
      reports:          'Reports',
    };
    const titleEl = document.getElementById('page-title');
    if (titleEl) titleEl.textContent = titles[page] || page;

    const content = document.getElementById('content');
    content.innerHTML = '';
    this.current = page;
    fn(content);
  },
};

export function toggleSidebar() {
  const sidebar   = document.getElementById('sidebar');
  const main      = document.getElementById('main');
  const collapsed = sidebar.classList.toggle('collapsed');
  main.classList.toggle('sidebar-collapsed', collapsed);
  localStorage.setItem('sidebarCollapsed', collapsed ? '1' : '0');
}

export function initSidebarState() {
  if (localStorage.getItem('sidebarCollapsed') === '1') {
    document.getElementById('sidebar')?.classList.add('collapsed');
    document.getElementById('main')?.classList.add('sidebar-collapsed');
  }
}

export async function loadStatus() {
  try {
    const s = await API.get('/status');
    const upd = (dotId, txtId, r) => {
      const dot = document.getElementById(dotId);
      const txt = document.getElementById(txtId);
      if (dot) dot.className = `status-dot ${r?.ok ? 'ok' : 'error'}`;
      if (txt) txt.textContent = r?.detail || (r?.ok ? 'Connected' : 'Error');
    };
    upd('st-dnac', 'st-dnac-txt', s.dnac);
    upd('st-ise',  'st-ise-txt',  s.ise);
    upd('st-pan',  'st-pan-txt',  s.panorama);
  } catch {}
}

export async function refreshCache() {
  const page = Router.current;
  const map  = {
    devices:   ['/dnac/cache/refresh'],
    ise:       ['/ise/cache/refresh'],
    firewall:  ['/firewall/cache/refresh'],
    reports:   ['/dnac/cache/refresh'],
  };
  const urls = map[page] || ['/dnac/cache/refresh', '/ise/cache/refresh', '/firewall/cache/refresh'];
  await Promise.allSettled(urls.map(u => API.post(u, {})));
  if (page) Router.render(page);
}
