import { createApp }   from '/static/petite-vue.esm.js';
import { API }          from '/static/js/api.js';
import { toast, initCacheBar, fmtList } from '/static/js/utils.js';
import { Router }       from '/static/js/router.js';

/* ── NADs sub-template ──────────────────────────────────────── */
const nadsTemplate = `
<div>
  <div v-if="!loaded" class="detail-placeholder">
    <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" d="M8.25 6.75h7.5M8.25 12h7.5m-7.5 5.25h4.5"/>
    </svg>
    Select a row to view details
  </div>
  <div v-else-if="selected" class="detail-panel">
    <div class="detail-header"><span class="detail-hostname">🖥️ {{ detail?.name || selected.name }}</span></div>
    <div v-if="detailLoading" class="empty-state p-4"><div class="spinner"></div></div>
    <div v-else-if="detail" class="detail-body">
      <div class="detail-grid">
        <div class="detail-section">
          <div class="detail-section-title">Identity</div>
          <div class="kv-row"><span class="kv-label">IP / Mask</span><span class="kv-value">{{ nadIps }}</span></div>
          <div class="kv-row"><span class="kv-label">Profile</span><span class="kv-value">{{ detail.profileName || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Model</span><span class="kv-value">{{ detail.modelName || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Groups</span><span class="kv-value">{{ nadGroups }}</span></div>
          <div class="kv-row"><span class="kv-label">CoA Port</span><span class="kv-value">{{ detail.coaPort || '—' }}</span></div>
        </div>
        <div class="detail-section">
          <div class="detail-section-title">RADIUS</div>
          <div class="kv-row"><span class="kv-label">Protocol</span><span class="kv-value">{{ detail.authenticationSettings?.networkProtocol || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Secret</span><span class="kv-value">{{ detail.authenticationSettings?.radiusSharedSecret ? '*** (set)' : 'Not set' }}</span></div>
          <div class="detail-section-title mt-3">TACACS</div>
          <div class="kv-row"><span class="kv-label">Secret</span><span class="kv-value">{{ detail.tacacsSettings?.sharedSecret ? '*** (set)' : 'Not set' }}</span></div>
          <div class="kv-row"><span class="kv-label">Connect Mode</span><span class="kv-value">{{ detail.tacacsSettings?.connectModeOptions || '—' }}</span></div>
          <div class="detail-section-title mt-3">SNMP</div>
          <div class="kv-row"><span class="kv-label">Version</span><span class="kv-value">{{ detail.snmpsettings?.version || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Poll Interval</span><span class="kv-value">{{ detail.snmpsettings?.pollingInterval ? detail.snmpsettings.pollingInterval + 's' : '—' }}</span></div>
        </div>
      </div>
    </div>
  </div>

  <div class="table-wrap">
    <div class="table-toolbar">
      <div class="search-input">
        <input class="input form-control form-control-sm" v-model="query" placeholder="Search by name or IP…"
               style="width:220px" @keydown.enter="search()">
      </div>
      <button class="btn btn-primary btn-sm" @click="search()" :disabled="loading">Search</button>
      <span class="table-count">{{ items.length ? items.length + ' device(s)' : '' }}</span>
    </div>
    <div v-if="loading" class="empty-state"><div class="spinner"></div></div>
    <div v-else-if="error" class="alert alert-danger">{{ error }}</div>
    <table v-else-if="items.length" class="table table-striped table-hover table-sm">
      <thead class="table-dark"><tr>
        <th @click="sort('name')" :class="{sorted: sortCol==='name'}">Name <span class="sort-arrow">↕</span></th>
        <th @click="sort('description')" :class="{sorted: sortCol==='description'}">Description <span class="sort-arrow">↕</span></th>
      </tr></thead>
      <tbody>
        <tr v-for="item in sortedItems" :key="item.id"
            :class="{selected: selected?.id === item.id}"
            @click="selectNad(item)">
          <td>{{ item.name }}</td>
          <td>{{ item.description || '—' }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>`;

/* ── Endpoints sub-template ─────────────────────────────────── */
const epTemplate = `
<div>
  <div v-if="!selected" class="detail-placeholder">
    <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" d="M8.25 6.75h7.5M8.25 12h7.5m-7.5 5.25h4.5"/>
    </svg>
    Select a row to view details
  </div>
  <div v-else class="detail-panel">
    <div class="detail-header"><span class="detail-hostname">💻 {{ detail?.mac || selected.name }}</span></div>
    <div v-if="detailLoading" class="empty-state p-4"><div class="spinner"></div></div>
    <div v-else-if="detail" class="detail-body">
      <div class="detail-grid">
        <div class="detail-section">
          <div class="detail-section-title">Endpoint</div>
          <div class="kv-row"><span class="kv-label">Portal User</span><span class="kv-value">{{ detail.portalUser || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Identity Store</span><span class="kv-value">{{ detail.identityStore || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Profile ID</span><span class="kv-value">{{ detail.profileId || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Group ID</span><span class="kv-value">{{ detail.groupId || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Static Profile</span><span class="kv-value">{{ detail.staticProfileAssignment }}</span></div>
          <div class="kv-row"><span class="kv-label">Static Group</span><span class="kv-value">{{ detail.staticGroupAssignment }}</span></div>
        </div>
        <div class="detail-section">
          <div class="detail-section-title">MFC Profiler</div>
          <div class="kv-row"><span class="kv-label">Endpoint Type</span><span class="kv-value">{{ mfcVal('mfcDeviceType') }}</span></div>
          <div class="kv-row"><span class="kv-label">Manufacturer</span><span class="kv-value">{{ mfcVal('mfcHardwareManufacturer') }}</span></div>
          <div class="kv-row"><span class="kv-label">Model</span><span class="kv-value">{{ mfcVal('mfcHardwareModel') }}</span></div>
          <div class="kv-row"><span class="kv-label">OS</span><span class="kv-value">{{ mfcVal('mfcOperatingSystem') }}</span></div>
        </div>
      </div>
    </div>
  </div>

  <div class="table-wrap">
    <div class="table-toolbar">
      <div class="search-input">
        <input class="input" v-model="query" placeholder="MAC address (partial OK)…"
               style="width:240px" @keydown.enter="search()">
      </div>
      <button class="btn btn-primary" @click="search()" :disabled="loading">Search</button>
      <span class="table-count">{{ items.length ? items.length + ' endpoint(s)' : '' }}</span>
    </div>
    <div v-if="loading" class="empty-state"><div class="spinner"></div></div>
    <div v-else-if="error" class="alert alert-danger">{{ error }}</div>
    <table v-else-if="items.length" class="table table-striped table-hover table-sm">
      <thead class="table-dark"><tr>
        <th>MAC Address</th><th>Description</th>
      </tr></thead>
      <tbody>
        <tr v-for="item in items" :key="item.id"
            :class="{selected: selected?.id === item.id}"
            @click="selectEp(item)">
          <td class="mono">{{ item.name }}</td>
          <td>{{ item.description || '—' }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>`;

/* ── Simple table sub-template factory ──────────────────────── */
function simpleTableTemplate(cols) {
  const ths = cols.map(c => `<th @click="sort('${c.key}')" :class="{sorted: sortCol==='${c.key}'}">${c.label} <span class="sort-arrow">↕</span></th>`).join('');
  const tds = cols.map(c => `<td class="${c.mono ? 'mono' : ''}">{{ item.${c.key} ${c.falsy ? "|| '—'" : ''} }}</td>`).join('');
  return `
<div>
  <div v-if="loading" class="empty-state"><div class="spinner spinner-lg"></div></div>
  <div v-else-if="error" class="alert alert-danger">{{ error }}</div>
  <div v-else class="table-wrap">
    <table class="table table-striped table-hover table-sm">
      <thead class="table-dark"><tr>${ths}</tr></thead>
      <tbody>
        <tr v-for="item in sortedItems" :key="item.id || item.name">
          ${tds}
        </tr>
      </tbody>
    </table>
  </div>
</div>`;
}

/* ── Page shell ─────────────────────────────────────────────── */
const shellTemplate = `
<div>
  <div class="d-flex gap-3 align-items-center mb-0">
    <ul class="nav nav-tabs flex-grow-1" id="ise-tabs" role="tablist" style="margin-bottom:0">
      <li class="nav-item" role="presentation">
        <button class="nav-link active" id="ise-nads-tab"      data-bs-toggle="tab" data-bs-target="#ise-nads"      type="button">NADs</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link"        id="ise-endpoints-tab" data-bs-toggle="tab" data-bs-target="#ise-endpoints" type="button">Endpoints</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link"        id="ise-trustsec-tab"  data-bs-toggle="tab" data-bs-target="#ise-trustsec"  type="button">TrustSec</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link"        id="ise-identity-tab"  data-bs-toggle="tab" data-bs-target="#ise-identity"  type="button">Identity</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link"        id="ise-policy-tab"    data-bs-toggle="tab" data-bs-target="#ise-policy"    type="button">Policy</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link"        id="ise-admin-tab"     data-bs-toggle="tab" data-bs-target="#ise-admin"     type="button">Admin</button>
      </li>
    </ul>
    <div class="cache-bar" id="ise-cache-bar"></div>
  </div>
  <div class="tab-content" id="ise-content" style="padding-top:16px">
    <div class="tab-pane fade show active" id="ise-nads"></div>
    <div class="tab-pane fade"             id="ise-endpoints"></div>
    <div class="tab-pane fade"             id="ise-trustsec"></div>
    <div class="tab-pane fade"             id="ise-identity"></div>
    <div class="tab-pane fade"             id="ise-policy"></div>
    <div class="tab-pane fade"             id="ise-admin"></div>
  </div>
</div>`;

/* ── Helper: mount a sub-tab Petite Vue app ──────────────────── */
function mountSubApp(paneId, template, component) {
  const pane = document.getElementById(paneId);
  if (!pane || pane._mounted) return;
  pane._mounted = true;
  pane.innerHTML = template;
  createApp(component).mount(pane.firstElementChild);
  if (component.init) component.init();
  else if (component.load) component.load();
}

/* ── NADs component ──────────────────────────────────────────── */
function NadsComponent(alive) {
  return {
    loaded: false, loading: false, error: null,
    query: '', items: [], sortCol: null, sortDir: 1,
    selected: null, detail: null, detailLoading: false,

    get sortedItems() {
      if (!this.sortCol) return this.items;
      const c = this.sortCol, d = this.sortDir;
      return [...this.items].sort((a, b) =>
        String(a[c] ?? '').localeCompare(String(b[c] ?? ''), undefined, { numeric: true }) * d
      );
    },
    get nadIps() {
      return (this.detail?.NetworkDeviceIPList || []).map(e => `${e.ipaddress}/${e.mask}`).join(', ') || '—';
    },
    get nadGroups() {
      return (this.detail?.NetworkDeviceGroupList || []).join(', ') || '—';
    },

    async init() { await this.search(); },
    async search() {
      this.loading = true; this.error = null;
      try {
        const d = await API.get(`/ise/nads?search=${encodeURIComponent(this.query)}`);
        if (!alive()) return;
        this.items = d.items;
      } catch(e) {
        if (!alive()) return;
        this.error = e.message;
      } finally { if (alive()) this.loading = false; }
    },
    sort(col) {
      if (this.sortCol === col) this.sortDir *= -1;
      else { this.sortCol = col; this.sortDir = 1; }
    },
    async selectNad(nad) {
      this.selected = nad; this.loaded = true;
      this.detail = null; this.detailLoading = true;
      try {
        const d = await API.get(`/ise/nads/${nad.id}`);
        if (!alive()) return;
        this.detail = d;
      } catch(e) { if (alive()) this.detail = null; }
      finally { if (alive()) this.detailLoading = false; }
    },
  };
}

/* ── Endpoints component ─────────────────────────────────────── */
function EndpointsComponent(alive) {
  return {
    loading: false, error: null,
    query: '', items: [],
    selected: null, detail: null, detailLoading: false,

    mfcVal(k) {
      const v = this.detail?.mfcAttributes?.[k];
      return Array.isArray(v) && v.length ? v[0] : '—';
    },
    async search() {
      const q = this.query.trim();
      if (!q || q.length < 2) { toast('Enter at least 2 characters', 'warn'); return; }
      this.loading = true; this.error = null;
      try {
        const d = await API.get(`/ise/endpoints?mac=${encodeURIComponent(q)}`);
        if (!alive()) return;
        this.items = d.items;
        if (d.items.length === 1) this.selectEp(d.items[0]);
      } catch(e) {
        if (!alive()) return;
        this.error = e.message;
      } finally { if (alive()) this.loading = false; }
    },
    async selectEp(ep) {
      this.selected = ep; this.detail = null; this.detailLoading = true;
      try {
        const d = await API.get(`/ise/endpoints/${ep.id}`);
        if (!alive()) return;
        this.detail = d;
      } catch {}
      finally { if (alive()) this.detailLoading = false; }
    },
  };
}

/* ── Simple table component factory ─────────────────────────── */
function SimpleTableComponent(apiUrl, alive) {
  return {
    loading: true, error: null, items: [],
    sortCol: null, sortDir: 1,
    get sortedItems() {
      if (!this.sortCol) return this.items;
      const c = this.sortCol, d = this.sortDir;
      return [...this.items].sort((a, b) =>
        String(a[c] ?? '').localeCompare(String(b[c] ?? ''), undefined, { numeric: true }) * d
      );
    },
    sort(col) {
      if (this.sortCol === col) this.sortDir *= -1;
      else { this.sortCol = col; this.sortDir = 1; }
    },
    async load() {
      try {
        const d = await API.get(apiUrl);
        if (!alive()) return;
        this.items = d.items;
      } catch(e) {
        if (!alive()) return;
        this.error = e.message;
      } finally { if (alive()) this.loading = false; }
    },
  };
}

/* ── TrustSec template ──────────────────────────────────────── */
const trustsecTemplate = `
<div>
  <ul class="nav nav-tabs mb-3" id="ts-tabs" role="tablist">
    <li class="nav-item" role="presentation">
      <button class="nav-link active" id="ts-sgts-tab"  data-bs-toggle="tab" data-bs-target="#ts-sgts"  type="button">SGTs</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link"        id="ts-sgacls-tab" data-bs-toggle="tab" data-bs-target="#ts-sgacls" type="button">SGACLs</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link"        id="ts-egress-tab" data-bs-toggle="tab" data-bs-target="#ts-egress" type="button">Egress Matrix</button>
    </li>
  </ul>
  <div class="tab-content">
    <div class="tab-pane fade show active" id="ts-sgts"></div>
    <div class="tab-pane fade"             id="ts-sgacls"></div>
    <div class="tab-pane fade"             id="ts-egress"></div>
  </div>
</div>`;

function TrustSecComponent(alive) {
  return {
    async init() {
      mountSubApp('ts-sgts', simpleTableTemplate([
        { key: 'name',            label: 'Name',        falsy: true },
        { key: 'value',           label: 'Tag Value',   falsy: true },
        { key: 'propagateToApic', label: 'To APIC',     falsy: true },
        { key: 'description',     label: 'Description', falsy: true },
      ]), SimpleTableComponent('/ise/sgts', alive));

      document.getElementById('ts-sgacls-tab')?.addEventListener('shown.bs.tab', () => {
        mountSubApp('ts-sgacls', simpleTableTemplate([
          { key: 'name',        label: 'Name',        falsy: true },
          { key: 'ipVersion',   label: 'IP Version',  falsy: true },
          { key: 'description', label: 'Description', falsy: true },
        ]), SimpleTableComponent('/ise/sgacls', alive));
      });

      document.getElementById('ts-egress-tab')?.addEventListener('shown.bs.tab', () => {
        mountSubApp('ts-egress', simpleTableTemplate([
          { key: 'sourceSgtId',      label: 'Src SGT',     falsy: true },
          { key: 'destinationSgtId', label: 'Dst SGT',     falsy: true },
          { key: 'matrixCellStatus', label: 'Status',      falsy: true },
          { key: 'defaultRule',      label: 'Default Rule',falsy: true },
        ]), SimpleTableComponent('/ise/egress-matrix', alive));
      });
    },
  };
}

/* ── Policy component ────────────────────────────────────────── */
const policyTemplate = `
<div>
  <div v-if="loading" class="empty-state"><div class="spinner spinner-lg"></div></div>
  <div v-else-if="error" class="alert alert-info">{{ error }}</div>
  <template v-else>
    <div class="table-wrap">
      <table class="table table-striped table-hover table-sm">
        <thead class="table-dark"><tr><th>Policy Set</th><th>Description</th></tr></thead>
        <tbody>
          <tr v-for="ps in items" :key="ps.id"
              :class="{selected: selected?.id === ps.id}"
              @click="loadDetail(ps)">
            <td>{{ ps.name }}</td><td>{{ ps.description || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="selected" class="mt-4">
      <div v-if="rulesLoading" class="empty-state"><div class="spinner"></div></div>
      <div v-else-if="rules" class="card">
        <div class="card-header"><span class="card-title">Auth Rules — {{ selected.name }}</span></div>
        <div class="card-body p-0">
          <table class="table table-sm table-striped table-hover mb-0">
            <thead class="table-dark"><tr><th>Rank</th><th>Rule Name</th><th>State</th><th>Identity Source</th></tr></thead>
            <tbody>
              <tr v-for="r in rules" :key="r.id || r.rank">
                <td>{{ r.rank }}</td><td>{{ r.name }}</td><td>{{ r.state }}</td><td>{{ r.identitySourceName || '—' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </template>
</div>`;

function PolicyComponent(alive) {
  return {
    loading: true, error: null, items: [],
    selected: null, rules: null, rulesLoading: false,
    async load() {
      try {
        const d = await API.get('/ise/policy-sets');
        if (!alive()) return;
        if (!d.items.length) {
          this.error = 'ℹ️ No policy sets returned — ensure OpenAPI is enabled on ISE (Administration → System → Settings → API Settings).';
        }
        this.items = d.items;
      } catch(e) {
        if (!alive()) return;
        this.error = e.message;
      } finally { if (alive()) this.loading = false; }
    },
    async loadDetail(ps) {
      this.selected = ps; this.rules = null; this.rulesLoading = true;
      try {
        const d = await API.get(`/ise/policy-sets/${ps.id}/auth-rules`);
        if (!alive()) return;
        this.rules = d.items;
      } catch {}
      finally { if (alive()) this.rulesLoading = false; }
    },
  };
}

/* ── Main mount ──────────────────────────────────────────────── */
export function mount(el) {
  el.innerHTML = shellTemplate;
  const alive = () => el.isConnected;

  const shellComp = {
    async init() {
      // Mount NADs (default tab)
      mountSubApp('ise-nads', nadsTemplate, NadsComponent(alive));

      // Mount other tabs lazily on first click
      const lazy = {
        'ise-endpoints-tab': () => mountSubApp('ise-endpoints', epTemplate, EndpointsComponent(alive)),
        'ise-trustsec-tab':  () => mountSubApp('ise-trustsec', trustsecTemplate, TrustSecComponent(alive)),
        'ise-identity-tab':  () => mountSubApp('ise-identity', simpleTableTemplate([
          { key: 'name',        label: 'Name',        falsy: true },
          { key: 'parent',      label: 'Parent',      falsy: true },
          { key: 'description', label: 'Description', falsy: true },
        ]), SimpleTableComponent('/ise/identity-groups', alive)),
        'ise-policy-tab':    () => mountSubApp('ise-policy', policyTemplate, PolicyComponent(alive)),
        'ise-admin-tab':     () => mountSubApp('ise-admin', simpleTableTemplate([
          { key: 'hostname',  label: 'Hostname', falsy: true },
          { key: 'ipAddress', label: 'IP',       mono: true,  falsy: true },
          { key: 'fqdn',      label: 'FQDN',     falsy: true },
          { key: 'nodeType',  label: 'Type',     falsy: true },
        ]), SimpleTableComponent('/ise/deployment-nodes', alive)),
      };

      Object.entries(lazy).forEach(([btnId, fn]) => {
        document.getElementById(btnId)?.addEventListener('shown.bs.tab', fn);
      });

      initCacheBar(
        document.getElementById('ise-cache-bar'),
        '/ise/cache/info',
        '/ise/cache/refresh',
        () => Router.go('ise')
      );
    },
  };
  createApp(shellComp).mount(el.firstElementChild);
  shellComp.init();
}
