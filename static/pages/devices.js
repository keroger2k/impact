import { createApp }   from '/static/petite-vue.esm.js';
import { API }          from '/static/js/api.js';
import { fmtTs, escHtml, dlText, initCacheBar } from '/static/js/utils.js';
import { Router }       from '/static/js/router.js';

const PAGE_SIZE = 50;

const template = `
<div class="dev-page-layout">

  <!-- ── Detail panel (always visible above table) ─────────── -->
  <div id="dev-detail">
    <div v-if="!selected" class="detail-placeholder">
      <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round"
          d="M8.25 6.75h7.5M8.25 12h7.5m-7.5 5.25h4.5M3.75 3h16.5a.75.75 0 01.75.75v16.5a.75.75 0 01-.75.75H3.75a.75.75 0 01-.75-.75V3.75A.75.75 0 013.75 3z"/>
      </svg>
      Select a row to view details
    </div>
    <div v-else class="detail-panel">
      <div class="detail-header">
        <span style="font-size:18px">{{ selected.reachabilityStatus === 'Reachable' ? '✅' : '🔴' }}</span>
        <div>
          <div class="detail-hostname">{{ selected.hostname || '—' }}</div>
          <div style="font-size:11px;opacity:.7">{{ selected.managementIpAddress }} · {{ selected.platformId }}</div>
        </div>
        <div class="ms-auto d-flex gap-2 align-items-center">
          <button class="btn btn-outline-secondary btn-sm" @click="loadConfig()">📄 Config</button>
          <a class="btn btn-outline-secondary btn-sm" :href="dnacUrl" target="_blank">🔗 Open in DNAC</a>
        </div>
      </div>
      <div class="detail-body">
        <div class="detail-grid">
          <div class="detail-section">
            <div class="detail-section-title">Identity</div>
            <div class="kv-row"><span class="kv-label">Hostname</span><span class="kv-value">{{ selected.hostname || '—' }}</span></div>
            <div class="kv-row"><span class="kv-label">Management IP</span><span class="kv-value"><code>{{ selected.managementIpAddress }}</code></span></div>
            <div class="kv-row"><span class="kv-label">Platform</span><span class="kv-value">{{ selected.platformId || '—' }}</span></div>
            <div class="kv-row"><span class="kv-label">IOS Version</span><span class="kv-value">{{ selected.softwareVersion || '—' }}</span></div>
            <div class="kv-row"><span class="kv-label">Serial</span><span class="kv-value">{{ selected.serialNumber || '—' }}</span></div>
            <div class="kv-row"><span class="kv-label">Vendor</span><span class="kv-value">{{ selected.vendor || '—' }}</span></div>
            <div class="kv-row"><span class="kv-label">Site</span><span class="kv-value">{{ selected.siteName || '—' }}</span></div>
          </div>
          <div class="detail-section">
            <div class="detail-section-title">Status</div>
            <div class="kv-row"><span class="kv-label">Reachability</span><span class="kv-value">
              <span class="badge" :class="selected.reachabilityStatus === 'Reachable' ? 'text-bg-success' : 'text-bg-danger'">
                {{ selected.reachabilityStatus === 'Reachable' ? '✅' : '🔴' }} {{ selected.reachabilityStatus || 'Unknown' }}
              </span>
            </span></div>
            <div class="kv-row"><span class="kv-label">Role</span><span class="kv-value">{{ selected.role || '—' }}</span></div>
            <div class="kv-row"><span class="kv-label">Uptime</span><span class="kv-value">{{ selected.upTime || '—' }}</span></div>
            <div class="kv-row"><span class="kv-label">Last Contact</span><span class="kv-value">{{ selected.lastContactFormatted || '—' }}</span></div>
            <div class="kv-row"><span class="kv-label">Device ID</span><span class="kv-value"><code style="font-size:10px">{{ selected.id }}</code></span></div>
            <div v-if="selected.reachabilityFailureReason" class="kv-row">
              <span class="kv-label">Failure</span>
              <span class="kv-value"><span class="badge text-bg-danger">{{ selected.reachabilityFailureReason }}</span></span>
            </div>
          </div>
        </div>
        <!-- Config area -->
        <div v-if="configLoading" class="empty-state"><div class="spinner"></div></div>
        <div v-else-if="configError" class="alert alert-danger mt-3">{{ configError }}</div>
        <template v-else-if="configData">
          <hr class="divider">
          <div class="section-header">
            <div class="section-title">Running Config — {{ selected.hostname }}</div>
            <div class="d-flex gap-2">
              <input class="input" v-model="configFilter" placeholder="Filter lines…" style="width:200px">
              <button class="btn btn-outline-secondary btn-sm" @click="downloadConfig()">⬇️ Download</button>
            </div>
          </div>
          <div class="code-wrap">
            <div class="code-toolbar">📄 {{ selected.hostname }} · {{ configData.cached ? 'cached' : 'live' }}</div>
            <pre class="code-block" v-text="filteredConfig"></pre>
          </div>
        </template>
      </div>
    </div>
  </div>

  <!-- ── Table section ──────────────────────────────────────── -->
  <div class="dev-table-wrap">
    <div class="table-toolbar">
      <div class="search-input">
        <input class="input" v-model="search.hostname" placeholder="Hostname…" style="width:160px"
               @keydown.enter="doSearch()">
      </div>
      <div class="search-input">
        <input class="input" v-model="search.ip" placeholder="IP address…" style="width:140px"
               @keydown.enter="doSearch()">
      </div>
      <input class="input" v-model="search.platform" placeholder="Platform…" style="width:130px"
             @keydown.enter="doSearch()">
      <input class="input" v-model="search.site" placeholder="Site…" style="width:150px"
             @keydown.enter="doSearch()">
      <select class="select" v-model="search.reachability" style="width:130px">
        <option value="">All reachability</option>
        <option value="reachable">Reachable</option>
        <option value="unreachable">Unreachable</option>
      </select>
      <button class="btn btn-primary" @click="doSearch()" :disabled="loading">Search</button>
      <span class="table-count">{{ total ? total.toLocaleString() + ' device(s)' : '' }}</span>
      <div class="cache-bar" id="dev-cache-bar"></div>
    </div>

    <div v-if="loading" class="empty-state"><div class="spinner spinner-lg"></div></div>
    <div v-else-if="tableError" class="alert alert-danger">{{ tableError }}</div>
    <div v-else-if="!devices.length && searched" class="empty-state">
      <div class="empty-state-icon">📭</div>
      <div class="empty-state-title">No results</div>
    </div>
    <table v-else-if="devices.length" class="table table-striped table-hover table-sm">
      <thead class="table-dark">
        <tr>
          <th @click="sort('hostname')"            :class="{sorted: sortCol==='hostname'}">Hostname <span class="sort-arrow">↕</span></th>
          <th @click="sort('managementIpAddress')" :class="{sorted: sortCol==='managementIpAddress'}">Mgmt IP <span class="sort-arrow">↕</span></th>
          <th @click="sort('platformId')"          :class="{sorted: sortCol==='platformId'}">Platform <span class="sort-arrow">↕</span></th>
          <th @click="sort('softwareVersion')"     :class="{sorted: sortCol==='softwareVersion'}">IOS Version <span class="sort-arrow">↕</span></th>
          <th @click="sort('role')"                :class="{sorted: sortCol==='role'}">Role <span class="sort-arrow">↕</span></th>
          <th @click="sort('siteName')"            :class="{sorted: sortCol==='siteName'}">Site <span class="sort-arrow">↕</span></th>
          <th @click="sort('reachabilityStatus')"  :class="{sorted: sortCol==='reachabilityStatus'}">Status <span class="sort-arrow">↕</span></th>
          <th>Last Contact</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="device in pageItems" :key="device.id"
            :class="{selected: selected?.id === device.id}"
            @click="select(device)">
          <td>{{ device.hostname }}</td>
          <td class="mono">{{ device.managementIpAddress }}</td>
          <td>{{ device.platformId }}</td>
          <td class="mono">{{ device.softwareVersion }}</td>
          <td>{{ device.role }}</td>
          <td>{{ device.siteName }}</td>
          <td>
            <span class="badge"
                  :class="device.reachabilityStatus === 'Reachable' ? 'text-bg-success' : 'text-bg-danger'">
              {{ device.reachabilityStatus || 'Unknown' }}
            </span>
          </td>
          <td>{{ device.lastContactFormatted }}</td>
        </tr>
      </tbody>
    </table>

    <!-- Pagination -->
    <div v-if="totalPages > 1" class="pagination">
      <button class="btn btn-outline-secondary btn-sm" @click="page--" :disabled="page===0">‹</button>
      <template v-for="p in visiblePages">
        <span v-if="p === '…'" class="pagination-ellipsis">…</span>
        <button v-else class="btn btn-outline-secondary btn-sm" :class="{active: p===page}" @click="page=p">{{ p+1 }}</button>
      </template>
      <button class="btn btn-outline-secondary btn-sm" @click="page++" :disabled="page>=totalPages-1">›</button>
      <span class="pagination-info">{{ page*PAGE_SIZE+1 }}–{{ Math.min((page+1)*PAGE_SIZE, devices.length) }} of {{ devices.length.toLocaleString() }}</span>
    </div>
  </div>
</div>`;

export function mount(el) {
  el.innerHTML = template;
  const comp = {
    PAGE_SIZE,

    // Search form state
    search:    { hostname: '', ip: '', platform: '', site: '', reachability: '' },

    // Table state
    devices:    [],
    loading:    false,
    searched:   false,
    tableError: null,
    total:      0,
    sortCol:    null,
    sortDir:    1,
    page:       0,

    // Detail panel state
    selected:     null,
    configLoading: false,
    configData:    null,
    configError:   null,
    configFilter:  '',

    // Computed
    get sorted() {
      if (!this.sortCol) return this.devices;
      const col = this.sortCol, dir = this.sortDir;
      return [...this.devices].sort((a, b) =>
        String(a[col] ?? '').localeCompare(String(b[col] ?? ''), undefined, { numeric: true }) * dir
      );
    },
    get totalPages() { return Math.ceil(this.devices.length / PAGE_SIZE) || 1; },
    get pageItems()  { return this.sorted.slice(this.page * PAGE_SIZE, (this.page + 1) * PAGE_SIZE); },
    get visiblePages() {
      const n = this.totalPages, p = this.page;
      const show = new Set([0, n - 1]);
      for (let i = Math.max(0, p - 2); i <= Math.min(n - 1, p + 2); i++) show.add(i);
      const sorted = [...show].sort((a, b) => a - b);
      const result = []; let prev = -1;
      for (const pg of sorted) {
        if (pg - prev > 1) result.push('…');
        result.push(pg);
        prev = pg;
      }
      return result;
    },
    get dnacUrl() {
      if (!this.selected) return '#';
      return `${window.location.origin.replace(':8000', '')}/dna/provision/devices/inventory/device-details?deviceId=${this.selected.id}`;
    },
    get filteredConfig() {
      if (!this.configData) return '';
      if (!this.configFilter) return this.configData.config;
      const q = this.configFilter.toLowerCase();
      return this.configData.config.split('\n').filter(l => l.toLowerCase().includes(q)).join('\n');
    },

    // Methods
    async init() {
      await this.doSearch();
      initCacheBar(
        document.getElementById('dev-cache-bar'),
        '/dnac/cache/info',
        '/dnac/cache/refresh',
        () => Router.go('devices')
      );
    },

    async doSearch() {
      const p = new URLSearchParams({
        hostname:     this.search.hostname,
        ip:           this.search.ip,
        platform:     this.search.platform,
        site:         this.search.site,
        reachability: this.search.reachability,
        limit:        2000,
      });
      this.loading    = true;
      this.tableError = null;
      this.selected   = null;
      this.configData = null;
      try {
        const data = await API.get(`/dnac/devices?${p}`);
        this.devices  = data.items.map(d => ({
          ...d,
          lastContactFormatted: d.lastContactFormatted || fmtTs(d.lastUpdateTime),
        }));
        this.total   = data.total;
        this.page    = 0;
        this.searched = true;
      } catch(e) {
        this.tableError = e.message;
      } finally {
        this.loading = false;
      }
    },

    select(device) {
      this.selected    = device;
      this.configData  = null;
      this.configError = null;
      this.configFilter = '';
    },

    sort(col) {
      if (this.sortCol === col) this.sortDir *= -1;
      else { this.sortCol = col; this.sortDir = 1; }
      this.page = 0;
    },

    async loadConfig() {
      if (!this.selected) return;
      this.configLoading = true;
      this.configData    = null;
      this.configError   = null;
      try {
        this.configData = await API.get(`/dnac/devices/${this.selected.id}/config`);
      } catch(e) {
        this.configError = e.message;
      } finally {
        this.configLoading = false;
      }
    },

    downloadConfig() {
      if (!this.configData || !this.selected) return;
      dlText(this.configData.config, `${this.selected.hostname}_config.txt`);
    },
  };
  createApp(comp).mount(el.firstElementChild);
  comp.init();
}
