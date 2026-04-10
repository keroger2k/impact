import { createApp } from '/static/petite-vue.esm.js';
import { API }        from '/static/js/api.js';
import { toast, dlText } from '/static/js/utils.js';

/* ── Shared sort mixin ───────────────────────────────────────── */
function sortedItems(items, col, dir) {
  if (!col) return items;
  return [...items].sort((a, b) =>
    String(a[col] ?? '').localeCompare(String(b[col] ?? ''), undefined, { numeric: true }) * dir
  );
}

/* ── Inventory tab ───────────────────────────────────────────── */
const inventoryTemplate = `
<div>
  <div v-if="loading" class="empty-state"><div class="spinner spinner-lg"></div></div>
  <div v-else-if="error" class="alert alert-danger">{{ error }}</div>
  <template v-else>
    <div class="section-header mb-3">
      <div class="section-title">Full Inventory — {{ items.length.toLocaleString() }} devices</div>
      <button class="btn btn-outline-secondary btn-sm" @click="downloadCsv()">⬇️ Download CSV</button>
    </div>
    <div class="table-wrap">
      <table class="table table-striped table-hover table-sm">
        <thead class="table-dark">
          <tr>
            <th @click="sort('hostname')"              :class="{sorted:col==='hostname'}">Hostname <span class="sort-arrow">↕</span></th>
            <th @click="sort('managementIpAddress')"   :class="{sorted:col==='managementIpAddress'}">Mgmt IP <span class="sort-arrow">↕</span></th>
            <th @click="sort('platformId')"            :class="{sorted:col==='platformId'}">Platform <span class="sort-arrow">↕</span></th>
            <th @click="sort('softwareVersion')"       :class="{sorted:col==='softwareVersion'}">Version <span class="sort-arrow">↕</span></th>
            <th @click="sort('reachabilityStatus')"    :class="{sorted:col==='reachabilityStatus'}">Status <span class="sort-arrow">↕</span></th>
            <th @click="sort('serialNumber')"          :class="{sorted:col==='serialNumber'}">Serial <span class="sort-arrow">↕</span></th>
            <th @click="sort('upTime')"                :class="{sorted:col==='upTime'}">Uptime <span class="sort-arrow">↕</span></th>
            <th>Last Contact</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in sorted" :key="d.id">
            <td>{{ d.hostname }}</td>
            <td class="mono">{{ d.managementIpAddress }}</td>
            <td>{{ d.platformId }}</td>
            <td class="mono">{{ d.softwareVersion }}</td>
            <td>
              <span class="badge" :class="d.reachabilityStatus === 'Reachable' ? 'text-bg-success' : 'text-bg-danger'">
                {{ d.reachabilityStatus || 'Unknown' }}
              </span>
            </td>
            <td class="mono">{{ d.serialNumber }}</td>
            <td>{{ d.upTime }}</td>
            <td>{{ d.lastContactFormatted }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>
</div>`;

/* ── Unreachable tab ─────────────────────────────────────────── */
const unreachableTemplate = `
<div>
  <div v-if="loading" class="empty-state"><div class="spinner spinner-lg"></div></div>
  <div v-else-if="error" class="alert alert-danger">{{ error }}</div>
  <div v-else-if="!items.length" class="alert alert-success">✅ All devices are reachable.</div>
  <template v-else>
    <div class="alert alert-danger mb-3">🔴 {{ items.length }} unreachable device(s)</div>
    <div class="table-wrap">
      <table class="table table-striped table-hover table-sm">
        <thead class="table-dark">
          <tr>
            <th @click="sort('hostname')"                  :class="{sorted:col==='hostname'}">Hostname <span class="sort-arrow">↕</span></th>
            <th @click="sort('managementIpAddress')"       :class="{sorted:col==='managementIpAddress'}">Mgmt IP <span class="sort-arrow">↕</span></th>
            <th @click="sort('platformId')"                :class="{sorted:col==='platformId'}">Platform <span class="sort-arrow">↕</span></th>
            <th>Last Contact</th>
            <th @click="sort('reachabilityFailureReason')" :class="{sorted:col==='reachabilityFailureReason'}">Failure Reason <span class="sort-arrow">↕</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in sorted" :key="d.id">
            <td>{{ d.hostname }}</td>
            <td class="mono">{{ d.managementIpAddress }}</td>
            <td>{{ d.platformId }}</td>
            <td>{{ d.lastContactFormatted }}</td>
            <td>{{ d.reachabilityFailureReason || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>
</div>`;

/* ── Sites tab ───────────────────────────────────────────────── */
const sitesTemplate = `
<div>
  <div v-if="loading" class="empty-state"><div class="spinner spinner-lg"></div></div>
  <div v-else-if="error" class="alert alert-danger">{{ error }}</div>
  <template v-else>
    <div class="section-header mb-3">
      <div class="section-title">{{ items.length.toLocaleString() }} sites</div>
    </div>
    <div class="table-wrap">
      <table class="table table-striped table-hover table-sm">
        <thead class="table-dark">
          <tr>
            <th @click="sort('name')"  :class="{sorted:col==='name'}">Full Path <span class="sort-arrow">↕</span></th>
            <th @click="sort('depth')" :class="{sorted:col==='depth'}">Depth <span class="sort-arrow">↕</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in sorted" :key="s.id">
            <td>{{ s.name }}</td>
            <td>{{ s.depth }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>
</div>`;

/* ── Config Search tab ───────────────────────────────────────── */
const configSearchTemplate = `
<div>
  <div class="card mb-4">
    <div class="card-header"><span class="card-title">Configuration String Search</span></div>
    <div class="card-body">
      <div class="alert alert-info mb-4">
        ℹ️ Configs are pulled from DNAC (cached 10 min per device). Results appear once all
        selected device configs have been fetched and searched.
      </div>
      <div class="form-group">
        <label class="form-label">Search string <span style="color:var(--danger)">*</span></label>
        <input class="input" v-model="query" placeholder="e.g. summary-address / crypto map / ip route 0.0.0.0"
               @keydown.enter="doSearch()">
      </div>
      <div class="grid-2 gap-3 mb-3">
        <div class="form-group m-0">
          <label class="form-label">Hostname contains</label>
          <input class="input" v-model="f.hostname" placeholder="e.g. ATL or router">
        </div>
        <div class="form-group m-0">
          <label class="form-label">Management IP contains</label>
          <input class="input" v-model="f.ip" placeholder="e.g. 10.16">
        </div>
        <div class="form-group m-0">
          <label class="form-label">Platform contains</label>
          <input class="input" v-model="f.platform" placeholder="e.g. C9300 or ISR">
        </div>
        <div class="form-group m-0">
          <label class="form-label">Role contains</label>
          <input class="input" v-model="f.role" placeholder="e.g. ACCESS or DISTRIBUTION">
        </div>
        <div class="form-group m-0">
          <label class="form-label">Device family contains</label>
          <input class="input" v-model="f.family" placeholder="e.g. Switches or Routers">
        </div>
        <div class="form-group m-0">
          <label class="form-label">Reachability</label>
          <select class="select" v-model="f.reachability">
            <option value="Reachable">Reachable only (recommended)</option>
            <option value="unreachable">Unreachable only</option>
            <option value="">All devices</option>
          </select>
        </div>
      </div>
      <div class="d-flex align-items-end gap-3">
        <div class="form-group m-0">
          <label class="form-label">Max devices</label>
          <input class="input" type="number" v-model.number="maxDevices" min="1" max="2700" style="width:100px">
        </div>
        <div class="d-flex gap-2">
          <button class="btn btn-primary btn-sm" @click="doSearch()" :disabled="loading">🔍 Search Configs</button>
          <button class="btn btn-outline-secondary btn-sm" @click="clear()">Clear</button>
        </div>
        <span style="font-size:12px;color:var(--text-secondary)">{{ statusMsg }}</span>
      </div>
    </div>
  </div>

  <div v-if="loading" class="card">
    <div class="card-body" style="text-align:center;padding:32px">
      <div class="spinner spinner-lg" style="margin:0 auto 12px"></div>
      <div style="color:var(--text-secondary);font-size:13px">
        Fetching and searching device configs from DNAC.<br>
        Configs are cached — subsequent searches on the same devices are instant.
      </div>
    </div>
  </div>
  <div v-else-if="error" class="alert alert-danger">❌ {{ error }}</div>

  <template v-else-if="csData">
    <div v-if="!csData.total_matches" class="card">
      <div class="card-body">
        <div class="empty-state">
          <div class="empty-state-icon">🔍</div>
          <div class="empty-state-title">No matches found</div>
          <div class="empty-state-desc">
            "{{ lastQuery }}" was not found in any config across
            {{ csData.devices_matched_filter.toLocaleString() }} device(s).
          </div>
        </div>
      </div>
    </div>

    <template v-else>
      <div class="kpi-row cols-4 mb-4">
        <div class="kpi-card">
          <div class="kpi-label">Devices filtered</div>
          <div class="kpi-value">{{ csData.devices_matched_filter.toLocaleString() }}</div>
        </div>
        <div class="kpi-card success">
          <div class="kpi-label">Devices with match</div>
          <div class="kpi-value">{{ csData.total_matches.toLocaleString() }}</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Total matching lines</div>
          <div class="kpi-value">{{ csData.total_matching_lines.toLocaleString() }}</div>
        </div>
        <div class="kpi-card teal">
          <div class="kpi-label">Search string</div>
          <div class="kpi-value" style="font-size:14px;padding-top:4px"><code>{{ lastQuery }}</code></div>
        </div>
      </div>

      <div class="table-wrap">
        <div class="table-toolbar d-flex justify-content-between align-items-center">
          <span class="table-count">{{ csData.total_matches }} device(s) with matches — click a row to expand</span>
          <button class="btn btn-outline-secondary btn-sm" @click="downloadCsv()">⬇️ Download CSV</button>
        </div>
        <table class="table table-sm table-striped table-hover">
          <thead class="table-dark">
            <tr>
              <th>Hostname</th><th>IP</th><th>Platform</th><th>Role</th>
              <th>Match Count</th><th></th>
            </tr>
          </thead>
          <tbody>
            <template v-for="(r, i) in csData.results" :key="r.hostname + r.ip">
              <tr @click="toggleExpand(i)" style="cursor:pointer">
                <td>{{ r.hostname }}</td>
                <td class="mono" style="font-size:12px">{{ r.ip || '—' }}</td>
                <td>{{ r.platform || '—' }}</td>
                <td>{{ r.role || '—' }}</td>
                <td><strong>{{ r.match_count }}</strong></td>
                <td style="text-align:right">
                  <span class="badge text-bg-secondary">{{ expanded.has(i) ? '▲' : '▼' }}</span>
                </td>
              </tr>
              <tr v-if="expanded.has(i)">
                <td colspan="6" style="padding:0;background:var(--bg)">
                  <div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center">
                    <input class="input" v-model="lineFilters[i]" placeholder="Filter these lines…" style="max-width:260px">
                    <button class="btn btn-outline-secondary btn-sm" @click="downloadDevice(i)">⬇️ Download</button>
                    <span style="font-size:11px;color:var(--text-secondary)">{{ r.match_count }} line(s) match</span>
                  </div>
                  <pre class="code-block" style="border-radius:0;margin:0;max-height:360px;overflow-y:auto">
<span v-for="l in filteredLines(i)" :key="l.line_num"><span style="color:var(--text-light);user-select:none;margin-right:10px">{{ String(l.line_num).padStart(4) }}</span>{{ l.text }}
</span></pre>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
    </template>
  </template>
</div>`;

/* ── Shell (Bootstrap tabs) ──────────────────────────────────── */
const shellTemplate = `
<div>
  <ul class="nav nav-tabs mb-3" role="tablist">
    <li class="nav-item" role="presentation">
      <button class="nav-link active" id="rep-inventory-tab" data-bs-toggle="tab"
              data-bs-target="#rep-inventory" type="button" role="tab">Inventory Export</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="rep-unreachable-tab" data-bs-toggle="tab"
              data-bs-target="#rep-unreachable" type="button" role="tab">Unreachable</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="rep-sites-tab" data-bs-toggle="tab"
              data-bs-target="#rep-sites" type="button" role="tab">Sites</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="rep-config-tab" data-bs-toggle="tab"
              data-bs-target="#rep-config" type="button" role="tab">Config Search</button>
    </li>
  </ul>
  <div class="tab-content">
    <div class="tab-pane fade show active" id="rep-inventory"   role="tabpanel"></div>
    <div class="tab-pane fade"             id="rep-unreachable" role="tabpanel"></div>
    <div class="tab-pane fade"             id="rep-sites"       role="tabpanel"></div>
    <div class="tab-pane fade"             id="rep-config"      role="tabpanel"></div>
  </div>
</div>`;

/* ── Component factories ─────────────────────────────────────── */
function makeSimpleTable(apiUrl, template, mapFn) {
  return {
    loading: true, error: null, items: [],
    col: null, dir: 1,
    get sorted() { return sortedItems(this.items, this.col, this.dir); },
    async load() {
      try {
        const d = await API.get(apiUrl);
        this.items = mapFn ? d.items.map(mapFn) : d.items;
      } catch (e) { this.error = e.message; }
      finally { this.loading = false; }
    },
    sort(c) {
      if (this.col === c) this.dir *= -1;
      else { this.col = c; this.dir = 1; }
    },
  };
}

function mountPane(pane, tmpl, component) {
  if (pane._mounted) return;
  pane._mounted = true;
  pane.innerHTML = tmpl;
  createApp(component).mount(pane.firstElementChild);
  if (component.init) component.init();
  else if (component.load) component.load();
}

/* ── Public mount ────────────────────────────────────────────── */
export function mount(el) {
  el.innerHTML = shellTemplate;
  const shellComp = {
    init() {
      // Inventory — mount immediately
      mountPane(
        document.getElementById('rep-inventory'),
        inventoryTemplate,
        {
          ...makeSimpleTable('/dnac/devices?limit=2000', inventoryTemplate),
          downloadCsv() {
            const header = 'Hostname,ManagementIP,Platform,Version,Reachability,Serial,Uptime,LastContact\n';
            const rows = this.items.map(d =>
              [d.hostname, d.managementIpAddress, d.platformId, d.softwareVersion,
               d.reachabilityStatus, d.serialNumber, d.upTime, d.lastContactFormatted]
              .map(v => `"${v||''}"`).join(',')
            ).join('\n');
            dlText(header + rows, `inventory_${new Date().toISOString().slice(0,10)}.csv`);
          },
        }
      );

      // Unreachable — lazy
      document.getElementById('rep-unreachable-tab').addEventListener('shown.bs.tab', () => {
        mountPane(
          document.getElementById('rep-unreachable'),
          unreachableTemplate,
          makeSimpleTable('/dnac/devices?reachability=unreachable&limit=2000', unreachableTemplate)
        );
      });

      // Sites — lazy
      document.getElementById('rep-sites-tab').addEventListener('shown.bs.tab', () => {
        mountPane(
          document.getElementById('rep-sites'),
          sitesTemplate,
          makeSimpleTable('/dnac/sites', sitesTemplate, s => ({
            ...s, depth: s.name.split('/').length - 1,
          }))
        );
      });

      // Config Search — lazy
      document.getElementById('rep-config-tab').addEventListener('shown.bs.tab', () => {
        const pane = document.getElementById('rep-config');
        if (pane._mounted) return;
        pane._mounted = true;
        pane.innerHTML = configSearchTemplate;
        createApp({
          query: '', lastQuery: '',
          f: { hostname: '', ip: '', platform: '', role: '', family: '', reachability: 'Reachable' },
          maxDevices: 500,
          loading: false, error: null, statusMsg: '',
          csData: null,
          expanded: new Set(),
          lineFilters: {},

          init() {},

          clear() {
            this.query = ''; this.lastQuery = '';
            Object.keys(this.f).forEach(k => { this.f[k] = k === 'reachability' ? 'Reachable' : ''; });
            this.maxDevices = 500;
            this.csData = null; this.statusMsg = '';
            this.expanded = new Set(); this.lineFilters = {};
          },

          async doSearch() {
            const q = this.query.trim();
            if (!q || q.length < 2) { toast('Enter at least 2 characters to search', 'warn'); return; }
            this.loading = true; this.error = null; this.csData = null;
            this.statusMsg = 'Searching…'; this.expanded = new Set(); this.lineFilters = {};
            this.lastQuery = q;
            try {
              const body = {
                search_string: q,
                hostname:      this.f.hostname   || null,
                ip:            this.f.ip          || null,
                platform:      this.f.platform    || null,
                role:          this.f.role         || null,
                device_family: this.f.family       || null,
                reachability:  this.f.reachability,
                max_devices:   this.maxDevices,
              };
              const data = await API.post('/dnac/config-search', body);
              this.csData = data;
              this.statusMsg = `${data.total_matches} device(s) matched in ${data.devices_matched_filter} searched`;
            } catch (e) {
              this.error = e.message; this.statusMsg = '';
            } finally {
              this.loading = false;
            }
          },

          toggleExpand(i) {
            const s = new Set(this.expanded);
            if (s.has(i)) s.delete(i); else s.add(i);
            this.expanded = s;
          },

          filteredLines(i) {
            if (!this.csData) return [];
            const r = this.csData.results[i];
            const q = (this.lineFilters[i] || '').toLowerCase();
            return q ? r.lines.filter(l => l.text.toLowerCase().includes(q)) : r.lines;
          },

          downloadDevice(i) {
            if (!this.csData) return;
            const r = this.csData.results[i];
            const text = `Device: ${r.hostname} (${r.ip})\nSearch: "${this.lastQuery}"\n${'='.repeat(60)}\n` +
              r.lines.map(l => `${String(l.line_num).padStart(5)}: ${l.text}`).join('\n');
            dlText(text, `${r.hostname}_matches.txt`);
          },

          downloadCsv() {
            if (!this.csData) return;
            const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
            const header = 'Hostname,IP,Platform,Role,Line Number,Match Text\n';
            const rows = this.csData.results.flatMap(r =>
              r.lines.map(l => [r.hostname, r.ip, r.platform, r.role, l.line_num, l.text].map(esc).join(','))
            ).join('\n');
            dlText(header + rows, `config_search_${new Date().toISOString().slice(0,10)}.csv`);
          },
        }).mount(pane.firstElementChild);
      });
    },
  };
  createApp(shellComp).mount(el.firstElementChild);
  shellComp.init();
}
