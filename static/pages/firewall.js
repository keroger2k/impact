import { createApp }   from '/static/petite-vue.esm.js';
import { API }          from '/static/js/api.js';
import { initCacheBar } from '/static/js/utils.js';

/* ── Shell template (Bootstrap tabs) ─────────────────────────── */
const shellTemplate = `
<div @vue:mounted="init()">
  <ul class="nav nav-tabs mb-3" id="fw-tabs" role="tablist">
    <li class="nav-item" role="presentation">
      <button class="nav-link active" id="fw-lookup-tab" data-bs-toggle="tab"
              data-bs-target="#fw-lookup" type="button" role="tab">Policy Lookup</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="fw-bydevice-tab" data-bs-toggle="tab"
              data-bs-target="#fw-bydevice" type="button" role="tab">By Device</button>
    </li>
  </ul>
  <div class="tab-content" id="fw-content">
    <div class="tab-pane fade show active" id="fw-lookup"   role="tabpanel"></div>
    <div class="tab-pane fade"             id="fw-bydevice" role="tabpanel"></div>
  </div>
</div>`;

/* ── Policy Lookup tab ────────────────────────────────────────── */
const lookupTemplate = `
<div @vue:mounted="init()">
  <div class="card mb-4">
    <div class="card-header">
      <span class="card-title">🔥 Firewall Policy Lookup</span>
      <div class="cache-bar" id="fw-cache-bar"></div>
    </div>
    <div class="card-body">
      <div class="input-row flex-wrap gap-2 mb-3">
        <div class="form-group m-0">
          <label class="form-label">Source IP</label>
          <input class="input" v-model="src" placeholder="10.47.31.195" @keydown.enter="doLookup()">
        </div>
        <div class="form-group m-0">
          <label class="form-label">Destination IP</label>
          <input class="input" v-model="dst" placeholder="10.16.97.122" @keydown.enter="doLookup()">
        </div>
        <div class="form-group m-0">
          <label class="form-label">Protocol</label>
          <select class="select" v-model="proto">
            <option value="any">any</option>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="icmp">icmp</option>
          </select>
        </div>
        <div class="form-group m-0">
          <label class="form-label">Dst Port</label>
          <input class="input" v-model="port" placeholder="443" style="width:80px" @keydown.enter="doLookup()">
        </div>
        <div class="d-flex align-items-end gap-2">
          <button class="btn btn-primary" @click="doLookup()" :disabled="loading">🔍 Search</button>
        </div>
      </div>

      <div class="d-flex flex-wrap gap-3 align-items-center">
        <div class="form-check">
          <input type="checkbox" class="form-check-input" id="fw-disabled" v-model="includeDisabled">
          <label class="form-check-label" for="fw-disabled">Include disabled rules</label>
        </div>
        <div class="form-check">
          <input type="checkbox" class="form-check-input" id="fw-all" v-model="showAll">
          <label class="form-check-label" for="fw-all">Show all matches</label>
        </div>

        <!-- Device group multi-select dropdown -->
        <div class="dg-select d-inline-block" style="position:relative">
          <button type="button" class="btn btn-outline-secondary btn-sm" @click="dgOpen=!dgOpen">
            {{ dgLabel }} ▾
          </button>
          <div v-if="dgOpen" class="dg-select-panel" style="position:absolute;top:100%;left:0;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:8px;min-width:200px;box-shadow:0 4px 12px rgba(0,0,0,.15)">
            <label style="display:flex;align-items:center;gap:6px;padding:4px 0;font-size:13px;cursor:pointer">
              <input type="checkbox" :checked="allSelected" @change="toggleAll($event.target.checked)">
              All device groups
            </label>
            <hr style="margin:4px 0">
            <label v-for="dg in deviceGroups" :key="dg"
                   style="display:flex;align-items:center;gap:6px;padding:3px 0;font-size:13px;cursor:pointer">
              <input type="checkbox" :value="dg" v-model="selectedDgs">
              {{ dg }}
            </label>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div v-if="loading" class="empty-state"><div class="spinner spinner-lg"></div></div>
  <div v-else-if="lookupError" class="alert alert-danger">{{ lookupError }}</div>
  <div v-else-if="noMatch" class="alert alert-warn">
    ⚠️ No rules match <strong>{{ lastSrc }} → {{ lastDst }}{{ lastPortLabel }}</strong>.
    Traffic hits the implicit deny.
    <span style="font-size:12px;color:var(--text-secondary);margin-left:8px">{{ result?.rules_searched?.toLocaleString() }} rules searched.</span>
  </div>

  <template v-else-if="result && result.match_count">
    <!-- KPIs -->
    <div class="kpi-row cols-4 mb-4">
      <div class="kpi-card">
        <div class="kpi-label">Rules Searched</div>
        <div class="kpi-value">{{ result.rules_searched?.toLocaleString() }}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Matching Rules</div>
        <div class="kpi-value">{{ result.match_count }}</div>
      </div>
      <div class="kpi-card" :class="result.traffic_decision === 'allow' ? 'success' : 'danger'">
        <div class="kpi-label">Traffic Decision</div>
        <div class="kpi-value" style="font-size:20px">{{ result.traffic_decision?.toUpperCase() }}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Flow</div>
        <div class="kpi-value" style="font-size:13px;padding-top:4px">{{ lastSrc }} → {{ lastDst }}{{ lastPortLabel }}</div>
      </div>
    </div>

    <!-- Rule detail panel -->
    <div v-if="!selectedRule" class="detail-placeholder">
      <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-3-3v6m-7.5 3h15a.75.75 0 00.75-.75V5.25a.75.75 0 00-.75-.75h-15a.75.75 0 00-.75.75v13.5c0 .414.336.75.75.75z"/>
      </svg>
      Select a row to view rule details
    </div>
    <div v-else class="detail-panel mb-3">
      <div class="detail-header">
        <span style="font-size:18px">{{ selectedRule.action === 'allow' ? '✅' : '🔴' }}</span>
        <div>
          <div class="detail-hostname">{{ selectedRule.first_match ? '⭐ ' : '' }}{{ selectedRule.name }}</div>
          <div style="font-size:11px;opacity:.7">{{ selectedRule.device_group }} · {{ selectedRule.rulebase }}</div>
        </div>
        <div class="ms-auto">
          <span class="badge" :class="selectedRule.action === 'allow' ? 'text-bg-success' : 'text-bg-danger'">
            {{ selectedRule.action?.toUpperCase() }}
          </span>
          <span v-if="selectedRule.disabled" class="badge text-bg-secondary ms-1">DISABLED</span>
        </div>
      </div>
      <div class="detail-body">
        <div class="detail-grid">
          <div class="detail-section">
            <div class="detail-section-title">Traffic</div>
            <div class="kv-row"><span class="kv-label">From Zone</span><span class="kv-value">{{ (selectedRule.from_zones || []).join(', ') || '—' }}</span></div>
            <div class="kv-row"><span class="kv-label">To Zone</span><span class="kv-value">{{ (selectedRule.to_zones || []).join(', ') || '—' }}</span></div>
            <div class="kv-row"><span class="kv-label">Source</span><span class="kv-value">{{ fmtArr(selectedRule.source) }}</span></div>
            <div class="kv-row"><span class="kv-label">Destination</span><span class="kv-value">{{ fmtArr(selectedRule.destination) }}</span></div>
            <div class="kv-row"><span class="kv-label">Application</span><span class="kv-value">{{ fmtArr(selectedRule.application) }}</span></div>
            <div class="kv-row"><span class="kv-label">Service</span><span class="kv-value">{{ fmtArr(selectedRule.service) }}</span></div>
          </div>
          <div class="detail-section">
            <div class="detail-section-title">Resolved Sources</div>
            <template v-if="selectedRule.resolved_source && Object.keys(selectedRule.resolved_source).length">
              <div v-for="(ips, name) in selectedRule.resolved_source" :key="name" class="kv-row">
                <span class="kv-label">{{ name }}</span>
                <span class="kv-value"><code>{{ (ips || []).join(', ') || '—' }}</code></span>
              </div>
            </template>
            <div v-else class="kv-row"><span class="kv-label" style="font-style:italic;opacity:.6">none</span></div>

            <div class="detail-section-title mt-3">Resolved Destinations</div>
            <template v-if="selectedRule.resolved_destination && Object.keys(selectedRule.resolved_destination).length">
              <div v-for="(ips, name) in selectedRule.resolved_destination" :key="name" class="kv-row">
                <span class="kv-label">{{ name }}</span>
                <span class="kv-value"><code>{{ (ips || []).join(', ') || '—' }}</code></span>
              </div>
            </template>
            <div v-else class="kv-row"><span class="kv-label" style="font-style:italic;opacity:.6">none</span></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Results table -->
    <div class="table-wrap">
      <div class="table-toolbar">
        <span class="table-count">{{ result.match_count }} rule(s) matched — click a row for detail</span>
      </div>
      <table class="table table-striped table-hover table-sm">
        <thead class="table-dark">
          <tr>
            <th @click="sort('name')"         :class="{sorted:sortCol==='name'}">Rule Name <span class="sort-arrow">↕</span></th>
            <th @click="sort('device_group')" :class="{sorted:sortCol==='device_group'}">Device Group <span class="sort-arrow">↕</span></th>
            <th @click="sort('rulebase')"     :class="{sorted:sortCol==='rulebase'}">Rulebase <span class="sort-arrow">↕</span></th>
            <th @click="sort('action')"       :class="{sorted:sortCol==='action'}">Action <span class="sort-arrow">↕</span></th>
            <th>Source</th>
            <th>Destination</th>
            <th>Service</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="rule in sortedMatches" :key="rule.name + rule.device_group"
              :class="{selected: selectedRule?.name === rule.name && selectedRule?.device_group === rule.device_group}"
              @click="selectedRule = rule">
            <td>{{ rule.first_match ? '⭐ ' : '' }}{{ rule.action === 'allow' ? '✅' : '🔴' }} {{ rule.name }}</td>
            <td>{{ rule.device_group }}</td>
            <td>{{ rule.rulebase }}</td>
            <td><span class="badge" :class="rule.action === 'allow' ? 'text-bg-success' : 'text-bg-danger'">{{ rule.action?.toUpperCase() }}</span></td>
            <td>{{ fmtArr(rule.source) }}</td>
            <td>{{ fmtArr(rule.destination) }}</td>
            <td>{{ fmtArr(rule.service) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>
</div>`;

/* ── By Device tab ────────────────────────────────────────────── */
const byDeviceTemplate = `
<div @vue:mounted="init()">
  <div class="card mb-4">
    <div class="card-header">
      <span class="card-title">Firewall Policies</span>
      <div class="cache-bar" id="fw-dev-cache-bar"></div>
    </div>
    <div class="card-body">
      <div class="form-group m-0">
        <label class="form-label">Select Firewall Device</label>
        <select class="select" v-model="selectedSerial" @change="onDeviceChange()" style="max-width:400px">
          <option value="">-- Choose a firewall --</option>
          <option v-for="d in devices" :key="d.serial" :value="d.serial">
            {{ d.name || d.hostname || d.serial }} ({{ d.serial }})
          </option>
        </select>
      </div>
    </div>
  </div>

  <div v-if="devLoading" class="empty-state"><div class="spinner spinner-lg"></div><p style="margin-top:12px;color:var(--text-secondary)">Loading virtual systems…</p></div>
  <div v-else-if="devError" class="alert alert-danger">{{ devError }}</div>

  <template v-else-if="vsysList.length">
    <div class="card mb-4">
      <div class="card-body">
        <div class="form-group m-0">
          <label class="form-label">Virtual System (VSYS)</label>
          <select class="select" v-model="selectedVsys" @change="onVsysChange()" style="max-width:300px">
            <option v-for="v in vsysList" :key="v" :value="v">{{ v }}</option>
          </select>
        </div>
      </div>
    </div>

    <div v-if="policiesLoading" class="empty-state"><div class="spinner spinner-lg"></div><p style="margin-top:12px;color:var(--text-secondary)">Loading policies…</p></div>
    <div v-else-if="policiesError" class="alert alert-danger">{{ policiesError }}</div>
    <div v-else-if="selectedVsys && !policies.length" class="alert alert-info">ℹ️ No policies found for {{ selectedVsys }}.</div>

    <template v-else-if="policies.length">
      <!-- KPIs -->
      <div class="kpi-row cols-3 mb-4">
        <div class="kpi-card">
          <div class="kpi-label">Total Policies</div>
          <div class="kpi-value">{{ policies.length }}</div>
        </div>
        <div class="kpi-card success">
          <div class="kpi-label">Allow Rules</div>
          <div class="kpi-value">{{ policies.filter(p => p.action === 'allow').length }}</div>
        </div>
        <div class="kpi-card danger">
          <div class="kpi-label">Deny / Drop Rules</div>
          <div class="kpi-value">{{ policies.filter(p => p.action === 'deny' || p.action === 'drop').length }}</div>
        </div>
      </div>

      <!-- Policy detail panel -->
      <div v-if="!selectedPolicy" class="detail-placeholder">
        <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-3-3v6m-7.5 3h15a.75.75 0 00.75-.75V5.25a.75.75 0 00-.75-.75h-15a.75.75 0 00-.75.75v13.5c0 .414.336.75.75.75z"/>
        </svg>
        Select a row to view policy details
      </div>
      <div v-else class="detail-panel mb-3">
        <div class="detail-header">
          <span style="font-size:18px">{{ selectedPolicy.action === 'allow' ? '✅' : '🔴' }}</span>
          <div>
            <div class="detail-hostname">{{ selectedPolicy.name }}</div>
            <div style="font-size:11px;opacity:.7">{{ selectedPolicy.device_group || selectedVsys }} · {{ selectedPolicy.rulebase }}</div>
          </div>
          <div class="ms-auto">
            <span class="badge" :class="selectedPolicy.action === 'allow' ? 'text-bg-success' : 'text-bg-danger'">
              {{ selectedPolicy.action?.toUpperCase() }}
            </span>
            <span v-if="selectedPolicy.disabled" class="badge text-bg-secondary ms-1">DISABLED</span>
          </div>
        </div>
        <div class="detail-body">
          <div class="detail-grid">
            <div class="detail-section">
              <div class="detail-section-title">Traffic</div>
              <div class="kv-row"><span class="kv-label">From Zone</span><span class="kv-value">{{ (selectedPolicy.from_zones || []).join(', ') || '—' }}</span></div>
              <div class="kv-row"><span class="kv-label">To Zone</span><span class="kv-value">{{ (selectedPolicy.to_zones || []).join(', ') || '—' }}</span></div>
              <div class="kv-row"><span class="kv-label">Source</span><span class="kv-value">{{ fmtArr(selectedPolicy.source) }}</span></div>
              <div class="kv-row"><span class="kv-label">Destination</span><span class="kv-value">{{ fmtArr(selectedPolicy.destination) }}</span></div>
              <div class="kv-row"><span class="kv-label">Application</span><span class="kv-value">{{ fmtArr(selectedPolicy.application) }}</span></div>
              <div class="kv-row"><span class="kv-label">Service</span><span class="kv-value">{{ fmtArr(selectedPolicy.service) }}</span></div>
            </div>
            <div class="detail-section">
              <div class="detail-section-title">Context</div>
              <div class="kv-row"><span class="kv-label">Rule #</span><span class="kv-value">{{ selectedPolicy.rule_number ?? '—' }}</span></div>
              <div class="kv-row"><span class="kv-label">Device Group</span><span class="kv-value">{{ selectedPolicy.device_group || '—' }}</span></div>
              <div class="kv-row"><span class="kv-label">Rulebase</span><span class="kv-value">{{ selectedPolicy.rulebase || '—' }}</span></div>
              <div class="kv-row"><span class="kv-label">Description</span><span class="kv-value">{{ selectedPolicy.description || '—' }}</span></div>
              <div class="kv-row"><span class="kv-label">Tags</span><span class="kv-value">{{ fmtArr(selectedPolicy.tags) }}</span></div>
            </div>
          </div>
        </div>
      </div>

      <!-- Policies table -->
      <div class="table-wrap">
        <div class="table-toolbar">
          <span class="table-count">{{ policies.length }} policy(ies) — click a row for detail</span>
        </div>
        <table class="table table-striped table-hover table-sm">
          <thead class="table-dark">
            <tr>
              <th style="width:40px">#</th>
              <th @click="sortDev('name')"         :class="{sorted:devSortCol==='name'}">Rule Name <span class="sort-arrow">↕</span></th>
              <th @click="sortDev('device_group')" :class="{sorted:devSortCol==='device_group'}">Context <span class="sort-arrow">↕</span></th>
              <th @click="sortDev('rulebase')"     :class="{sorted:devSortCol==='rulebase'}">Base <span class="sort-arrow">↕</span></th>
              <th @click="sortDev('action')"       :class="{sorted:devSortCol==='action'}">Action <span class="sort-arrow">↕</span></th>
              <th>From</th>
              <th>To</th>
              <th>Source</th>
              <th>Destination</th>
              <th>App</th>
              <th>Service</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in sortedPolicies" :key="(p.rule_number ?? p.name) + p.device_group"
                :class="{selected: selectedPolicy?.name === p.name && selectedPolicy?.device_group === p.device_group}"
                @click="selectedPolicy = p">
              <td><strong style="color:var(--primary)">{{ p.rule_number }}</strong></td>
              <td>{{ p.action === 'allow' ? '✅' : '🔴' }} {{ p.name }}</td>
              <td>{{ p.device_group }}</td>
              <td>{{ p.rulebase }}</td>
              <td><span class="badge" :class="p.action === 'allow' ? 'text-bg-success' : 'text-bg-danger'">{{ p.action?.toUpperCase() }}</span></td>
              <td>{{ (p.from_zones || []).join(', ') || '—' }}</td>
              <td>{{ (p.to_zones || []).join(', ') || '—' }}</td>
              <td>{{ fmtArr(p.source) }}</td>
              <td>{{ fmtArr(p.destination) }}</td>
              <td>{{ fmtArr(p.application) }}</td>
              <td>{{ fmtArr(p.service) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </template>
</div>`;

/* ── Mount helpers ───────────────────────────────────────────── */
function fmtArr(arr) {
  if (!arr || !arr.length) return '—';
  if (arr.includes('any')) return 'any';
  return arr.join(', ');
}

function mountLookup(pane) {
  if (pane._mounted) return;
  pane._mounted = true;
  pane.innerHTML = lookupTemplate;

  createApp({
    src: '', dst: '', port: '', proto: 'any',
    includeDisabled: false, showAll: true,
    deviceGroups: [], selectedDgs: [],
    dgOpen: false,
    loading: false, lookupError: null, noMatch: false,
    result: null, lastSrc: '', lastDst: '', lastPortLabel: '',
    selectedRule: null,
    sortCol: null, sortDir: 1,
    fmtArr,

    get allSelected() {
      return this.selectedDgs.length === 0 || this.selectedDgs.length === this.deviceGroups.length;
    },
    get dgLabel() {
      if (!this.selectedDgs.length || this.selectedDgs.length === this.deviceGroups.length)
        return 'All device groups';
      if (this.selectedDgs.length === 1) return this.selectedDgs[0];
      return `${this.selectedDgs.length} device groups`;
    },
    get sortedMatches() {
      if (!this.result?.matches) return [];
      if (!this.sortCol) return this.result.matches;
      const col = this.sortCol, dir = this.sortDir;
      return [...this.result.matches].sort((a, b) =>
        String(a[col] ?? '').localeCompare(String(b[col] ?? '')) * dir
      );
    },

    async init() {
      initCacheBar(
        document.getElementById('fw-cache-bar'),
        '/firewall/cache/info',
        '/firewall/cache/refresh',
        () => { this.result = null; this.selectedRule = null; }
      );
      try {
        const d = await API.get('/firewall/device-groups');
        this.deviceGroups = d.items || [];
      } catch {}
      // Close dropdown on outside click
      document.addEventListener('click', e => {
        if (!e.target.closest('.dg-select')) this.dgOpen = false;
      });
    },

    toggleAll(checked) {
      this.selectedDgs = checked ? [] : [];
      if (!checked) this.selectedDgs = [...this.deviceGroups];
    },

    sort(col) {
      if (this.sortCol === col) this.sortDir *= -1;
      else { this.sortCol = col; this.sortDir = 1; }
    },

    async doLookup() {
      const src = this.src.trim(), dst = this.dst.trim();
      if (!src || !dst) return;
      const port = this.port.trim();

      this.loading = true; this.lookupError = null;
      this.noMatch = false; this.result = null; this.selectedRule = null;
      this.lastSrc = src; this.lastDst = dst;
      this.lastPortLabel = port ? `:${port}` : ' (any port)';

      const body = {
        src_ip: src, dst_ip: dst,
        protocol: this.proto,
        dst_port: port ? parseInt(port) : null,
        device_groups: this.selectedDgs.length && this.selectedDgs.length < this.deviceGroups.length
          ? this.selectedDgs : [],
        include_disabled: this.includeDisabled,
        show_all: this.showAll,
      };
      try {
        const data = await API.post('/firewall/lookup', body);
        if (!data.match_count) { this.noMatch = true; this.result = data; return; }
        this.result = data;
        if (data.matches?.length) this.selectedRule = data.matches[0];
      } catch (e) {
        this.lookupError = e.message;
      } finally {
        this.loading = false;
      }
    },
  }).mount(pane.firstElementChild);
}

function mountByDevice(pane) {
  if (pane._mounted) return;
  pane._mounted = true;
  pane.innerHTML = byDeviceTemplate;

  createApp({
    devices: [],
    selectedSerial: '',
    devLoading: false, devError: null,
    vsysList: [], selectedVsys: '',
    policies: [], selectedPolicy: null,
    policiesLoading: false, policiesError: null,
    devSortCol: null, devSortDir: 1,
    fmtArr,

    get sortedPolicies() {
      if (!this.devSortCol) return this.policies;
      const col = this.devSortCol, dir = this.devSortDir;
      return [...this.policies].sort((a, b) =>
        String(a[col] ?? '').localeCompare(String(b[col] ?? '')) * dir
      );
    },

    async init() {
      initCacheBar(
        document.getElementById('fw-dev-cache-bar'),
        '/firewall/cache/info',
        '/firewall/cache/refresh',
        () => { this.policies = []; this.selectedPolicy = null; }
      );
      try {
        const d = await API.get('/firewall/devices');
        this.devices = d.items || [];
      } catch {}
    },

    async onDeviceChange() {
      const serial = this.selectedSerial;
      this.vsysList = []; this.selectedVsys = '';
      this.policies = []; this.selectedPolicy = null;
      this.devError = null;
      if (!serial) return;

      this.devLoading = true;
      try {
        const d = await API.get(`/firewall/device-vsys/${serial}`);
        this.vsysList = d.vsys || [];
        if (this.vsysList.length) {
          this.selectedVsys = this.vsysList[0];
          await this.loadPolicies();
        }
      } catch (e) {
        this.devError = e.message;
      } finally {
        this.devLoading = false;
      }
    },

    async onVsysChange() {
      this.policies = []; this.selectedPolicy = null;
      await this.loadPolicies();
    },

    async loadPolicies() {
      if (!this.selectedSerial || !this.selectedVsys) return;
      this.policiesLoading = true; this.policiesError = null;
      try {
        const d = await API.get(`/firewall/device-vsys-policies/${this.selectedSerial}/${this.selectedVsys}`);
        this.policies = d.policies || [];
        if (this.policies.length) this.selectedPolicy = this.policies[0];
      } catch (e) {
        this.policiesError = e.message;
      } finally {
        this.policiesLoading = false;
      }
    },

    sortDev(col) {
      if (this.devSortCol === col) this.devSortDir *= -1;
      else { this.devSortCol = col; this.devSortDir = 1; }
    },
  }).mount(pane.firstElementChild);
}

/* ── Public mount ────────────────────────────────────────────── */
export function mount(el) {
  el.innerHTML = shellTemplate;
  createApp({
    init() {
      // Mount lookup tab immediately
      mountLookup(document.getElementById('fw-lookup'));

      // Lazy-mount by-device tab on first show
      document.getElementById('fw-bydevice-tab').addEventListener('shown.bs.tab', () => {
        mountByDevice(document.getElementById('fw-bydevice'));
      });
    },
  }).mount(el.firstElementChild);
}
