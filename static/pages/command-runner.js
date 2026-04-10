import { createApp } from '/static/petite-vue.esm.js';
import { API }        from '/static/js/api.js';
import { toast, dlText } from '/static/js/utils.js';

const QUICK_CMDS = [
  '— Quick commands —', 'show version', 'show ip interface brief', 'show interfaces',
  'show ip route summary', 'show ip bgp summary', 'show cdp neighbors', 'show dmvpn',
  'show crypto session', 'show access-lists', 'show logging', 'show ntp status',
  'show processes cpu sorted | head 20', 'show spanning-tree summary',
  'show ip ospf neighbor', 'show ip eigrp neighbors',
];

const template = `
<div>
  <div class="grid-2 gap-4 items-start">
    <!-- Step 1 — Devices -->
    <div>
      <div class="card mb-4">
        <div class="card-header"><span class="card-title">Step 1 — Devices</span></div>
        <div class="card-body">
          <div class="tabs mb-3">
            <div class="tab" :class="{active: inputTab==='paste'}" @click="inputTab='paste'">Paste IPs</div>
            <div class="tab" :class="{active: inputTab==='filter'}" @click="inputTab='filter'">Filter from DNAC</div>
          </div>

          <div v-if="inputTab==='paste'">
            <textarea class="textarea" v-model="pasteIps"
              placeholder="One IP per line, or comma-separated&#10;10.12.4.1&#10;10.14.1.2"
              style="min-height:120px"></textarea>
            <button class="btn btn-outline-secondary btn-sm mt-2" @click="parseIpList()">Parse IP list</button>
          </div>

          <div v-else>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px">
              <input class="input" v-model="filter.hostname" placeholder="Hostname…">
              <input class="input" v-model="filter.ip" placeholder="IP…">
              <input class="input" v-model="filter.platform" placeholder="Platform…">
              <select class="select" v-model="filter.reachability">
                <option value="">All</option>
                <option value="reachable">Reachable</option>
                <option value="unreachable">Unreachable</option>
              </select>
            </div>
            <button class="btn btn-outline-secondary btn-sm" @click="filterDevices()" :disabled="filterLoading">
              {{ filterLoading ? 'Loading…' : 'Apply filter' }}
            </button>
          </div>
        </div>
      </div>

      <div class="card mb-4">
        <div class="card-header">
          <span class="card-title">Selected Devices</span>
          <span class="table-count">{{ devices.length }} selected</span>
        </div>
        <div style="max-height:220px;overflow-y:auto">
          <div v-if="!devices.length" class="empty-state p-5" style="padding:20px">No devices selected yet.</div>
          <table v-else class="table table-sm table-striped mb-0">
            <thead class="table-dark"><tr><th>Hostname</th><th>IP</th><th>Platform</th></tr></thead>
            <tbody>
              <tr v-for="d in devices" :key="d.ip">
                <td>{{ d.hostname }}</td>
                <td class="mono">{{ d.ip }}</td>
                <td>{{ d.platform || '—' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Step 2 + 3 -->
    <div>
      <div class="card mb-4">
        <div class="card-header"><span class="card-title">Step 2 — Command</span></div>
        <div class="card-body">
          <div class="form-group">
            <label class="form-label">Quick commands</label>
            <select class="select" v-model="quickCmd" @change="onQuickCmd()">
              <option v-for="c in quickCmds" :key="c">{{ c }}</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Command</label>
            <input class="input" v-model="cmd" placeholder="e.g. show ip interface brief"
                   @keydown.enter="run()">
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Step 3 — Settings</span></div>
        <div class="card-body">
          <div class="grid-2 gap-3">
            <div class="form-group m-0">
              <label class="form-label">Device type</label>
              <select class="select" v-model="deviceType">
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
              <input class="input" type="number" v-model.number="workers" min="1" max="30">
            </div>
            <div class="form-group m-0">
              <label class="form-label">Timeout (s)</label>
              <input class="input" type="number" v-model.number="timeout" min="10" max="120">
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="mt-4 d-flex gap-3 align-items-center">
    <button class="btn btn-primary" @click="run()" :disabled="running">▶ Run</button>
    <span style="font-size:12px;color:var(--text-secondary)">{{ runStatus }}</span>
  </div>

  <!-- Progress -->
  <div v-if="running || logs.length" class="mt-4">
    <div class="progress-outer"><div class="progress-inner" :style="{width: progPct + '%'}"></div></div>
    <div class="progress-label">{{ progLabel }}</div>
    <div class="log-stream mt-2" style="max-height:200px;overflow-y:auto" ref="logEl">
      <div v-for="(l, i) in logs" :key="i" class="log-line" :class="l.level">
        <span class="log-time">{{ l.ts }}</span>
        <span class="log-msg">{{ l.msg }}</span>
      </div>
    </div>
  </div>

  <!-- Results -->
  <template v-if="results.length && !running">
    <div class="kpi-row cols-4 mb-4 mt-4">
      <div class="kpi-card">
        <div class="kpi-label">Total</div>
        <div class="kpi-value">{{ results.length }}</div>
      </div>
      <div class="kpi-card success">
        <div class="kpi-label">Succeeded</div>
        <div class="kpi-value">{{ results.filter(r=>r.status==='success').length }}</div>
      </div>
      <div class="kpi-card danger">
        <div class="kpi-label">Failed</div>
        <div class="kpi-value">{{ results.filter(r=>r.status!=='success').length }}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Avg Time</div>
        <div class="kpi-value">{{ avgTime }}s</div>
      </div>
    </div>

    <!-- Output detail panel -->
    <div v-if="!selectedResult" class="detail-placeholder">
      <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round"
          d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3M5.25 4.5h13.5A2.25 2.25 0 0121 6.75v10.5A2.25 2.25 0 0118.75 19.5H5.25A2.25 2.25 0 013 17.25V6.75A2.25 2.25 0 015.25 4.5z"/>
      </svg>
      Select a row to view output
    </div>
    <div v-else class="detail-panel mb-3">
      <div class="detail-header">
        <span>{{ selectedResult.status === 'success' ? '✅' : '❌' }}</span>
        <div>
          <div class="detail-hostname">{{ selectedResult.hostname }}</div>
          <div style="font-size:11px;opacity:.7">{{ selectedResult.ip }} · {{ selectedResult.elapsed }}s</div>
        </div>
        <div class="ms-auto d-flex gap-2 align-items-center">
          <input class="input" v-model="outFilter" placeholder="Filter lines…" style="width:200px">
          <button class="btn btn-outline-secondary btn-sm" @click="downloadDevice()">⬇️ Download</button>
        </div>
      </div>
      <div class="detail-body">
        <pre class="code-block" v-text="filteredOutput"></pre>
      </div>
    </div>

    <!-- Results table -->
    <div class="table-wrap">
      <div class="table-toolbar">
        <span class="table-count">Click a row to view output</span>
        <button class="btn btn-outline-secondary btn-sm ms-auto" @click="downloadAll()">⬇️ Download All</button>
        <button class="btn btn-outline-secondary btn-sm" @click="downloadCsv()">⬇️ CSV</button>
      </div>
      <table class="table table-striped table-hover table-sm">
        <thead class="table-dark">
          <tr>
            <th @click="sort('hostname')"  :class="{sorted:sortCol==='hostname'}">Hostname <span class="sort-arrow">↕</span></th>
            <th @click="sort('ip')"        :class="{sorted:sortCol==='ip'}">IP <span class="sort-arrow">↕</span></th>
            <th @click="sort('platform')"  :class="{sorted:sortCol==='platform'}">Platform <span class="sort-arrow">↕</span></th>
            <th @click="sort('status')"    :class="{sorted:sortCol==='status'}">Status <span class="sort-arrow">↕</span></th>
            <th @click="sort('elapsed')"   :class="{sorted:sortCol==='elapsed'}">Time (s) <span class="sort-arrow">↕</span></th>
            <th>Lines</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in sortedResults" :key="r.ip"
              :class="{selected: selectedResult?.ip === r.ip}"
              @click="selectedResult = r; outFilter = ''">
            <td>{{ r.status === 'success' ? '✅' : '❌' }} {{ r.hostname }}</td>
            <td class="mono">{{ r.ip }}</td>
            <td>{{ r.platform }}</td>
            <td>{{ r.status }}</td>
            <td>{{ r.elapsed }}</td>
            <td>{{ r.output ? r.output.split('\\n').length : 0 }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>
</div>`;

export function mount(el) {
  el.innerHTML = template;
  createApp({
    quickCmds: QUICK_CMDS,
    quickCmd:  QUICK_CMDS[0],
    cmd:       '',
    inputTab:  'paste',
    pasteIps:  '',
    filter:    { hostname: '', ip: '', platform: '', reachability: '' },
    filterLoading: false,
    devices:   [],
    deviceType: 'auto',
    workers:   10,
    timeout:   30,
    running:   false,
    runStatus: '',
    progPct:   0,
    progLabel: '',
    logs:      [],
    results:   [],
    selectedResult: null,
    outFilter: '',
    sortCol:   null,
    sortDir:   1,

    get avgTime() {
      if (!this.results.length) return '0.0';
      return (this.results.reduce((s, r) => s + (r.elapsed || 0), 0) / this.results.length).toFixed(1);
    },
    get filteredOutput() {
      if (!this.selectedResult?.output) return this.selectedResult?.error || '';
      if (!this.outFilter) return this.selectedResult.output;
      const q = this.outFilter.toLowerCase();
      return this.selectedResult.output.split('\n').filter(l => l.toLowerCase().includes(q)).join('\n');
    },
    get sortedResults() {
      if (!this.sortCol) return this.results;
      const col = this.sortCol, dir = this.sortDir;
      return [...this.results].sort((a, b) =>
        String(a[col] ?? '').localeCompare(String(b[col] ?? ''), undefined, { numeric: true }) * dir
      );
    },

    init() {},

    onQuickCmd() {
      if (this.quickCmd !== QUICK_CMDS[0]) this.cmd = this.quickCmd;
    },

    async parseIpList() {
      const ips = this.pasteIps.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
      if (!ips.length) return;
      let dnacDevices = [];
      try {
        const d = await API.get('/dnac/devices?limit=500');
        dnacDevices = d.items;
      } catch {}
      const ipMap = {};
      dnacDevices.forEach(d => { ipMap[d.managementIpAddress] = d; });
      this.devices = ips.map(ip => ({
        ip, hostname: ipMap[ip]?.hostname || ip, platform: ipMap[ip]?.platformId || '',
      }));
    },

    async filterDevices() {
      this.filterLoading = true;
      const params = new URLSearchParams({
        hostname: this.filter.hostname, ip: this.filter.ip,
        platform: this.filter.platform, reachability: this.filter.reachability,
        limit: 500,
      });
      try {
        const d = await API.get(`/dnac/devices?${params}`);
        this.devices = d.items.map(dev => ({
          ip: dev.managementIpAddress, hostname: dev.hostname, platform: dev.platformId,
        }));
      } catch (e) { toast(e.message, 'error'); }
      finally { this.filterLoading = false; }
    },

    sort(col) {
      if (this.sortCol === col) this.sortDir *= -1;
      else { this.sortCol = col; this.sortDir = 1; }
    },

    run() {
      if (!this.devices.length) { toast('Select devices first', 'warn'); return; }
      if (!this.cmd.trim()) { toast('Enter a command', 'warn'); return; }

      this.results = []; this.logs = []; this.selectedResult = null;
      this.running = true; this.progPct = 0; this.progLabel = 'Starting…';
      this.runStatus = '';

      const body = {
        devices: this.devices,
        command: this.cmd.trim(),
        device_type_override: this.deviceType === 'auto' ? null : this.deviceType,
        max_workers: this.workers,
        timeout: this.timeout,
      };

      const logLine = (msg, level = 'info') => {
        this.logs.push({ ts: new Date().toLocaleTimeString(), msg, level });
        // Auto-scroll log
        this.$nextTick?.(() => {
          const logEl = document.querySelector('.log-stream');
          if (logEl) logEl.scrollTop = logEl.scrollHeight;
        });
      };

      API.stream('/commands/run', body, ev => {
        if (ev.type === 'progress') {
          this.results.push(ev);
          const pct = Math.round((ev.done / ev.total) * 100);
          this.progPct = pct;
          this.progLabel = `${ev.done}/${ev.total} complete`;
          const icon = ev.status === 'success' ? '✅' : '❌';
          logLine(`${icon} ${ev.hostname} (${ev.ip}) — ${ev.status} in ${ev.elapsed}s`,
            ev.status === 'success' ? 'success' : 'error');
        } else if (ev.type === 'complete') {
          this.running = false;
          this.runStatus = `Done — ${this.results.filter(r => r.status === 'success').length}/${this.results.length} succeeded`;
        } else if (ev.type === 'error') {
          logLine(`Error: ${ev.message}`, 'error');
        }
      }, () => { this.running = false; });
    },

    downloadDevice() {
      if (!this.selectedResult) return;
      const r = this.selectedResult;
      const text = `Device: ${r.hostname} (${r.ip})\nCommand: ${this.cmd}\n${'='.repeat(60)}\n` +
        (r.output || `ERROR: ${r.error}`);
      dlText(text, `${r.hostname}_output.txt`);
    },

    downloadAll() {
      const text = this.results.map(r =>
        `${'='.repeat(60)}\nDevice: ${r.hostname} (${r.ip})\nStatus: ${r.status} | Time: ${r.elapsed}s\n${'='.repeat(60)}\n` +
        (r.output || `ERROR: ${r.error}`)
      ).join('\n\n');
      dlText(text, `command_output_${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.txt`);
    },

    downloadCsv() {
      const header = 'Hostname,IP,Platform,Status,Time_s,Error\n';
      const rows = this.results.map(r =>
        [r.hostname, r.ip, r.platform, r.status, r.elapsed, r.error||'']
          .map(v => `"${v}"`).join(',')
      ).join('\n');
      dlText(header + rows, 'command_summary.csv');
    },
  }).mount(el.firstElementChild);
}
