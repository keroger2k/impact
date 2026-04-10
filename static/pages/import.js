import { createApp } from '/static/petite-vue.esm.js';
import { API }        from '/static/js/api.js';


/* ── Discovery & Import tab ───────────────────────────────────── */
const discoveryTemplate = `
<div>
  <div class="card mb-4">
    <div class="card-header"><span class="card-title">Device Discovery &amp; Import</span></div>
    <div class="card-body">
      <div class="alert alert-warning mb-4">
        ⚠️ <strong>Write operation.</strong> This discovers and assigns devices in Catalyst Center.
      </div>
      <div class="form-group">
        <label class="form-label">Device list (site_code,ip_address — one per line)</label>
        <textarea class="textarea" v-model="raw" style="min-height:140px"
          placeholder="# One entry per line&#10;ATL-T1,10.16.1.1&#10;DFW-T1,10.12.4.1"></textarea>
      </div>
      <div class="grid-2 gap-3 mb-3">
        <div class="form-group m-0">
          <label class="form-label">CLI Username</label>
          <input class="input" v-model="cliUser">
        </div>
        <div class="form-group m-0">
          <label class="form-label">SNMP Username</label>
          <input class="input" v-model="snmpUser">
        </div>
      </div>
      <button class="btn btn-outline-secondary btn-sm" @click="preview()">Preview</button>
    </div>
  </div>

  <!-- Preview table -->
  <div v-if="entries.length" class="card mb-4">
    <div class="card-header d-flex justify-content-between align-items-center">
      <span class="card-title">Preview — {{ entries.length }} entries</span>
      <div class="d-flex gap-2 align-items-center">
        <div class="form-check mb-0">
          <input type="checkbox" class="form-check-input" id="imp-confirm" v-model="confirmed">
          <label class="form-check-label" for="imp-confirm" style="font-size:13px">
            I confirm I want to run this import
          </label>
        </div>
        <button class="btn btn-primary btn-sm" @click="runImport()" :disabled="!confirmed || running">
          🚀 Run Import
        </button>
      </div>
    </div>
    <div class="card-body p-0">
      <table class="table table-sm table-striped table-hover mb-0">
        <thead class="table-dark"><tr><th>Site Code</th><th>IP Address</th><th>Valid</th></tr></thead>
        <tbody>
          <tr v-for="(e, i) in entries" :key="i">
            <td>{{ e.site || '—' }}</td>
            <td class="mono" style="font-size:12px">{{ e.ip || '—' }}</td>
            <td>
              <span v-if="e.valid" class="badge text-bg-success">✅</span>
              <span v-else class="badge text-bg-danger">❌</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Progress -->
  <div v-if="running || logs.length" class="mb-4">
    <div class="progress-outer"><div class="progress-inner" :style="{width: progPct + '%'}"></div></div>
    <div class="progress-label">{{ progLabel }}</div>
    <div class="log-stream mt-2" style="max-height:200px;overflow-y:auto">
      <div v-for="(l, i) in logs" :key="i" class="log-line" :class="l.level">
        <span class="log-time">{{ l.ts }}</span>
        <span class="log-msg">{{ l.msg }}</span>
      </div>
    </div>
  </div>

  <!-- Results -->
  <template v-if="importResult">
    <div class="kpi-row cols-4 mb-4">
      <div class="kpi-card">
        <div class="kpi-label">Total</div>
        <div class="kpi-value">{{ importResult.total }}</div>
      </div>
      <div class="kpi-card success">
        <div class="kpi-label">Discovered</div>
        <div class="kpi-value">{{ importResult.discovered }}</div>
      </div>
      <div class="kpi-card warn">
        <div class="kpi-label">Skipped</div>
        <div class="kpi-value">{{ importResult.skipped }}</div>
      </div>
      <div class="kpi-card danger">
        <div class="kpi-label">Failed</div>
        <div class="kpi-value">{{ (importResult.failed || 0) + (importResult.no_site || 0) }}</div>
      </div>
    </div>
    <div class="table-wrap">
      <table class="table table-sm table-striped table-hover">
        <thead class="table-dark"><tr><th>IP</th><th>Site</th><th>Outcome</th></tr></thead>
        <tbody>
          <tr v-for="r in importResult.results" :key="r.ip">
            <td class="mono" style="font-size:12px">{{ r.ip }}</td>
            <td>{{ r.site }}</td>
            <td>
              <span class="badge"
                :class="r.outcome === 'discovered' ? 'text-bg-success' : r.outcome === 'skipped_exists' ? 'text-bg-secondary' : 'text-bg-danger'">
                {{ r.outcome }}
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>
</div>`;

/* ── Tag Devices tab ──────────────────────────────────────────── */
const tagTemplate = `
<div>
  <div class="card mb-4">
    <div class="card-header"><span class="card-title">Tag Devices</span></div>
    <div class="card-body">
      <div class="alert alert-warning mb-4">
        ⚠️ <strong>Write operation.</strong> This applies a tag to devices in Catalyst Center.
      </div>
      <div class="form-group">
        <label class="form-label">Tag Name</label>
        <input class="input" v-model="tagName" placeholder="e.g. CRITICAL-INFRA" style="max-width:300px">
      </div>
      <div class="form-group">
        <label class="form-label">IP Addresses (one per line)</label>
        <textarea class="textarea" v-model="tagIps" style="min-height:140px"
          placeholder="10.16.1.1&#10;10.12.4.1&#10;10.14.1.2"></textarea>
      </div>
      <button class="btn btn-primary btn-sm" @click="applyTag()" :disabled="running">🏷️ Apply Tag</button>
    </div>
  </div>

  <!-- Progress -->
  <div v-if="running || logs.length" class="mb-4">
    <div class="log-stream" style="max-height:200px;overflow-y:auto">
      <div v-for="(l, i) in logs" :key="i" class="log-line" :class="l.level">
        <span class="log-time">{{ l.ts }}</span>
        <span class="log-msg">{{ l.msg }}</span>
      </div>
    </div>
  </div>

  <!-- Results -->
  <template v-if="tagResult">
    <div class="kpi-row cols-2 mb-4">
      <div class="kpi-card success">
        <div class="kpi-label">Tagged</div>
        <div class="kpi-value">{{ tagResult.tagged }}</div>
      </div>
      <div class="kpi-card warn">
        <div class="kpi-label">Not Found</div>
        <div class="kpi-value">{{ tagResult.skipped }}</div>
      </div>
    </div>
    <div v-if="tagResult.tagged" class="table-wrap">
      <table class="table table-sm table-striped table-hover">
        <thead class="table-dark"><tr><th>Hostname</th><th>IP</th><th>Tag</th></tr></thead>
        <tbody>
          <tr v-for="r in tagResult.results" :key="r.ip">
            <td>{{ r.hostname }}</td>
            <td class="mono" style="font-size:12px">{{ r.ip }}</td>
            <td><span class="badge text-bg-info">{{ tagResult.tag_name }}</span></td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>
</div>`;

/* ── Shell (Bootstrap tabs) ──────────────────────────────────── */
const shellTemplate = `
<div>
  <ul class="nav nav-tabs mb-3" role="tablist">
    <li class="nav-item" role="presentation">
      <button class="nav-link active" id="mgmt-discovery-tab" data-bs-toggle="tab"
              data-bs-target="#mgmt-discovery" type="button" role="tab">Discovery &amp; Import</button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="mgmt-tag-tab" data-bs-toggle="tab"
              data-bs-target="#mgmt-tag" type="button" role="tab">Tag Devices</button>
    </li>
  </ul>
  <div class="tab-content">
    <div class="tab-pane fade show active" id="mgmt-discovery" role="tabpanel"></div>
    <div class="tab-pane fade"             id="mgmt-tag"       role="tabpanel"></div>
  </div>
</div>`;

/* ── Mount helpers ───────────────────────────────────────────── */
function mountDiscovery(pane) {
  if (pane._mounted) return;
  pane._mounted = true;
  pane.innerHTML = discoveryTemplate;

  createApp({
    raw: '', cliUser: 'dnac-acct', snmpUser: 'tsa_mon_user',
    entries: [], confirmed: false,
    running: false, progPct: 0, progLabel: '',
    logs: [], importResult: null,

    init() {},

    preview() {
      const lines = this.raw.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
      this.entries = lines.map(l => {
        const [site, ip] = l.split(',').map(s => s.trim());
        return { site, ip, valid: !!(site && ip) };
      });
      this.confirmed = false;
      this.importResult = null;
    },

    runImport() {
      const valid = this.entries.filter(e => e.valid);
      if (!valid.length) return;
      this.running = true; this.logs = []; this.progPct = 0;
      this.progLabel = 'Starting…'; this.importResult = null;

      const log = (msg, level = 'info') => {
        this.logs.push({ ts: new Date().toLocaleTimeString(), msg, level });
      };

      const body = {
        entries: valid.map(e => ({ site_code: e.site, ip: e.ip })),
        cli_username: this.cliUser,
        snmp_username: this.snmpUser,
      };

      API.stream('/import/run', body, ev => {
        if (ev.type === 'log') {
          log(ev.message, ev.level);
        } else if (ev.type === 'progress') {
          this.progPct = ev.pct;
          this.progLabel = `${ev.done}/${ev.total} processed`;
        } else if (ev.type === 'complete') {
          this.progPct = 100;
          this.progLabel = 'Complete';
          this.running = false;
          this.importResult = ev;
        } else if (ev.type === 'error') {
          log(`Error: ${ev.message}`, 'error');
        }
      }, () => { this.running = false; });
    },
  }).mount(pane.firstElementChild);
}

function mountTag(pane) {
  if (pane._mounted) return;
  pane._mounted = true;
  pane.innerHTML = tagTemplate;

  createApp({
    tagName: '', tagIps: '',
    running: false, logs: [], tagResult: null,

    init() {},

    applyTag() {
      const tagName = this.tagName.trim();
      const ips = this.tagIps.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
      if (!tagName) { alert('Please enter a tag name.'); return; }
      if (!ips.length) { alert('Please enter at least one IP address.'); return; }

      this.running = true; this.logs = []; this.tagResult = null;

      const log = (msg, level = 'info') => {
        this.logs.push({ ts: new Date().toLocaleTimeString(), msg, level });
      };

      API.stream('/dnac/tag-devices', { tag_name: tagName, ips }, ev => {
        if (ev.type === 'log') {
          log(ev.message, ev.level);
        } else if (ev.type === 'complete') {
          this.running = false;
          this.tagResult = ev;
        } else if (ev.type === 'error') {
          log(`Error: ${ev.message}`, 'error');
        }
      }, () => { this.running = false; });
    },
  }).mount(pane.firstElementChild);
}

/* ── Public mount ────────────────────────────────────────────── */
export function mount(el) {
  el.innerHTML = shellTemplate;
  const shellComp = {
    init() {
      mountDiscovery(document.getElementById('mgmt-discovery'));
      document.getElementById('mgmt-tag-tab').addEventListener('shown.bs.tab', () => {
        mountTag(document.getElementById('mgmt-tag'));
      });
    },
  };
  createApp(shellComp).mount(el.firstElementChild);
  shellComp.init();
}
