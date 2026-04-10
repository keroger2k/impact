import { createApp } from '/static/petite-vue.esm.js';
import { API }        from '/static/js/api.js';
import { toast }      from '/static/js/utils.js';

const template = `
<div>
  <div class="card mb-4" style="max-width:700px">
    <div class="card-header"><span class="card-title">🔍 IP Address Lookup</span></div>
    <div class="card-body">
      <div class="input-row">
        <div class="form-group">
          <label class="form-label">IP Address</label>
          <input class="input" id="ip-input" v-model="ip" placeholder="e.g. 10.47.31.195"
                 @keydown.enter="lookup()">
        </div>
        <button class="btn btn-primary mt-5" @click="lookup()" :disabled="loading">Look up</button>
      </div>
    </div>
  </div>

  <div v-if="loading" class="empty-state"><div class="spinner spinner-lg"></div></div>
  <div v-else-if="error" class="alert alert-danger">{{ error }}</div>
  <div v-else-if="notFound" class="alert alert-warn">
    ⚠️ No interface found for <strong>{{ lastIp }}</strong> in DNAC.
    The address may be a secondary IP, loopback, or not yet synced.
  </div>

  <template v-else-if="results.length">
    <div v-for="r in results" class="grid-2 mb-4">
      <div class="card">
        <div class="card-header">
          <span class="card-title">🔌 Interface</span>
          <span style="color:var(--text-secondary);font-size:12px;margin-left:8px">{{ r.interface.portName }}</span>
        </div>
        <div class="card-body">
          <div class="kv-row"><span class="kv-label">IP Address</span><span class="kv-value"><code>{{ lastIp }}</code></span></div>
          <div class="kv-row"><span class="kv-label">Subnet</span><span class="kv-value">{{ r.interface.subnet || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">MAC Address</span><span class="kv-value">{{ r.interface.macAddress || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">VLAN</span><span class="kv-value">{{ r.interface.vlanId || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Description</span><span class="kv-value">{{ r.interface.description || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Admin Status</span><span class="kv-value">{{ r.interface.adminStatus || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Oper Status</span><span class="kv-value">{{ r.interface.operStatus || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Speed</span><span class="kv-value">{{ r.interface.speed || '—' }}</span></div>
        </div>
      </div>
      <div class="card">
        <div class="card-header">
          <span>{{ r.device.reachabilityStatus === 'Reachable' ? '✅' : '🔴' }}</span>
          <span class="card-title">{{ r.device.hostname || 'Unknown Device' }}</span>
        </div>
        <div class="card-body">
          <div class="kv-row"><span class="kv-label">Management IP</span><span class="kv-value"><code>{{ r.device.managementIpAddress }}</code></span></div>
          <div class="kv-row"><span class="kv-label">Platform</span><span class="kv-value">{{ r.device.platformId || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">IOS Version</span><span class="kv-value">{{ r.device.softwareVersion || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Serial</span><span class="kv-value">{{ r.device.serialNumber || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Role</span><span class="kv-value">{{ r.device.role || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Site</span><span class="kv-value">{{ r.siteName || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Uptime</span><span class="kv-value">{{ r.device.upTime || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Last Contact</span><span class="kv-value">{{ r.device.lastContactFormatted || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Reachability</span><span class="kv-value">
            <span class="badge" :class="r.device.reachabilityStatus === 'Reachable' ? 'text-bg-success' : 'text-bg-danger'">
              {{ r.device.reachabilityStatus || 'Unknown' }}
            </span>
          </span></div>
        </div>
      </div>
    </div>
  </template>
</div>`;

export function mount(el) {
  el.innerHTML = template;
  const comp = {
    ip:       '',
    lastIp:   '',
    loading:  false,
    error:    null,
    notFound: false,
    results:  [],

    focus() {
      document.getElementById('ip-input')?.focus();
    },

    async lookup() {
      const ip = this.ip.trim();
      if (!ip) return;
      this.loading  = true;
      this.error    = null;
      this.notFound = false;
      this.results  = [];
      this.lastIp   = ip;
      try {
        const data = await API.get(`/dnac/ip-lookup/${encodeURIComponent(ip)}`);
        if (!data.found) { this.notFound = true; return; }
        this.results = data.interfaces;
      } catch(e) {
        this.error = e.message;
      } finally {
        this.loading = false;
      }
    },
  };
  createApp(comp).mount(el.firstElementChild);
  comp.focus();
}
