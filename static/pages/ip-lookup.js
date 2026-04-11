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
    ⚠️ No interface found for <strong>{{ lastIp }}</strong> in DNAC or Palo Alto.
    The address may be a secondary IP, loopback, or not yet synced.
    <span v-if="panCacheEmpty"> Palo Alto interface cache is not loaded — visit Firewall → Interfaces to populate it.</span>
  </div>

  <template v-else-if="results.length || firewallResults.length">

    <!-- DNAC results -->
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
          <span>{{ r.device && r.device.reachabilityStatus === 'Reachable' ? '✅' : '🔴' }}</span>
          <span class="card-title">{{ r.device && r.device.hostname || 'Unknown Device' }}</span>
        </div>
        <div class="card-body">
          <div class="kv-row"><span class="kv-label">Management IP</span><span class="kv-value"><code>{{ r.device && r.device.managementIpAddress }}</code></span></div>
          <div class="kv-row"><span class="kv-label">Platform</span><span class="kv-value">{{ r.device && r.device.platformId || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">IOS Version</span><span class="kv-value">{{ r.device && r.device.softwareVersion || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Serial</span><span class="kv-value">{{ r.device && r.device.serialNumber || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Role</span><span class="kv-value">{{ r.device && r.device.role || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Site</span><span class="kv-value">{{ r.siteName || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Uptime</span><span class="kv-value">{{ r.device && r.device.upTime || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Last Contact</span><span class="kv-value">{{ r.device && r.device.lastContactFormatted || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Reachability</span><span class="kv-value">
            <span class="badge" :class="r.device && r.device.reachabilityStatus === 'Reachable' ? 'text-bg-success' : 'text-bg-danger'">
              {{ r.device && r.device.reachabilityStatus || 'Unknown' }}
            </span>
          </span></div>
        </div>
      </div>
    </div>

    <!-- Palo Alto firewall results -->
    <div v-for="fw in firewallResults" class="grid-2 mb-4">
      <div class="card">
        <div class="card-header">
          <span class="card-title">🔥 Firewall Interface</span>
          <span style="color:var(--text-secondary);font-size:12px;margin-left:8px">{{ fw.interface }}</span>
        </div>
        <div class="card-body">
          <div class="kv-row"><span class="kv-label">IP Address</span><span class="kv-value"><code>{{ fw.ipv4 || lastIp }}</code></span></div>
          <div class="kv-row" v-if="fw.ipv6 && fw.ipv6.length">
            <span class="kv-label">IPv6</span>
            <span class="kv-value">
              <div v-for="a in fw.ipv6"><code>{{ a }}</code></div>
            </span>
          </div>
          <div class="kv-row"><span class="kv-label">Interface</span><span class="kv-value">{{ fw.interface || '—' }}</span></div>
        </div>
      </div>
      <div class="card">
        <div class="card-header">
          <span>🛡️</span>
          <span class="card-title">{{ fw.hostname || 'Unknown Firewall' }}</span>
        </div>
        <div class="card-body">
          <div class="kv-row"><span class="kv-label">Management IP</span><span class="kv-value"><code>{{ fw.management_ip || '—' }}</code></span></div>
          <div class="kv-row"><span class="kv-label">Serial</span><span class="kv-value">{{ fw.serial || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Model</span><span class="kv-value">{{ fw.model || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">Device Group</span><span class="kv-value">{{ fw.device_group || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">PAN-OS</span><span class="kv-value">{{ fw.os_version || '—' }}</span></div>
          <div class="kv-row"><span class="kv-label">HA State</span><span class="kv-value">
            <span v-if="fw.ha_state" class="badge" :class="fw.ha_state === 'active' ? 'text-bg-success' : 'text-bg-secondary'">
              {{ fw.ha_state }}
            </span>
            <span v-else>—</span>
          </span></div>
          <div class="kv-row"><span class="kv-label">Source</span><span class="kv-value">
            <span class="badge text-bg-warning">Palo Alto</span>
          </span></div>
        </div>
      </div>
    </div>

  </template>
</div>`;

export function mount(el) {
  el.innerHTML = template;
  const alive = () => el.isConnected;
  const comp = {
    ip:              '',
    lastIp:          '',
    loading:         false,
    error:           null,
    notFound:        false,
    panCacheEmpty:   false,
    results:         [],
    firewallResults: [],

    focus() {
      document.getElementById('ip-input')?.focus();
    },

    async lookup() {
      const ip = this.ip.trim();
      if (!ip) return;
      this.loading         = true;
      this.error           = null;
      this.notFound        = false;
      this.panCacheEmpty   = false;
      this.results         = [];
      this.firewallResults = [];
      this.lastIp          = ip;
      try {
        const data = await API.get(`/dnac/ip-lookup/${encodeURIComponent(ip)}`);
        if (!alive()) return;
        if (!data.found) {
          this.notFound      = true;
          this.panCacheEmpty = !(data.firewall_interfaces?.length > 0);
          return;
        }
        this.results         = data.interfaces        || [];
        this.firewallResults = data.firewall_interfaces || [];
      } catch(e) {
        if (!alive()) return;
        this.error = e.message;
      } finally {
        if (alive()) this.loading = false;
      }
    },
  };
  createApp(comp).mount(el.firstElementChild);
  comp.focus();
}
