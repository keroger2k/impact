import { createApp } from '/static/petite-vue.esm.js';
import { API }        from '/static/js/api.js';

const template = `
<div>
  <div v-if="loading" class="empty-state"><div class="spinner spinner-lg"></div></div>
  <div v-else-if="error" class="alert alert-danger">Failed to load dashboard: {{ error }}</div>
  <template v-else>
    <div class="kpi-row cols-4">
      <div class="kpi-card">
        <div class="kpi-label">Total Devices</div>
        <div class="kpi-value">{{ stats.total?.toLocaleString() ?? '—' }}</div>
      </div>
      <div class="kpi-card success">
        <div class="kpi-label">Reachable</div>
        <div class="kpi-value">{{ stats.reachable?.toLocaleString() ?? '—' }}</div>
        <div class="kpi-sub">{{ stats.pct_reachable ?? 0 }}% of inventory</div>
      </div>
      <div class="kpi-card danger">
        <div class="kpi-label">Unreachable</div>
        <div class="kpi-value">{{ stats.unreachable?.toLocaleString() ?? '—' }}</div>
        <div class="kpi-sub">
          <div class="progress-outer">
            <div class="progress-inner" :style="{ width: (stats.pct_reachable ?? 0) + '%' }"></div>
          </div>
        </div>
      </div>
      <div class="kpi-card teal">
        <div class="kpi-label">Systems Online</div>
        <div class="kpi-value">{{ systemsOnline }}/3</div>
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
              <tr v-for="row in (stats.platforms || [])">
                <td>{{ row[0] }}</td><td><strong>{{ row[1] }}</strong></td>
              </tr>
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
              <tr v-for="row in (stats.versions || [])">
                <td class="mono">{{ row[0] }}</td><td><strong>{{ row[1] }}</strong></td>
              </tr>
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
            <tr v-for="row in (stats.roles || [])">
              <td>{{ row[0] }}</td><td><strong>{{ row[1] }}</strong></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </template>
</div>`;

export function mount(el) {
  el.innerHTML = template;
  const comp = {
    loading: true,
    error:   null,
    stats:   null,
    status:  null,

    get systemsOnline() {
      if (!this.status) return 0;
      return [this.status.dnac, this.status.ise, this.status.panorama].filter(s => s?.ok).length;
    },

    async load() {
      try {
        const [stats, status] = await Promise.all([
          API.get('/dnac/devices/stats'),
          API.get('/status'),
        ]);
        this.stats  = stats;
        this.status = status;
      } catch(e) {
        this.error = e.message;
      } finally {
        this.loading = false;
      }
    },
  };
  createApp(comp).mount(el.firstElementChild);
  comp.load();
}
