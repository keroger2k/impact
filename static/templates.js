/* ============================================================
   IMPACT II — HTML Templates
   Pure functions: data in, HTML string out. No DOM access.
   Loaded before app.js so T is available globally.
   ============================================================ */

const T = {};

/* ── Utilities ─────────────────────────────────────────────── */

T.kvRow = (label, value, fullWidth = false) =>
  `<div class="kv-row${fullWidth ? ' kv-row-full' : ''}"><span class="kv-label">${label}</span><span class="kv-value">${value ?? '—'}</span></div>`;

T.reachBadge = (status) =>
  status === 'Reachable'
    ? '<span class="badge text-bg-success">✅ Reachable</span>'
    : `<span class="badge text-bg-danger">🔴 ${status || 'Unknown'}</span>`;

T.detailPlaceholder = () =>
  `<div class="detail-placeholder">
    <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" d="M8.25 6.75h7.5M8.25 12h7.5m-7.5 5.25h4.5M3.75 3h16.5a.75.75 0 01.75.75v16.5a.75.75 0 01-.75.75H3.75a.75.75 0 01-.75-.75V3.75A.75.75 0 013.75 3z"/>
    </svg>
    Select a row to view details
  </div>`;

T.makePagination = (page, totalPages, pageSize, total) => {
  if (totalPages <= 1) return '';
  const start = page * pageSize + 1;
  const end   = Math.min((page + 1) * pageSize, total);

  const show = new Set([0, totalPages - 1]);
  for (let i = Math.max(0, page - 2); i <= Math.min(totalPages - 1, page + 2); i++) show.add(i);
  const sorted = [...show].sort((a, b) => a - b);

  let btns = '', prev = -1;
  for (const p of sorted) {
    if (p - prev > 1) btns += `<span class="pagination-ellipsis">…</span>`;
    btns += `<button class="btn btn-outline-secondary btn-sm${p === page ? ' active' : ''}" data-page="${p}">${p + 1}</button>`;
    prev = p;
  }

  return `<div class="pagination">
    <button class="btn btn-outline-secondary btn-sm" data-page="${page - 1}" ${page === 0 ? 'disabled' : ''}>‹</button>
    ${btns}
    <button class="btn btn-outline-secondary btn-sm" data-page="${page + 1}" ${page >= totalPages - 1 ? 'disabled' : ''}>›</button>
    <span class="pagination-info">${start.toLocaleString()}–${end.toLocaleString()} of ${total.toLocaleString()}</span>
  </div>`;
};

/* ── Firewall helpers ──────────────────────────────────────── */

T.fmtList = (arr) => {
  if (!arr || !arr.length) return '—';
  if (arr.includes('any')) return '<span class="badge text-bg-secondary">any</span>';
  if (arr.length <= 2) return arr.join(', ');
  return `${arr.slice(0, 2).join(', ')} <span class="badge text-bg-secondary">+${arr.length - 2}</span>`;
};

T._resolvedRows = (names, resolved) => names
  .filter(n => n !== 'any')
  .flatMap(name => {
    const vals = resolved?.[name] || [];
    if (!vals.length) return [`<tr><td>${name}</td><td style="color:var(--text-secondary)">(unresolved)</td></tr>`];
    return vals.map(v => `<tr><td>${name}</td><td class="mono">${v}</td></tr>`);
  }).join('');

T._svcRows = (names, resolved) => names
  .filter(n => !['any', 'application-default'].includes(n))
  .flatMap(name => {
    const vals = resolved?.[name] || [];
    if (!vals.length) return [`<tr><td>${name}</td><td>—</td><td>—</td></tr>`];
    return vals.map(v => `<tr><td>${name}</td><td>${v.protocol?.toUpperCase()}</td><td class="mono">${v.ports}</td></tr>`);
  }).join('');

/* ── Device templates ──────────────────────────────────────── */

T.deviceDetailEmpty = () => `
  <div class="detail-panel" style="opacity:.6">
    <div class="detail-header">
      <span style="font-size:18px;opacity:.4">○</span>
      <div>
        <div class="detail-hostname" style="opacity:.5">No device selected</div>
        <div style="font-size:11px;opacity:.4">Select a row from the table below</div>
      </div>
    </div>
    <div class="detail-body">
      <div class="detail-grid">
        <div class="detail-section">
          <div class="detail-section-title">Identity</div>
          ${T.kvRow('Hostname', '—')}${T.kvRow('Management IP', '—')}${T.kvRow('Platform', '—')}
          ${T.kvRow('IOS Version', '—')}${T.kvRow('Serial', '—')}${T.kvRow('Vendor', '—')}${T.kvRow('Site', '—')}
        </div>
        <div class="detail-section">
          <div class="detail-section-title">Status</div>
          ${T.kvRow('Reachability', '—')}${T.kvRow('Role', '—')}${T.kvRow('Uptime', '—')}
          ${T.kvRow('Last Contact', '—')}${T.kvRow('Device ID', '—')}
        </div>
      </div>
    </div>
  </div>`;

T.deviceDetail = (device, dnacUrl) => `
  <div class="detail-panel">
    <div class="detail-header">
      <span style="font-size:18px">${device.reachabilityStatus === 'Reachable' ? '✅' : '🔴'}</span>
      <div>
        <div class="detail-hostname">${device.hostname || '—'}</div>
        <div style="font-size:11px;opacity:.7">${device.managementIpAddress} · ${device.platformId}</div>
      </div>
      <div class="ms-auto d-flex gap-2 align-items-center">
        <button class="btn btn-outline-secondary btn-sm" onclick="loadConfig('${device.id}','${device.hostname}')">📄 Config</button>
        <a class="btn btn-outline-secondary btn-sm" href="${dnacUrl}" target="_blank">🔗 Open in DNAC</a>
      </div>
    </div>
    <div class="detail-body">
      <div class="detail-grid">
        <div class="detail-section">
          <div class="detail-section-title">Identity</div>
          ${T.kvRow('Hostname', device.hostname)}
          ${T.kvRow('Management IP', `<code>${device.managementIpAddress}</code>`)}
          ${T.kvRow('Platform', device.platformId)}
          ${T.kvRow('IOS Version', device.softwareVersion)}
          ${T.kvRow('Serial', device.serialNumber)}
          ${T.kvRow('Vendor', device.vendor)}
          ${T.kvRow('Site', device.siteName)}
        </div>
        <div class="detail-section">
          <div class="detail-section-title">Status</div>
          ${T.kvRow('Reachability', T.reachBadge(device.reachabilityStatus))}
          ${T.kvRow('Role', device.role)}
          ${T.kvRow('Uptime', device.upTime)}
          ${T.kvRow('Last Contact', device.lastContactFormatted)}
          ${T.kvRow('Device ID', `<code style="font-size:10px">${device.id}</code>`)}
          ${device.reachabilityFailureReason ? T.kvRow('Failure', `<span class="badge text-bg-danger">${device.reachabilityFailureReason}</span>`) : ''}
        </div>
      </div>
      <div id="config-area-${device.id}"></div>
    </div>
  </div>`;

/* ── ISE templates ─────────────────────────────────────────── */

T.nadDetail = (d) => {
  const ips  = (d.NetworkDeviceIPList || []).map(e => `${e.ipaddress}/${e.mask}`).join(', ') || '—';
  const grps = (d.NetworkDeviceGroupList || []).join(', ') || '—';
  const rad  = d.authenticationSettings || {};
  const tac  = d.tacacsSettings || {};
  const snmp = d.snmpsettings || {};
  return `
  <div class="detail-panel">
    <div class="detail-header"><span class="detail-hostname">🖥️ ${d.name}</span></div>
    <div class="detail-body">
      <div class="detail-grid">
        <div class="detail-section">
          <div class="detail-section-title">Identity</div>
          ${T.kvRow('IP / Mask', ips)}
          ${T.kvRow('Profile', d.profileName)}
          ${T.kvRow('Model', d.modelName)}
          ${T.kvRow('Groups', grps)}
          ${T.kvRow('CoA Port', d.coaPort)}
        </div>
        <div class="detail-section">
          <div class="detail-section-title">RADIUS</div>
          ${T.kvRow('Protocol', rad.networkProtocol)}
          ${T.kvRow('Secret', rad.radiusSharedSecret ? '*** (set)' : 'Not set')}
          <div class="detail-section-title mt-3">TACACS</div>
          ${T.kvRow('Secret', tac.sharedSecret ? '*** (set)' : 'Not set')}
          ${T.kvRow('Connect Mode', tac.connectModeOptions)}
          <div class="detail-section-title mt-3">SNMP</div>
          ${T.kvRow('Version', snmp.version)}
          ${T.kvRow('Poll Interval', snmp.pollingInterval ? `${snmp.pollingInterval}s` : '—')}
        </div>
      </div>
    </div>
  </div>`;
};

T.endpointDetail = (d, ep) => {
  const mfc    = d.mfcAttributes || {};
  const mfcVal = k => { const v = mfc[k]; return Array.isArray(v) && v.length ? v[0] : '—'; };
  return `
  <div class="detail-panel">
    <div class="detail-header"><span class="detail-hostname">💻 ${d.mac || ep.name}</span></div>
    <div class="detail-body">
      <div class="detail-grid">
        <div class="detail-section">
          <div class="detail-section-title">Endpoint</div>
          ${T.kvRow('Portal User', d.portalUser)}
          ${T.kvRow('Identity Store', d.identityStore)}
          ${T.kvRow('Profile ID', d.profileId)}
          ${T.kvRow('Group ID', d.groupId)}
          ${T.kvRow('Static Profile', d.staticProfileAssignment)}
          ${T.kvRow('Static Group', d.staticGroupAssignment)}
        </div>
        <div class="detail-section">
          <div class="detail-section-title">MFC Profiler</div>
          ${T.kvRow('Endpoint Type', mfcVal('mfcDeviceType'))}
          ${T.kvRow('Manufacturer', mfcVal('mfcHardwareManufacturer'))}
          ${T.kvRow('Model', mfcVal('mfcHardwareModel'))}
          ${T.kvRow('Operating System', mfcVal('mfcOperatingSystem'))}
        </div>
      </div>
      <p style="font-size:11px;color:var(--text-secondary);margin-top:12px">
        ℹ️ Full authentication attributes (AAA-Server, AD-*, Posture) available once OpenAPI is enabled on ISE.
      </p>
    </div>
  </div>`;
};

/* ── Firewall templates ────────────────────────────────────── */

T.ruleDetail = (rule) => {
  const actionCss  = rule.action === 'allow' ? 'var(--success)' : 'var(--danger)';
  const hasSrc     = rule.source?.filter(n => n !== 'any').length;
  const hasDst     = rule.destination?.filter(n => n !== 'any').length;
  const hasSvc     = rule.service?.filter(n => !['any', 'application-default'].includes(n)).length;

  return `
  <div class="detail-panel">
    <div class="detail-header">
      <span style="font-size:18px">${rule.action === 'allow' ? '✅' : '🔴'}</span>
      <div>
        <div class="detail-hostname">${rule.first_match ? '⭐ ' : ''}${rule.name}</div>
        <div style="font-size:11px;opacity:.7">
          ${rule.device_group} · ${rule.rulebase}-rulebase${rule.disabled ? ' · DISABLED' : ''}
        </div>
      </div>
      <span class="action-badge action-${rule.action} ms-auto" style="padding:4px 12px;border-radius:3px;font-weight:700">${rule.action.toUpperCase()}</span>
    </div>
    <div class="detail-body">
      <div class="detail-grid">
        <div class="detail-section">
          <div class="detail-section-title">Traffic</div>
          ${T.kvRow('Source Zones', rule.from_zones?.join(', ') || '—')}
          ${T.kvRow('Source Addresses', T.fmtList(rule.source))}
          ${T.kvRow('Source Negate', rule.source_negate ? 'Yes' : 'No')}
          ${T.kvRow('Dest Zones', rule.to_zones?.join(', ') || '—')}
          ${T.kvRow('Dest Addresses', T.fmtList(rule.destination))}
          ${T.kvRow('Dest Negate', rule.dest_negate ? 'Yes' : 'No')}
        </div>
        <div class="detail-section">
          <div class="detail-section-title">Policy</div>
          ${T.kvRow('Application', T.fmtList(rule.application))}
          ${T.kvRow('Service', T.fmtList(rule.service))}
          ${T.kvRow('Security Profile', rule.profile_group)}
          ${T.kvRow('Log Setting', rule.log_setting)}
          ${T.kvRow('Tags', rule.tag?.join(', '))}
          ${T.kvRow('Description', rule.description)}
          ${T.kvRow('First Match', rule.first_match ? '<span class="badge text-bg-success">Yes — decides traffic</span>' : 'No')}
        </div>
      </div>
      ${hasSrc || hasDst || hasSvc ? `
      <hr class="divider">
      <div class="section-title mb-3">Resolved Objects</div>
      <div class="grid-3">
        ${hasSrc ? `
        <div>
          <div class="detail-section-title">Source Addresses</div>
          <table><thead><tr><th>Object</th><th>Resolves to</th></tr></thead>
          <tbody>${T._resolvedRows(rule.source, rule.resolved_source)}</tbody></table>
        </div>` : ''}
        ${hasDst ? `
        <div>
          <div class="detail-section-title">Destination Addresses</div>
          <table><thead><tr><th>Object</th><th>Resolves to</th></tr></thead>
          <tbody>${T._resolvedRows(rule.destination, rule.resolved_destination)}</tbody></table>
        </div>` : ''}
        ${hasSvc ? `
        <div>
          <div class="detail-section-title">Services</div>
          <table><thead><tr><th>Service</th><th>Proto</th><th>Port(s)</th></tr></thead>
          <tbody>${T._svcRows(rule.service, rule.resolved_service)}</tbody></table>
        </div>` : ''}
      </div>` : ''}
    </div>
  </div>`;
};

T.devicePolicyDetail = (policy) => `
  <div class="detail-panel">
    <div class="detail-header">
      <span style="font-size:18px">${policy.action === 'allow' ? '✅' : '🔴'}</span>
      <div>
        <div class="detail-hostname">
          <span style="color:var(--primary);font-weight:bold;margin-right:8px">Rule #${policy.rule_number || '—'}</span>
          ${policy.name}
        </div>
        <div style="font-size:11px;opacity:.7">
          ${policy.device_group} · ${policy.rulebase}-rulebase${policy.disabled ? ' · DISABLED' : ''}
        </div>
      </div>
      <span class="action-badge action-${policy.action} ms-auto" style="padding:4px 12px;border-radius:3px;font-weight:700">${policy.action.toUpperCase()}</span>
    </div>
    <div class="detail-body">
      <div class="detail-grid">
        <div class="detail-section">
          <div class="detail-section-title">Traffic & Zones</div>
          ${T.kvRow('From Zones', policy.from_zones?.length ? policy.from_zones.join(', ') : '—')}
          ${T.kvRow('To Zones', policy.to_zones?.length ? policy.to_zones.join(', ') : '—')}
          ${T.kvRow('Source Addresses', T.fmtList(policy.source))}
          ${T.kvRow('Source Negate', policy.source_negate ? 'Yes' : 'No')}
          ${T.kvRow('Destination Addresses', T.fmtList(policy.destination))}
          ${T.kvRow('Dest Negate', policy.dest_negate ? 'Yes' : 'No')}
        </div>
        <div class="detail-section">
          <div class="detail-section-title">Application & Services</div>
          ${T.kvRow('Application', T.fmtList(policy.application))}
          ${T.kvRow('Service', T.fmtList(policy.service))}
          ${T.kvRow('Category', T.fmtList(policy.category))}
        </div>
        <div class="detail-section">
          <div class="detail-section-title">Security & Logging</div>
          ${T.kvRow('Action', `<span class="badge text-bg-${policy.action === 'allow' ? 'success' : 'danger'}">${policy.action.toUpperCase()}</span>`)}
          ${T.kvRow('Security Profile', policy.profile_group || '—')}
          ${T.kvRow('HIP Profiles', T.fmtList(policy.hip_profiles))}
          ${T.kvRow('Log Start', policy.log_start ? '✓' : '—')}
          ${T.kvRow('Log End', policy.log_end ? '✓' : '—')}
          ${T.kvRow('Log Setting', policy.log_setting || '—')}
        </div>
        <div class="detail-section">
          <div class="detail-section-title">Advanced</div>
          ${T.kvRow('Source User', T.fmtList(policy.source_user))}
          ${T.kvRow('Source User Negate', policy.source_user_negate ? 'Yes' : 'No')}
          ${T.kvRow('Source Device', T.fmtList(policy.source_device))}
          ${T.kvRow('Source Device Negate', policy.source_device_negate ? 'Yes' : 'No')}
          ${T.kvRow('Dest Device', T.fmtList(policy.destination_device))}
          ${T.kvRow('Dest Device Negate', policy.destination_device_negate ? 'Yes' : 'No')}
          ${T.kvRow('Schedule', policy.schedule || '—')}
          ${T.kvRow('QoS Type', policy.qos_type || '—')}
          ${T.kvRow('Tags', policy.tag?.length ? policy.tag.join(', ') : '—')}
        </div>
      </div>
      ${T.kvRow('Description', policy.description || '(no description)', true)}
    </div>
  </div>`;

/* ── Command Runner templates ──────────────────────────────── */

T.outputDetail = (r) => `
  <div class="detail-panel">
    <div class="detail-header">
      <span>${r.status === 'success' ? '✅' : '❌'}</span>
      <span class="detail-hostname">${r.hostname} (${r.ip})</span>
      <span class="ms-auto" style="font-size:11px;opacity:.7">${r.elapsed}s · ${r.status}</span>
    </div>
    <div class="detail-body p-0">
      ${r.output ? `
        <div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;gap:8px">
          <input class="input" style="max-width:240px" id="out-filter" placeholder="Filter lines…">
          <button class="btn btn-outline-secondary btn-sm" onclick="dlText(document.getElementById('out-pre').textContent,'${r.hostname}_output.txt')">⬇️ Download</button>
        </div>
        <pre class="code-block" id="out-pre" style="border-radius:0;max-height:460px">${r._escapedOutput}</pre>` :
        `<div class="alert alert-danger m-3">${r.error}</div>`}
    </div>
  </div>`;
