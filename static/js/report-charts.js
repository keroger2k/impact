/* static/js/report-charts.js — inline-SVG chart renderers for the Reports pages.
 *
 * Extracted from templates/pages/reports_bandwidth_content.html, which had
 * grown ~700 lines of inline chart code. Page-specific glue (form handling,
 * fetches, result wiring) stays in the template; anything reusable lives here.
 *
 * Exposed as window.ImpactReportCharts. Loaded from base.html rather than the
 * page partial so it isn't re-fetched on every htmx swap into #main-content.
 *
 * Two chart types:
 *   renderBandwidthChart  — dual line chart, percent utilization (SolarWinds)
 *   renderStackedBarChart — stacked bars, per-application bps (SNA)
 *
 * TIMEZONES: the two sources differ, and conflating them mislabels data.
 * SolarWinds returns real sample instants, so rendering those in the viewer's
 * local timezone is correct. SNA series are re-binned server-side into
 * UTC-aligned buckets (utils/sna_traffic._bucket_start), so a daily bucket is
 * a *UTC day* — formatting its midnight-UTC start in any timezone behind UTC
 * lands on the previous calendar day. That produced a real mislabeling: our
 * chart read "Jul 29" for data SNA's own UI labeled "7/30". Daily SNA buckets
 * are therefore formatted in UTC and marked as such.
 */
(function () {
  'use strict';

  const BW_COLOR_OUT = '#2a78d6';      /* categorical slot 1 — Outbound (Tx) */
  const BW_COLOR_IN = '#eb6834';       /* categorical slot 2 — Inbound (Rx) */
  const BW_TEXT_SECONDARY = '#52514e';
  const BW_TEXT_MUTED = '#898781';
  const BW_GRID = '#e1e0d9';
  const BW_AXIS = '#c3c2b7';
  const BW_SURFACE = '#ffffff';
  const BW_NS = 'http://www.w3.org/2000/svg';

  const SEVEN_DAY_LABEL = 'Last 7 Days';

  /* Categorical slots 1-7 (blue, orange, aqua, yellow, magenta, green, violet)
     assigned in rank order (biggest application first); "Other Apps" always
     gets a fixed muted gray rather than the 8th hue, since it's a residual
     fold, not a real identity. (Named "Other Apps" rather than "Other" so it
     doesn't read as a duplicate of SNA's own literal "Others" application.) */
  const SNA_PALETTE = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#4a3aa7'];
  const SNA_OTHER_COLOR = '#898781';

  function svgEl(tag, attrs) {
    const el = document.createElementNS(BW_NS, tag);
    for (const k in attrs) el.setAttribute(k, attrs[k]);
    return el;
  }

  function legendSwatch(color, text) {
    const wrap = document.createElement('span');
    wrap.className = 'd-inline-flex align-items-center';
    const swatch = document.createElement('span');
    swatch.className = 'bw-legend-swatch';
    swatch.style.background = color;
    const label = document.createElement('span');
    label.className = 'text-secondary';
    label.textContent = text;
    wrap.appendChild(swatch);
    wrap.appendChild(label);
    return wrap;
  }

  function emptyState(container, text) {
    const empty = document.createElement('div');
    empty.className = 'text-muted small text-center py-5';
    empty.textContent = text;
    container.appendChild(empty);
  }

  // ── Formatters ─────────────────────────────────────────────────────────────
  // `utc` is set only for SNA daily buckets — see the module header.

  function formatTick(date, periodLabel, utc) {
    if (periodLabel === SEVEN_DAY_LABEL) {
      const opts = { month: 'short', day: 'numeric' };
      if (utc) opts.timeZone = 'UTC';
      return date.toLocaleDateString(undefined, opts);
    }
    return date.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  }

  function formatFull(date, periodLabel, utc) {
    if (utc && periodLabel === SEVEN_DAY_LABEL) {
      return date.toLocaleDateString(undefined, {
        month: 'short', day: 'numeric', timeZone: 'UTC',
      }) + ' (UTC)';
    }
    return date.toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit',
    });
  }

  // Most of this router's own traffic (netflow/snmp/syslog housekeeping, not
  // dataplane) sits well under 1 Mbps in practice (confirmed against real
  // SNA data) — a fixed 2-decimal format would round meaningful values to
  // "0.00", so scale precision to the magnitude instead.
  function formatMbps(v) {
    if (v === 0) return '0';
    const abs = Math.abs(v);
    if (abs < 0.001) return v.toFixed(4);
    if (abs < 0.01) return v.toFixed(3);
    if (abs < 1) return v.toFixed(2);
    return v.toFixed(v < 10 ? 1 : 0);
  }

  function tooltipRow(color, text, valueText) {
    const row = document.createElement('div');
    row.className = 'bw-tooltip-row';
    const key = document.createElement('span');
    key.className = 'bw-tooltip-key';
    key.style.background = color;
    const val = document.createElement('strong');
    val.textContent = valueText;
    const label = document.createElement('span');
    label.className = 'text-muted ms-1';
    label.textContent = text;
    row.appendChild(key);
    row.appendChild(val);
    row.appendChild(label);
    return row;
  }

  function snaColorFor(app, applications) {
    return app === 'Other Apps'
      ? SNA_OTHER_COLOR
      : SNA_PALETTE[applications.indexOf(app) % SNA_PALETTE.length];
  }

  // ── Percent-utilization line chart (SolarWinds) ────────────────────────────

  function addEndMarker(svg, points, key, color, xOf, yOf, dy) {
    let last = null;
    for (let i = points.length - 1; i >= 0; i--) {
      if (points[i][key] !== null && points[i][key] !== undefined) { last = points[i]; break; }
    }
    if (!last) return;
    const x = xOf(last.t), y = yOf(last[key]);
    svg.appendChild(svgEl('circle', { cx: x, cy: y, r: 4, fill: color, stroke: BW_SURFACE, 'stroke-width': 2 }));
    const text = svgEl('text', {
      x: x - 6, y: y + dy, 'text-anchor': 'end', 'font-size': 9,
      fill: BW_TEXT_SECONDARY, 'font-weight': 600,
    });
    text.textContent = last[key].toFixed(1) + '%';
    svg.appendChild(text);
  }

  function renderBandwidthChart(containerId, points, periodLabel) {
    const container = document.getElementById(containerId);
    container.textContent = '';

    const validPoints = (points || []).filter(p => p.in !== null || p.out !== null);
    if (!points || points.length === 0 || validPoints.length === 0) {
      emptyState(container, 'No traffic data available for this period.');
      return;
    }

    const legend = document.createElement('div');
    legend.className = 'bw-legend d-flex gap-3 small mb-1';
    legend.appendChild(legendSwatch(BW_COLOR_OUT, 'Outbound (Tx)'));
    legend.appendChild(legendSwatch(BW_COLOR_IN, 'Inbound (Rx)'));
    container.appendChild(legend);

    const W = 640, H = 280;
    const marginL = 34, marginR = 12, marginT = 14, marginB = 26;
    const plotW = W - marginL - marginR;
    const plotH = H - marginT - marginB;

    const times = points.map(p => new Date(p.t).getTime());
    const tMin = Math.min(...times);
    const tMax = Math.max(...times);
    const tSpan = Math.max(1, tMax - tMin);

    const xOf = (t) => marginL + ((new Date(t).getTime() - tMin) / tSpan) * plotW;
    const yOf = (v) => marginT + (1 - (v / 100)) * plotH;

    const svg = svgEl('svg', {
      viewBox: `0 0 ${W} ${H}`, width: '100%', style: 'display:block',
      role: 'img', 'aria-label': periodLabel + ' percent utilization chart',
    });

    [0, 20, 40, 60, 80, 100].forEach(v => {
      const y = yOf(v);
      svg.appendChild(svgEl('line', { x1: marginL, x2: W - marginR, y1: y, y2: y, stroke: BW_GRID, 'stroke-width': 1 }));
      const t = svgEl('text', { x: marginL - 6, y: y + 3, 'text-anchor': 'end', 'font-size': 9, fill: BW_TEXT_MUTED });
      t.textContent = v + '%';
      svg.appendChild(t);
    });

    svg.appendChild(svgEl('line', {
      x1: marginL, x2: W - marginR, y1: marginT + plotH, y2: marginT + plotH,
      stroke: BW_AXIS, 'stroke-width': 1,
    }));

    const tickCount = 4;
    for (let i = 0; i <= tickCount; i++) {
      const t = tMin + (tSpan * i) / tickCount;
      const x = xOf(t);
      svg.appendChild(svgEl('line', { x1: x, x2: x, y1: marginT + plotH, y2: marginT + plotH + 4, stroke: BW_AXIS, 'stroke-width': 1 }));
      const anchor = i === 0 ? 'start' : (i === tickCount ? 'end' : 'middle');
      const label = svgEl('text', { x: x, y: H - 6, 'text-anchor': anchor, 'font-size': 9, fill: BW_TEXT_MUTED });
      // SolarWinds points are real instants — local time is correct here.
      label.textContent = formatTick(new Date(t), periodLabel, false);
      svg.appendChild(label);
    }

    function buildPath(key) {
      let d = '';
      let open = false;
      points.forEach(p => {
        const v = p[key];
        if (v === null || v === undefined) { open = false; return; }
        const x = xOf(p.t), y = yOf(v);
        d += (open ? 'L' : 'M') + x.toFixed(2) + ',' + y.toFixed(2) + ' ';
        open = true;
      });
      return d.trim();
    }

    const outPath = buildPath('out');
    const inPath = buildPath('in');
    if (outPath) svg.appendChild(svgEl('path', { d: outPath, fill: 'none', stroke: BW_COLOR_OUT, 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
    if (inPath) svg.appendChild(svgEl('path', { d: inPath, fill: 'none', stroke: BW_COLOR_IN, 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));

    addEndMarker(svg, points, 'out', BW_COLOR_OUT, xOf, yOf, -8);
    addEndMarker(svg, points, 'in', BW_COLOR_IN, xOf, yOf, 14);

    const crosshair = svgEl('line', { x1: 0, x2: 0, y1: marginT, y2: marginT + plotH, stroke: BW_AXIS, 'stroke-width': 1, visibility: 'hidden' });
    svg.appendChild(crosshair);

    const hitRect = svgEl('rect', { x: marginL, y: marginT, width: plotW, height: plotH, fill: 'transparent' });
    svg.appendChild(hitRect);

    container.appendChild(svg);

    const tooltip = document.createElement('div');
    tooltip.className = 'bw-tooltip';
    container.appendChild(tooltip);

    const pct = (v) => (v === null || v === undefined) ? '—' : v.toFixed(1) + '%';

    hitRect.addEventListener('pointermove', (evt) => {
      const rect = svg.getBoundingClientRect();
      const scaleX = W / rect.width;
      const px = (evt.clientX - rect.left) * scaleX;
      const hoverT = tMin + ((px - marginL) / plotW) * tSpan;

      let nearest = points[0], nearestDist = Infinity;
      points.forEach(p => {
        const dist = Math.abs(new Date(p.t).getTime() - hoverT);
        if (dist < nearestDist) { nearestDist = dist; nearest = p; }
      });

      const x = xOf(nearest.t);
      crosshair.setAttribute('x1', x);
      crosshair.setAttribute('x2', x);
      crosshair.setAttribute('visibility', 'visible');

      tooltip.textContent = '';
      const timeEl = document.createElement('div');
      timeEl.className = 'bw-tooltip-time';
      timeEl.textContent = formatFull(new Date(nearest.t), periodLabel, false);
      tooltip.appendChild(timeEl);
      tooltip.appendChild(tooltipRow(BW_COLOR_OUT, 'Outbound', pct(nearest.out)));
      tooltip.appendChild(tooltipRow(BW_COLOR_IN, 'Inbound', pct(nearest.in)));

      tooltip.style.display = 'block';
      const containerRect = container.getBoundingClientRect();
      let left = evt.clientX - containerRect.left + 12;
      const top = evt.clientY - containerRect.top + 12;
      if (left + 150 > containerRect.width) left = evt.clientX - containerRect.left - 150;
      tooltip.style.left = left + 'px';
      tooltip.style.top = top + 'px';
    });

    hitRect.addEventListener('pointerleave', () => {
      crosshair.setAttribute('visibility', 'hidden');
      tooltip.style.display = 'none';
    });
  }

  function renderBwTable(containerId, points) {
    const container = document.getElementById(containerId);
    container.textContent = '';

    if (!points || points.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'text-muted small mb-0';
      empty.textContent = 'No traffic data available for this period.';
      container.appendChild(empty);
      return;
    }

    const wrap = document.createElement('div');
    wrap.className = 'table-responsive';
    wrap.style.maxHeight = '280px';

    const table = document.createElement('table');
    table.className = 'table table-sm data-table mb-0';

    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    ['Time', 'Outbound %', 'Inbound %'].forEach(h => {
      const th = document.createElement('th');
      th.textContent = h;
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    points.forEach(p => {
      const row = document.createElement('tr');
      const tCell = document.createElement('td');
      tCell.textContent = formatFull(new Date(p.t), null, false);
      const outCell = document.createElement('td');
      outCell.textContent = (p.out === null || p.out === undefined) ? '—' : p.out.toFixed(1);
      const inCell = document.createElement('td');
      inCell.textContent = (p.in === null || p.in === undefined) ? '—' : p.in.toFixed(1);
      row.appendChild(tCell);
      row.appendChild(outCell);
      row.appendChild(inCell);
      tbody.appendChild(row);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    container.appendChild(wrap);

    if (window.ImpactDataTable) window.ImpactDataTable.init(container);
  }

  // ── Per-application stacked bars (SNA) ─────────────────────────────────────

  /* Buckets now span the whole requested window, so absent data renders as
     empty space — which is indistinguishable from genuinely low traffic
     unless we say so. This states the coverage outright. */
  function coverageNote(data, periodLabel) {
    const total = (data.buckets || []).length;
    if (!total) return null;

    const withData = (data.buckets_with_data === undefined || data.buckets_with_data === null)
      ? total : data.buckets_with_data;
    const daily = periodLabel === SEVEN_DAY_LABEL;

    const parts = [];
    if (withData < total) {
      parts.push(`SNA reported data for ${withData} of ${total} ${daily ? 'days' : 'hours'}`);
    }
    if (daily) parts.push('days are UTC');
    if (!parts.length) return null;

    const note = document.createElement('div');
    note.className = 'text-muted mb-1';
    note.style.fontSize = '11px';
    note.textContent = parts.join(' · ');
    return note;
  }

  function renderStackedBarChart(containerId, data, periodLabel) {
    const container = document.getElementById(containerId);
    container.textContent = '';

    const buckets = data.buckets || [];
    const applications = data.applications || [];

    if (buckets.length === 0 || applications.length === 0) {
      emptyState(container, 'No application traffic data available for this window.');
      return;
    }

    const utc = periodLabel === SEVEN_DAY_LABEL;
    const toMbps = (bps) => bps / 1e6;

    const legend = document.createElement('div');
    legend.className = 'bw-legend d-flex flex-wrap gap-3 small mb-2';
    applications.forEach(app => legend.appendChild(legendSwatch(snaColorFor(app, applications), app)));
    container.appendChild(legend);

    const note = coverageNote(data, periodLabel);
    if (note) container.appendChild(note);

    const W = 640, H = 300;
    const marginL = 40, marginR = 12, marginT = 10, marginB = 34;
    const plotW = W - marginL - marginR;
    const plotH = H - marginT - marginB;

    const stacks = buckets.map((_, bi) => {
      let cum = 0;
      return applications.map(app => {
        const v = toMbps((data.series[app] || [])[bi] || 0);
        const start = cum;
        cum += v;
        return { app, start, end: cum, value: v };
      });
    });
    const maxTotal = Math.max(0, ...stacks.map(s => (s.length ? s[s.length - 1].end : 0)));

    function niceCeil(v) {
      if (v <= 0) return 1;
      const mag = Math.pow(10, Math.floor(Math.log10(v)));
      const norm = v / mag;
      const nice = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10;
      return nice * mag;
    }
    const yMax = niceCeil(maxTotal);

    const svg = svgEl('svg', {
      viewBox: `0 0 ${W} ${H}`, width: '100%', style: 'display:block',
      role: 'img', 'aria-label': periodLabel + ' application traffic stacked chart',
    });

    const ySteps = 5;
    for (let i = 0; i <= ySteps; i++) {
      const v = (yMax / ySteps) * i;
      const y = marginT + plotH - (v / yMax) * plotH;
      svg.appendChild(svgEl('line', { x1: marginL, x2: W - marginR, y1: y, y2: y, stroke: BW_GRID, 'stroke-width': 1 }));
      const t = svgEl('text', { x: marginL - 6, y: y + 3, 'text-anchor': 'end', 'font-size': 9, fill: BW_TEXT_MUTED });
      t.textContent = formatMbps(v);
      svg.appendChild(t);
    }
    svg.appendChild(svgEl('line', {
      x1: marginL, x2: W - marginR, y1: marginT + plotH, y2: marginT + plotH,
      stroke: BW_AXIS, 'stroke-width': 1,
    }));

    // Wide, flush, square-edged columns (no gap between stacked segments) —
    // matches the reference SNA Report Builder chart's blocky "skyline" look,
    // at the user's request, overriding the dataviz skill's default
    // thin-bar/2px-gap spec for this chart.
    //
    // Exception for sparse views: the 7d chart has only ~8 daily bands, and
    // flush bars there merge adjacent days into one indistinguishable block,
    // so you can't tell a solid week from a single wide bar. Leave a
    // proportional gap once bands get wide; dense hourly views stay flush.
    const bandW = plotW / buckets.length;
    const barW = buckets.length <= 12
      ? Math.max(1, bandW * 0.6)
      : Math.max(1, bandW - 1);

    const tooltip = document.createElement('div');
    tooltip.className = 'bw-tooltip';

    const tickEvery = Math.max(1, Math.ceil(buckets.length / 8));

    buckets.forEach((iso, bi) => {
      const bandX = marginL + bi * bandW;
      const barX = bandX + (bandW - barW) / 2;

      stacks[bi].forEach((seg) => {
        if (seg.value <= 0) return;
        const yTop = marginT + plotH - (seg.end / yMax) * plotH;
        const yBottom = marginT + plotH - (seg.start / yMax) * plotH;
        const h = yBottom - yTop;
        if (h <= 0) return;
        svg.appendChild(svgEl('rect', {
          x: barX, y: yTop, width: barW, height: h,
          fill: snaColorFor(seg.app, applications),
        }));
      });

      if (bi % tickEvery === 0) {
        const label = svgEl('text', {
          x: bandX + bandW / 2, y: H - 10, 'text-anchor': 'middle',
          'font-size': 9, fill: BW_TEXT_MUTED,
        });
        label.textContent = formatTick(new Date(iso), periodLabel, utc);
        svg.appendChild(label);
      }

      const hit = svgEl('rect', { x: bandX, y: marginT, width: bandW, height: plotH, fill: 'transparent' });
      hit.addEventListener('pointerenter', () => {
        tooltip.textContent = '';
        const timeEl = document.createElement('div');
        timeEl.className = 'bw-tooltip-time';
        timeEl.textContent = formatFull(new Date(iso), periodLabel, utc);
        tooltip.appendChild(timeEl);

        const active = [...stacks[bi]].filter(seg => seg.value > 0).sort((a, b) => b.value - a.value);
        if (!active.length) {
          const none = document.createElement('div');
          none.className = 'text-muted';
          none.textContent = 'No data reported';
          tooltip.appendChild(none);
        }
        active.forEach(seg => {
          tooltip.appendChild(tooltipRow(
            snaColorFor(seg.app, applications), seg.app, formatMbps(seg.value) + ' Mbps',
          ));
        });
        tooltip.style.display = 'block';
      });
      hit.addEventListener('pointermove', (evt) => {
        const containerRect = container.getBoundingClientRect();
        let left = evt.clientX - containerRect.left + 12;
        const top = evt.clientY - containerRect.top + 12;
        if (left + 160 > containerRect.width) left = evt.clientX - containerRect.left - 160;
        tooltip.style.left = left + 'px';
        tooltip.style.top = top + 'px';
      });
      hit.addEventListener('pointerleave', () => { tooltip.style.display = 'none'; });
      svg.appendChild(hit);
    });

    container.appendChild(svg);
    container.appendChild(tooltip);
  }

  function renderSnaTable(containerId, data, periodLabel) {
    const container = document.getElementById(containerId);
    container.textContent = '';

    const buckets = data.buckets || [];
    const applications = data.applications || [];
    if (buckets.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'text-muted small mb-0';
      empty.textContent = 'No application traffic data available for this window.';
      container.appendChild(empty);
      return;
    }

    const utc = periodLabel === SEVEN_DAY_LABEL;
    const toMbps = (bps) => bps / 1e6;

    const wrap = document.createElement('div');
    wrap.className = 'table-responsive';
    wrap.style.maxHeight = '320px';

    const table = document.createElement('table');
    table.className = 'table table-sm data-table mb-0';

    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    const th0 = document.createElement('th');
    th0.textContent = utc ? 'Day (UTC)' : 'Time';
    headRow.appendChild(th0);
    applications.forEach(app => {
      const th = document.createElement('th');
      th.textContent = app + ' (Mbps)';
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    buckets.forEach((iso, bi) => {
      const row = document.createElement('tr');
      const tCell = document.createElement('td');
      tCell.textContent = formatFull(new Date(iso), periodLabel, utc);
      row.appendChild(tCell);
      applications.forEach(app => {
        const cell = document.createElement('td');
        cell.textContent = formatMbps(toMbps((data.series[app] || [])[bi] || 0));
        row.appendChild(cell);
      });
      tbody.appendChild(row);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    container.appendChild(wrap);

    if (window.ImpactDataTable) window.ImpactDataTable.init(container);
  }

  // ── Shared ─────────────────────────────────────────────────────────────────

  function toggleTable(prefix) {
    const chart = document.getElementById(prefix + '-chart');
    const table = document.getElementById(prefix + '-table');
    const showingTable = !table.classList.contains('d-none');
    table.classList.toggle('d-none', showingTable);
    chart.classList.toggle('d-none', !showingTable);
  }

  window.ImpactReportCharts = {
    renderBandwidthChart,
    renderBwTable,
    renderStackedBarChart,
    renderSnaTable,
    toggleTable,
    formatMbps,
  };
})();
