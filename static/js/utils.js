/* ============================================================
   IMPACT II — Shared utilities (ES module)
   ============================================================ */

import { API } from './api.js';

export function toast(msg, type = 'info', ms = 3500) {
  const c = document.getElementById('toast-container');
  if (!c) return;
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.classList.add('show'), 10);
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 300); }, ms);
}

export function fmtTs(ts) {
  if (!ts) return '—';
  const d = new Date(typeof ts === 'number' ? ts : ts);
  return isNaN(d) ? String(ts) : d.toLocaleString();
}

export function fmtAge(ts) {
  if (!ts) return '?';
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function dlText(text, filename) {
  const a   = document.createElement('a');
  a.href    = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

export function showModal(title, bodyHtml, wide = false) {
  document.getElementById('modal-container')?.remove();
  const el = document.createElement('div');
  el.id    = 'modal-container';
  el.innerHTML = `
    <div class="modal-backdrop" onclick="document.getElementById('modal-container').remove()"></div>
    <div class="modal-box${wide ? ' modal-wide' : ''}">
      <div class="modal-header">
        <span>${title}</span>
        <button onclick="document.getElementById('modal-container').remove()">✕</button>
      </div>
      <div class="modal-body">${bodyHtml}</div>
    </div>`;
  document.body.appendChild(el);
}

export async function initCacheBar(barEl, infoUrl, refreshUrl, onRefresh) {
  if (!barEl) return;
  try {
    const info  = await API.get(infoUrl);
    const setAt = info.oldest_at ?? info.devices?.set_at;
    barEl.innerHTML = setAt
      ? `<span class="cache-ts">Cached ${fmtAge(setAt)}</span>
         <button class="btn btn-outline-secondary btn-sm cache-refresh-btn">↻ Refresh</button>`
      : `<span class="cache-ts cache-ts-warn">Not yet cached</span>`;
    barEl.querySelector('.cache-refresh-btn')?.addEventListener('click', async () => {
      barEl.innerHTML = '<span class="cache-ts cache-ts-warn">Refreshing…</span>';
      try { await API.post(refreshUrl, {}); } catch {}
      onRefresh();
    });
  } catch {
    barEl.innerHTML = '';
  }
}

/** Shared fmtList used for firewall address/service lists */
export function fmtList(arr) {
  if (!arr || !arr.length) return '—';
  if (arr.includes('any')) return '<span class="badge text-bg-secondary">any</span>';
  if (arr.length <= 2) return arr.join(', ');
  return `${arr.slice(0, 2).join(', ')} <span class="badge text-bg-secondary">+${arr.length - 2}</span>`;
}
