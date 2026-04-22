/* ============================================================
   IMPACT II — Auth + API client (ES module)
   ============================================================ */

export const Auth = {
  username() {
    const match = document.cookie.match(/impact_user=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : null;
  },
  headers() {
    const csrfToken = document.cookie.split('; ').find(row => row.startsWith('csrf_token='));
    const headers = {};
    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken.split('=')[1];
    }
    return headers;
  },
};

export const API = {
  _handle401() {
    if (!window._bootstrapping) {
      window.dispatchEvent(new CustomEvent('impact:logout'));
    }
  },
  async get(path) {
    try {
      const r = await fetch(`/api${path}`, { headers: Auth.headers() });
      if (r.status === 401) { this._handle401(); throw new Error('Not authenticated'); }
      if (!r.ok) { 
        let errorMsg = r.statusText || 'Unknown error';
        try {
          const e = await r.json();
          errorMsg = e.detail || e.message || r.statusText || 'HTTP ' + r.status;
        } catch {
          errorMsg = 'HTTP ' + r.status + ': ' + r.statusText;
        }
        throw new Error(errorMsg); 
      }
      return await r.json();
    } catch (err) {
      throw new Error(err.message || 'API request failed');
    }
  },
  async post(path, body) {
    const r = await fetch(`/api${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...Auth.headers() },
      body: JSON.stringify(body),
    });
    if (r.status === 401) { this._handle401(); throw new Error('Not authenticated'); }
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || r.statusText); }
    return r.json();
  },
  stream(path, body, onEvent, onDone, signal) {
    fetch(`/api${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...Auth.headers() },
      body: JSON.stringify(body),
      signal: signal
    }).then(async r => {
      if (r.status === 401) { this._handle401(); if (onDone) onDone(); return; }
      if (!r.body) return;
      const reader = r.body.getReader();
      const dec    = new TextDecoder();
      let buf      = '';
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          const lines = buf.split('\n');
          buf = lines.pop();
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try { onEvent(JSON.parse(line.slice(6))); } catch {}
            }
          }
        }
      } catch (e) {
          if (e.name === 'AbortError') {
              console.log('Stream aborted');
          } else {
              throw e;
          }
      } finally {
          reader.releaseLock();
      }
      if (onDone) onDone();
    }).catch(err => {
      if (err.name !== 'AbortError') {
          onEvent({ type: 'error', message: err.message });
          if (onDone) onDone();
      }
    });
  },
};
