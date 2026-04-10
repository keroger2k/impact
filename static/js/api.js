/* ============================================================
   IMPACT II — Auth + API client (ES module)
   ============================================================ */

export const Auth = {
  token()    { return localStorage.getItem('impact_token'); },
  username() { return localStorage.getItem('impact_user'); },
  save(token, username) {
    localStorage.setItem('impact_token', token);
    localStorage.setItem('impact_user', username);
  },
  clear() {
    localStorage.removeItem('impact_token');
    localStorage.removeItem('impact_user');
  },
  headers() {
    const t = this.token();
    return t ? { 'Authorization': `Bearer ${t}` } : {};
  },
};

export const API = {
  _handle401() {
    Auth.clear();
    if (!window._bootstrapping) {
      window.dispatchEvent(new CustomEvent('impact:logout'));
    }
  },
  async get(path) {
    console.log('[API] GET', path);
    const r = await fetch(`/api${path}`, { headers: Auth.headers() });
    console.log('[API] GET response status:', r.status);
    if (r.status === 401) { this._handle401(); throw new Error('Not authenticated'); }
    if (!r.ok) { 
      const e = await r.json().catch(() => ({})); 
      console.error('[API] GET error:', e);
      throw new Error(e.detail || r.statusText); 
    }
    const json = await r.json();
    console.log('[API] GET response body:', json);
    return json;
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
  stream(path, body, onEvent, onDone) {
    fetch(`/api${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...Auth.headers() },
      body: JSON.stringify(body),
    }).then(async r => {
      if (r.status === 401) { this._handle401(); if (onDone) onDone(); return; }
      const reader = r.body.getReader();
      const dec    = new TextDecoder();
      let buf      = '';
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
      if (onDone) onDone();
    }).catch(err => {
      onEvent({ type: 'error', message: err.message });
      if (onDone) onDone();
    });
  },
};
