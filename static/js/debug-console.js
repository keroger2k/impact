/**
 * Hardened Debug Console
 * - Disabled by default
 * - Enabled via Ctrl+Shift+D keyboard shortcut
 * - Persists state in localStorage
 * - Keyboard-only access for developers
 */

(function() {
  class DebugConsole {
    constructor() {
      this.logs = [];
      this.maxLogs = 200;
      this.isVisible = localStorage.getItem('impact_debug_console') === '1';
      this.overlay = null;
      this.init();
    }

    init() {
      const origLog = console.log;
      const origError = console.error;
      const origWarn = console.warn;
      const origInfo = console.info;

      console.log = (...args) => { this.addLog('log', args); origLog.apply(console, args); };
      console.error = (...args) => { this.addLog('error', args); origError.apply(console, args); };
      console.warn = (...args) => { this.addLog('warn', args); origWarn.apply(console, args); };
      console.info = (...args) => { this.addLog('info', args); origInfo.apply(console, args); };

      window.addEventListener('error', (event) => {
        this.addLog('error', [`UNCAUGHT: ${event.message}`, 'at', event.filename + ':' + event.lineno]);
      });

      window.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.shiftKey && e.code === 'KeyD') {
          e.preventDefault();
          this.toggle();
        }
      });

      // Create UI only if debug is enabled via DOM attribute or it was already visible
      const debugEnabled = document.body.dataset.debugConsole === "1";
      if (debugEnabled || this.isVisible) {
        this.createUI();
      }
    }

    addLog(level, args) {
      const message = args.map(arg => {
        if (typeof arg === 'string') return arg;
        try { return JSON.stringify(arg); } catch { return String(arg); }
      }).join(' ');

      this.logs.push({ level, message, timestamp: new Date().toLocaleTimeString() });
      if (this.logs.length > this.maxLogs) this.logs.shift();
      if (this.overlay && this.isVisible) this.render();
    }

    createUI() {
      if (this.overlay) return;
      this.overlay = document.createElement('div');
      this.overlay.id = 'impact-debug-console';
      this.overlay.style.cssText = `
        position: fixed; bottom: 0; right: 0; width: 600px; max-height: 400px;
        background: #0F172A; border-top: 2px solid #334155;
        color: #E2E8F0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 11px; z-index: 10000; display: ${this.isVisible ? 'flex' : 'none'};
        flex-direction: column; box-shadow: 0 -10px 15px -3px rgba(0, 0, 0, 0.1);
      `;
      document.body.appendChild(this.overlay);
      this.render();
    }

    render() {
      if (!this.overlay) return;
      const logsHtml = this.logs.map(log => {
        let color = '#94A3B8';
        if (log.level === 'error') color = '#F87171';
        if (log.level === 'warn') color = '#FACC15';
        return `<div style="padding: 2px 8px; border-bottom: 1px solid #1E293B; color: ${color};">
          <span style="opacity: 0.5;">[${log.timestamp}]</span> ${this.escape(log.message)}
        </div>`;
      }).join('');

      this.overlay.innerHTML = `
        <div style="background: #1E293B; padding: 4px 8px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155;">
          <span style="font-weight: 600; color: #38BDF8;">Debug Console</span>
          <button onclick="window.__debugConsole.hide()" style="background: transparent; border: none; color: #94A3B8; cursor: pointer;">✕</button>
        </div>
        <div style="overflow-y: auto; flex: 1;">${logsHtml}</div>
      `;
    }

    escape(t) {
      const d = document.createElement('div');
      d.textContent = t;
      return d.innerHTML;
    }

    toggle() {
      if (!this.overlay) this.createUI();
      this.isVisible = !this.isVisible;
      this.overlay.style.display = this.isVisible ? 'flex' : 'none';
      localStorage.setItem('impact_debug_console', this.isVisible ? '1' : '0');
      if (this.isVisible) this.render();
    }

    hide() {
      this.isVisible = false;
      if (this.overlay) this.overlay.style.display = 'none';
      localStorage.setItem('impact_debug_console', '0');
    }
  }

  window.__debugConsole = new DebugConsole();
})();
