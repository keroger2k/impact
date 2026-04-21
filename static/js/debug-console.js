/**
 * On-screen debug console overlay
 * Captures console.log, console.error, console.warn, console.info
 * Displays them in a floating overlay on the page
 */

(function() {
  class DebugConsole {
    constructor() {
      this.logs = [];
      this.maxLogs = 100;
      this.isVisible = false;
      this.overlay = null;
      this.toggleBtn = null;
      this.init();
    }

    init() {
      // Intercept console methods
      const origLog = console.log;
      const origError = console.error;
      const origWarn = console.warn;
      const origInfo = console.info;

      console.log = (...args) => {
        this.addLog('log', args);
        origLog.apply(console, args);
      };

      console.error = (...args) => {
        this.addLog('error', args);
        origError.apply(console, args);
      };

      console.warn = (...args) => {
        this.addLog('warn', args);
        origWarn.apply(console, args);
      };

      console.info = (...args) => {
        this.addLog('info', args);
        origInfo.apply(console, args);
      };

      // Capture uncaught errors
      window.addEventListener('error', (event) => {
        this.addLog('error', [`UNCAUGHT: ${event.message}`, 'at', event.filename + ':' + event.lineno]);
      });

      window.addEventListener('unhandledrejection', (event) => {
        const reason = event.reason;
        let msg = 'UNHANDLED PROMISE REJECTION:';
        if (reason && typeof reason === 'object') {
          msg += ' ' + (reason.message || JSON.stringify(reason));
        } else if (reason) {
          msg += ' ' + String(reason);
        } else {
          msg += ' (empty error object)';
        }
        this.addLog('error', [msg, reason]);
        // Prevent browser from logging duplicate
        event.preventDefault();
      });

      // Create the overlay immediately
      this.createOverlay();
      this.createToggleButton();
      
      // Auto-show on error
      setInterval(() => {
        const hasErrors = this.logs.some(l => l.level === 'error');
        if (hasErrors && !this.isVisible) {
          this.show();
        }
      }, 500);

      console.log('[DebugConsole] Initialized and ready');
    }

    addLog(level, args) {
      const message = args.map(arg => {
        if (typeof arg === 'string') return arg;
        if (typeof arg === 'object') {
          try {
            return JSON.stringify(arg);
          } catch {
            return String(arg);
          }
        }
        return String(arg);
      }).join(' ');

      this.logs.push({
        level,
        message,
        timestamp: new Date().toLocaleTimeString(),
      });

      if (this.logs.length > this.maxLogs) {
        this.logs.shift();
      }

      if (this.overlay) {
        this.render();
      }
    }

    createOverlay() {
      this.overlay = document.createElement('div');
      this.overlay.id = 'debug-console';
      this.overlay.style.cssText = `
        position: fixed;
        bottom: 0;
        right: 0;
        width: 600px;
        max-height: 400px;
        background: #1e1e1e;
        border: 2px solid #ff6b6b;
        border-radius: 8px 8px 0 0;
        color: #e0e0e0;
        font-family: 'Courier New', monospace;
        font-size: 12px;
        z-index: 999999;
        display: none;
        flex-direction: column;
        box-shadow: 0 -4px 12px rgba(0,0,0,0.5);
      `;

      document.body.appendChild(this.overlay);
      this.render();
    }

    createToggleButton() {
      this.toggleBtn = document.createElement('button');
      this.toggleBtn.id = 'debug-console-toggle';
      this.toggleBtn.textContent = '🐛 Console';
      this.toggleBtn.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: #ff6b6b;
        color: white;
        border: none;
        padding: 10px 16px;
        border-radius: 6px;
        cursor: pointer;
        font-weight: bold;
        z-index: 999998;
        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        font-size: 14px;
      `;
      this.toggleBtn.onclick = () => this.toggle();
      this.toggleBtn.onmouseover = () => this.toggleBtn.style.background = '#ff5252';
      this.toggleBtn.onmouseout = () => this.toggleBtn.style.background = '#ff6b6b';
      document.body.appendChild(this.toggleBtn);
    }

    render() {
      if (!this.overlay) return;

      const header = `
        <div style="
          background: #2d2d2d;
          padding: 8px;
          border-bottom: 1px solid #444;
          display: flex;
          justify-content: space-between;
          align-items: center;
          border-radius: 6px 6px 0 0;
        ">
          <div style="font-weight: bold; color: #ff6b6b;">🐛 Debug Console (${this.logs.length} logs)</div>
          <div style="display: flex; gap: 8px;">
            <button id="debug-clear-btn" style="
              background: #444;
              color: #fff;
              border: 1px solid #666;
              padding: 4px 8px;
              border-radius: 4px;
              cursor: pointer;
              font-size: 11px;
            ">Clear</button>
            <button id="debug-hide-btn" style="
              background: #444;
              color: #fff;
              border: 1px solid #666;
              padding: 4px 8px;
              border-radius: 4px;
              cursor: pointer;
              font-size: 11px;
            ">Hide</button>
          </div>
        </div>
      `;

      const logs = this.logs.map(log => {
        let color = '#e0e0e0';
        let icon = '📝';
        switch (log.level) {
          case 'error':
            color = '#ff6b6b';
            icon = '❌';
            break;
          case 'warn':
            color = '#ffd93d';
            icon = '⚠️';
            break;
          case 'info':
            color = '#5dade2';
            icon = 'ℹ️';
            break;
        }
        return `
          <div style="
            padding: 6px 8px;
            border-bottom: 1px solid #333;
            color: ${color};
            line-height: 1.4;
            word-break: break-word;
          ">
            <span style="margin-right: 6px;">${icon}</span>
            <span style="color: #888; font-size: 10px;">${log.timestamp}</span>
            <span style="margin-left: 8px;">${this.escapeHtml(log.message)}</span>
          </div>
        `;
      }).join('');

      const content = `
        <div style="
          overflow-y: auto;
          flex: 1;
          display: flex;
          flex-direction: column-reverse;
        ">
          ${logs || '<div style="padding: 8px; color: #888;">No logs yet...</div>'}
        </div>
      `;

      this.overlay.innerHTML = header + content;

      // Re-attach button handlers
      const clearBtn = this.overlay.querySelector('#debug-clear-btn');
      const hideBtn = this.overlay.querySelector('#debug-hide-btn');
      if (clearBtn) clearBtn.onclick = () => this.clear();
      if (hideBtn) hideBtn.onclick = () => this.hide();
    }

    escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }

    show() {
      if (!this.overlay) return;
      this.overlay.style.display = 'flex';
      this.isVisible = true;
    }

    hide() {
      if (!this.overlay) return;
      this.overlay.style.display = 'none';
      this.isVisible = false;
    }

    toggle() {
      this.isVisible ? this.hide() : this.show();
    }

    clear() {
      this.logs = [];
      this.render();
    }
  }

  // Create global instance
  window.__debugConsole = new DebugConsole();
})();
