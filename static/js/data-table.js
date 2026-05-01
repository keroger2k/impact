/* ============================================================
   IMPACT II — data-table.js
   ------------------------------------------------------------
   Auto-wires sort + per-column filter on any
       <table class="data-table"> ... </table>

   No template changes are required beyond adding the class.
   Optional <th> hints (only when auto-detection would be wrong):
       data-key      — alias for the column (used in localStorage key)
       data-type     — "text" | "number" | "ip" | "none"
                       ("none" disables sort/filter for that column)
       data-no-sort  — disable sorting only
       data-no-filter — disable filter input only

   Header detection: columns are auto-classified by sampling cell
   text in the first ~10 non-empty rows. If everything parses as
   a number it's "number"; if it parses as an IPv4/IPv6 prefix it's
   "ip"; otherwise "text".

   Sort persists per-table via localStorage, keyed by the table's
   id (or, falling back, by the first <th> text concatenated).

   Re-runs after htmx swaps (htmx:afterSwap) so server-rendered
   partials gain the behaviour without explicit init.
   ============================================================ */
(function () {
  "use strict";

  const FILTER_ROW_CLASS = "data-table-filter-row";
  const HEADER_BTN_CLASS = "data-table-sort";
  const ACTIVE_ASC = "sorted-asc";
  const ACTIVE_DESC = "sorted-desc";
  const STORAGE_PREFIX = "impactii.table.sort.";

  // ── Comparators ───────────────────────────────────────────
  function ipToTuple(s) {
    if (!s) return null;
    const trimmed = String(s).trim().split("/")[0].split(" ")[0];
    // IPv4
    const v4 = trimmed.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (v4) {
      const parts = [+v4[1], +v4[2], +v4[3], +v4[4]];
      if (parts.every((p) => p >= 0 && p <= 255)) {
        return [4, parts[0], parts[1], parts[2], parts[3], 0, 0, 0, 0];
      }
    }
    // IPv6 (loose: must contain a colon and only hex/colon chars)
    if (/^[0-9a-fA-F:]+$/.test(trimmed) && trimmed.includes(":")) {
      // Expand :: -> zeros
      const sides = trimmed.split("::");
      let head = sides[0] ? sides[0].split(":") : [];
      let tail = sides[1] !== undefined && sides[1] !== "" ? sides[1].split(":") : [];
      const fill = 8 - head.length - tail.length;
      if (fill < 0) return null;
      const groups = head.concat(Array(fill).fill("0"), tail);
      if (groups.length !== 8) return null;
      const nums = groups.map((g) => parseInt(g || "0", 16));
      if (nums.some((n) => isNaN(n))) return null;
      return [6].concat(nums);
    }
    return null;
  }

  function asNumber(s) {
    if (s === null || s === undefined) return null;
    const trimmed = String(s).replace(/[,%\s]/g, "").trim();
    if (trimmed === "" || trimmed === "—" || trimmed === "-") return null;
    const n = Number(trimmed);
    return Number.isFinite(n) ? n : null;
  }

  function compareIp(a, b) {
    const A = ipToTuple(a);
    const B = ipToTuple(b);
    if (A && B) {
      for (let i = 0; i < Math.max(A.length, B.length); i++) {
        const ai = A[i] ?? 0;
        const bi = B[i] ?? 0;
        if (ai !== bi) return ai - bi;
      }
      return 0;
    }
    if (A) return -1;
    if (B) return 1;
    return compareText(a, b);
  }

  function compareNumber(a, b) {
    const A = asNumber(a);
    const B = asNumber(b);
    if (A === null && B === null) return compareText(a, b);
    if (A === null) return 1;
    if (B === null) return -1;
    return A - B;
  }

  function compareText(a, b) {
    return String(a ?? "").localeCompare(String(b ?? ""), undefined, {
      numeric: true,
      sensitivity: "base",
    });
  }

  function comparatorFor(type) {
    if (type === "ip") return compareIp;
    if (type === "number") return compareNumber;
    return compareText;
  }

  // ── Auto-detect column type ──────────────────────────────
  function detectType(samples) {
    const nonEmpty = samples
      .map((s) => (s ?? "").trim())
      .filter((s) => s && s !== "—" && s !== "-" && s !== "N/A");
    if (nonEmpty.length === 0) return "text";

    let ipCount = 0;
    let numCount = 0;
    for (const s of nonEmpty) {
      if (ipToTuple(s)) ipCount++;
      else if (asNumber(s) !== null) numCount++;
    }
    if (ipCount / nonEmpty.length >= 0.6) return "ip";
    if (numCount / nonEmpty.length >= 0.8) return "number";
    return "text";
  }

  // ── Cell sort/filter value ───────────────────────────────
  function cellText(td) {
    if (!td) return "";
    // Prefer explicit data-sort-value if author provided one.
    const explicit = td.getAttribute("data-sort-value");
    if (explicit !== null) return explicit;
    return (td.textContent || "").trim();
  }

  // ── Storage key ──────────────────────────────────────────
  function tableKey(table) {
    if (table.id) return table.id;
    const headers = Array.from(table.querySelectorAll("thead th"))
      .map((th) => (th.textContent || "").trim())
      .join("|");
    return "anon:" + headers.slice(0, 80);
  }

  // ── Visible-row-count badge ──────────────────────────────
  function ensureCountBadge(table) {
    // Look for a `.fw-bold` span in the immediate card-header that contains
    // a "(N)" pattern. If found, expose a function that updates it after filter.
    const card = table.closest(".card");
    if (!card) return null;
    const header = card.querySelector(":scope > .card-header");
    if (!header) return null;
    // Find a text node containing "(123)" and remember its template.
    const titleSpan = header.querySelector(".fw-bold");
    if (!titleSpan) return null;
    const orig = titleSpan.textContent;
    const m = orig.match(/^(.*?)\((\d+)\)\s*$/);
    if (!m) return null;
    const prefix = m[1];
    const total = m[2];
    return function (visible) {
      titleSpan.textContent = `${prefix}(${visible} of ${total})`.replace(
        / +\)/,
        ")"
      );
    };
  }

  // ── Wire one table ───────────────────────────────────────
  function wireTable(table) {
    if (!table || table.dataset.dtWired === "1") return;
    if (table.classList.contains("data-table-skip")) {
      table.dataset.dtWired = "1";
      return;
    }

    const thead = table.tHead;
    if (!thead) {
      table.dataset.dtWired = "1";
      return;
    }
    const headerRow = thead.querySelector("tr");
    if (!headerRow) {
      table.dataset.dtWired = "1";
      return;
    }
    const ths = Array.from(headerRow.children);
    if (ths.length === 0) {
      table.dataset.dtWired = "1";
      return;
    }

    // Snapshot the initial row order from the first tbody so that
    // "unsorted" can restore it after toggling sort off.
    const tbody = table.tBodies[0];
    if (!tbody) {
      table.dataset.dtWired = "1";
      return;
    }
    const allRows = Array.from(tbody.rows);
    const originalOrder = allRows.slice();

    // Detect column types from sample rows.
    const sampleSize = Math.min(allRows.length, 12);
    const colTypes = ths.map((th, idx) => {
      const declared = (th.dataset.type || "").toLowerCase();
      if (declared === "none") return "none";
      if (declared === "text" || declared === "number" || declared === "ip") {
        return declared;
      }
      const samples = [];
      for (let i = 0; i < sampleSize; i++) {
        const row = allRows[i];
        if (!row || !row.cells || !row.cells[idx]) continue;
        samples.push(cellText(row.cells[idx]));
      }
      return detectType(samples);
    });

    // Build filter row.
    const filterRow = document.createElement("tr");
    filterRow.className = FILTER_ROW_CLASS;
    ths.forEach((th, idx) => {
      const cell = document.createElement("th");
      cell.className = "data-table-filter-cell";
      const noFilter =
        th.dataset.noFilter !== undefined ||
        colTypes[idx] === "none" ||
        th.classList.contains("data-table-no-filter");
      if (!noFilter) {
        const input = document.createElement("input");
        input.type = "text";
        input.className = "form-control form-control-sm data-table-filter-input";
        input.placeholder = "Filter…";
        input.dataset.colIdx = String(idx);
        input.addEventListener("input", () => applyFilter(table));
        // Stop click on filter input from triggering header sort.
        input.addEventListener("click", (e) => e.stopPropagation());
        cell.appendChild(input);
      }
      filterRow.appendChild(cell);
    });
    thead.appendChild(filterRow);

    // Wire each header for sort.
    ths.forEach((th, idx) => {
      const noSort =
        th.dataset.noSort !== undefined ||
        colTypes[idx] === "none" ||
        th.classList.contains("data-table-no-sort");
      if (noSort) return;
      th.classList.add(HEADER_BTN_CLASS);
      const indicator = document.createElement("span");
      indicator.className = "data-table-sort-indicator";
      indicator.setAttribute("aria-hidden", "true");
      th.appendChild(indicator);
      th.addEventListener("click", (e) => {
        // Don't sort when the click landed on the filter input.
        if (e.target && e.target.classList.contains("data-table-filter-input"))
          return;
        toggleSort(table, idx);
      });
    });

    // Restore persisted sort if any.
    table.dataset.dtWired = "1";
    table._dtCtx = {
      ths: ths,
      colTypes: colTypes,
      originalOrder: originalOrder,
      tbody: tbody,
      sortIdx: -1,
      sortDir: 0, // 0 = none, 1 = asc, -1 = desc
      updateBadge: ensureCountBadge(table),
    };
    restoreSort(table);
    applyFilter(table);
  }

  function persistSort(table) {
    const ctx = table._dtCtx;
    if (!ctx) return;
    const key = STORAGE_PREFIX + tableKey(table);
    try {
      if (ctx.sortDir === 0) {
        localStorage.removeItem(key);
      } else {
        localStorage.setItem(
          key,
          JSON.stringify({ idx: ctx.sortIdx, dir: ctx.sortDir })
        );
      }
    } catch (_e) {
      /* ignore storage errors */
    }
  }

  function restoreSort(table) {
    const ctx = table._dtCtx;
    if (!ctx) return;
    const key = STORAGE_PREFIX + tableKey(table);
    let raw = null;
    try {
      raw = localStorage.getItem(key);
    } catch (_e) {
      raw = null;
    }
    if (!raw) return;
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (_e) {
      return;
    }
    if (!parsed || typeof parsed.idx !== "number") return;
    if (parsed.idx >= ctx.ths.length) return;
    if (ctx.colTypes[parsed.idx] === "none") return;
    ctx.sortIdx = parsed.idx;
    ctx.sortDir = parsed.dir === -1 ? -1 : 1;
    applySort(table);
  }

  function toggleSort(table, idx) {
    const ctx = table._dtCtx;
    if (!ctx) return;
    if (ctx.sortIdx === idx) {
      // asc -> desc -> none -> asc ...
      ctx.sortDir = ctx.sortDir === 1 ? -1 : ctx.sortDir === -1 ? 0 : 1;
      if (ctx.sortDir === 0) ctx.sortIdx = -1;
    } else {
      ctx.sortIdx = idx;
      ctx.sortDir = 1;
    }
    applySort(table);
    persistSort(table);
  }

  function applySort(table) {
    const ctx = table._dtCtx;
    if (!ctx) return;

    // Update header indicators.
    ctx.ths.forEach((th, i) => {
      th.classList.remove(ACTIVE_ASC, ACTIVE_DESC);
      if (i === ctx.sortIdx) {
        th.classList.add(ctx.sortDir === 1 ? ACTIVE_ASC : ACTIVE_DESC);
      }
    });

    if (ctx.sortDir === 0 || ctx.sortIdx < 0) {
      // Restore original order (only the rows still attached to the tbody).
      const frag = document.createDocumentFragment();
      ctx.originalOrder.forEach((row) => {
        if (row.parentNode === ctx.tbody) frag.appendChild(row);
      });
      ctx.tbody.appendChild(frag);
      return;
    }

    const cmp = comparatorFor(ctx.colTypes[ctx.sortIdx]);
    const dir = ctx.sortDir;
    const rows = Array.from(ctx.tbody.rows).filter(
      (r) => !r.classList.contains(FILTER_ROW_CLASS)
    );
    rows.sort((a, b) => {
      const av = cellText(a.cells[ctx.sortIdx]);
      const bv = cellText(b.cells[ctx.sortIdx]);
      return cmp(av, bv) * dir;
    });
    const frag = document.createDocumentFragment();
    rows.forEach((r) => frag.appendChild(r));
    ctx.tbody.appendChild(frag);
  }

  function applyFilter(table) {
    const ctx = table._dtCtx;
    if (!ctx) return;
    const filterInputs = table.querySelectorAll(".data-table-filter-input");
    const filters = [];
    filterInputs.forEach((inp) => {
      const v = (inp.value || "").trim().toLowerCase();
      if (v) filters.push({ idx: +inp.dataset.colIdx, q: v });
    });
    let visible = 0;
    Array.from(ctx.tbody.rows).forEach((row) => {
      if (row.classList.contains(FILTER_ROW_CLASS)) return;
      let show = true;
      for (const f of filters) {
        const cell = row.cells[f.idx];
        const text = (cellText(cell) || "").toLowerCase();
        if (!text.includes(f.q)) {
          show = false;
          break;
        }
      }
      row.style.display = show ? "" : "none";
      if (show) visible++;
    });
    if (typeof ctx.updateBadge === "function") {
      ctx.updateBadge(visible);
    }
  }

  // ── Entry points ──────────────────────────────────────────
  function initAll(root) {
    const scope = root || document;
    if (
      scope.matches &&
      scope.tagName === "TABLE" &&
      scope.classList.contains("data-table")
    ) {
      wireTable(scope);
    }
    if (scope.querySelectorAll) {
      scope.querySelectorAll("table.data-table").forEach(wireTable);
    }
  }

  // Initial load.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => initAll());
  } else {
    initAll();
  }

  // Re-run after every htmx swap so server-rendered partials gain behaviour.
  document.body.addEventListener("htmx:afterSwap", function (evt) {
    initAll(evt.detail && evt.detail.target ? evt.detail.target : document);
  });
  // Some swaps replace the target itself; htmx:load fires on inserted elements.
  document.body.addEventListener("htmx:load", function (evt) {
    initAll(evt.detail && evt.detail.elt ? evt.detail.elt : document);
  });

  // Expose for manual init from inline scripts if needed.
  window.ImpactDataTable = { init: initAll };
})();
