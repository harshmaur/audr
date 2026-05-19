/*
 * audr daemon dashboard — Phase 2 visual slice.
 *
 * What this does:
 *  - reads ?t=<token> from the URL
 *  - GET /api/findings — render the snapshot
 *  - groups findings into severity sections (CRIT/HIGH expanded by default,
 *    MED/LOW collapsed with a count)
 *  - filter pills, finding row expand, Copy AI Prompt
 *  - EventSource /api/events — just confirms connectivity (Phase 3+ will push
 *    live deltas)
 *
 * Intentionally framework-free. ~250 LOC of vanilla JS. SSE handler is the
 * place future-Claude wires the live update protocol.
 */
(function () {
  'use strict';

  const token = new URLSearchParams(window.location.search).get('t') || '';
  if (!token) {
    document.body.innerHTML = '<div class="empty">missing auth token in URL. Re-open via <code>audr open</code>.</div>';
    return;
  }

  const $ = (id) => document.getElementById(id);
  const el = (tag, attrs = {}, ...children) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') e.className = v;
      else if (k === 'text') e.textContent = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (k === 'dataset') Object.assign(e.dataset, v);
      else e.setAttribute(k, v);
    }
    for (const c of children) {
      if (c == null) continue;
      e.append(c.nodeType ? c : document.createTextNode(c));
    }
    return e;
  };

  // ----- API ------------------------------------------------------
  async function apiGet(path) {
    const sep = path.includes('?') ? '&' : '?';
    const r = await fetch(path + sep + 't=' + encodeURIComponent(token), {
      headers: { Accept: 'application/json' },
    });
    if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + path);
    return r.json();
  }

  // ----- State ----------------------------------------------------
  // v1.3: state.findings holds ROLLED-UP rows (one per unique vulnerability,
  // partitioned by FixAuthority). Each row has shape:
  //   { dedup_group_key, worst_severity, category, rule_id, title,
  //     description, path_count, groups: [ { fix_authority, secondary_notify,
  //     path_count, paths: [{ fingerprint, path }] } ], first_seen }
  // The expanded state is keyed by dedup_group_key.
  const state = {
    findings: [],
    metrics: null,
    daemon: null,
    scanners: [],
    filters: { category: 'all', severity: 'all' },
    expanded: new Set(),
    sectionsCollapsed: { critical: false, high: false, medium: true, low: true },
    scanActive: false,
    firstScanCompleted: false,
    // Timestamp (ms since epoch) of the most recent scan-completed
    // event. Powers the "WATCHING — last scan X min ago" sub-label.
    lastScanCompletedAt: 0,
    dismissedBanners: new Set(),

    // v6 (project-tabs): server-supplied summaries.
    //   projects: [{class, id, label, count, severity_counts}]
    //   classTotals: { "<class>": {count, severity_counts}, ... }
    // Both reflect the FULL store, not the filtered subset; the
    // dashboard filters client-side from state.findings so the
    // global landscape stays visible even while focused on one tab.
    projects: [],
    classTotals: {},

    // activeTab is one of:
    //   ''                   — ALL (no tab filtering; pre-v6 view)
    //   '__my_projects__'    — union of all code-project tabs
    //   '<project_id>'       — a single project (any class)
    // Persisted in localStorage; restored on next load. URL fragment
    // override wins (so shared links land on the right tab).
    activeTab: '__my_projects__',

    // noiseExpanded: collapse state of the OTHER LOCATIONS group.
    // Auto-expands when its findings contain a crit/high (D11);
    // user toggle overrides for the session via localStorage.
    noiseExpanded: false,
    noiseExpandedManual: null, // null = follow auto; true/false = user override

    // Internal: per-render bookkeeping for project-tabs polish.
    _metricsBootstrapped: false,
    _lastProjectCounts: null,
    _flashingTabs: new Set(),
  };

  const SCAN_CATEGORIES = ['ai-agent', 'secrets', 'deps', 'os-pkg'];
  const SCAN_CATEGORY_LABEL = {
    'ai-agent': 'AI-AGENT',
    'secrets':  'SECRETS',
    'deps':     'DEPS',
    'os-pkg':   'OS-PKG',
  };

  // ----- Top bar / metrics ----------------------------------------
  // The raw daemon state (RUN/SLOW/PAUSE/OFFLINE) is operationally
  // accurate but unhelpful as a label — "RUN" tells the user nothing
  // about what audr is currently doing. We surface a friendlier
  // label here that combines the raw state with the scan-active
  // signal: between scans the daemon is "WATCHING" (fsnotify +
  // periodic poll), during a scan it's "SCANNING". The full mapping
  // lives in topBarLabel below.
  function renderTop() {
    const d = state.daemon || { state: 'OFFLINE', version: 'unknown' };
    const dot = $('state-dot');
    const label = $('state-label');
    const meta = $('state-meta');
    dot.className = 'pulse-dot ' + ({ RUN: '', SLOW: 'slow', PAUSE: 'pause', OFFLINE: 'offline' }[d.state] || 'offline');
    label.textContent = topBarLabel(d);
    meta.textContent = stateNoteFor(d);

    const scan = $('scan-status');
    scan.replaceChildren();
    if (d.scan_target) {
      scan.append('SCANNING ', el('code', { text: d.scan_target }), ` · ${d.scan_done || 0} / ${d.scan_total || 0}`);
    }
    $('version').textContent = d.version || 'unknown';
  }

  function topBarLabel(d) {
    const raw = (d && d.state) || 'OFFLINE';
    switch (raw) {
      case 'RUN':
        // Between scans the daemon is watching for changes; during a
        // scan it's actively scanning. Surface both clearly.
        return state.scanActive ? 'SCANNING' : 'WATCHING';
      case 'SLOW':    return 'SLOWED';
      case 'PAUSE':   return 'PAUSED';
      case 'OFFLINE': return 'DISCONNECTED';
      default:        return raw;
    }
  }

  function stateNoteFor(d) {
    // The raw state_note (e.g., "battery", "load 5.2") is preserved
    // as a meta clause after the friendly label. Empty note → empty
    // string so we don't leave a dangling separator.
    const note = (d && d.state_note) || '';
    return note ? '· ' + note : '';
  }

  function renderMetrics() {
    const globalM = state.metrics || { open_total: 0, open_critical: 0, open_high: 0, resolved_today: 0 };
    // Rescope per active tab: when MY PROJECTS is active or a
    // specific project tab, the strip shows that scope's counts;
    // ALL keeps the global numbers. Global totals stay visible as
    // a secondary line under the Open Findings card so users don't
    // lose the panopticon view.
    const scope = computeStripScope(globalM);
    // Subtle number tween on tab-click rescope. Skip on initial load
    // (no previous value) and on every-SSE-redraw (otherwise the
    // strip jitters during a scan). Tween only fires when the user
    // changed something, not when the dashboard refreshed itself.
    tweenMetric($('m-open'), scope.open, !state._metricsBootstrapped);
    tweenMetric($('m-crit'), scope.critical, !state._metricsBootstrapped);
    tweenMetric($('m-high'), scope.high, !state._metricsBootstrapped);
    tweenMetric($('m-resolved'), globalM.resolved_today || 0, !state._metricsBootstrapped, '+');
    state._metricsBootstrapped = true;

    // Secondary "scope / global" context line.
    const ctx = $('m-context');
    if (ctx) {
      if (scope.label && scope.global !== scope.open) {
        ctx.innerHTML = '';
        ctx.append(
          el('strong', { text: scope.label }),
          document.createTextNode(' · global: ' + scope.global),
        );
      } else if (scope.label) {
        ctx.innerHTML = '';
        ctx.append(el('strong', { text: scope.label }));
      } else {
        ctx.textContent = '';
      }
    }
  }

  // tweenMetric animates a metric-strip number toward target over
  // ~220ms using requestAnimationFrame. easeOutQuart for a snappy
  // settle. Skipped when force=true (initial load) — the number
  // jumps to target without animation in that case.
  //
  // Cancellation: re-calling tween on the same element while a
  // previous animation is in-flight cancels the old and starts a
  // new one (no overlap, no rubber-band).
  const TWEEN_MS = 220;
  function tweenMetric(elNode, target, force, prefix) {
    if (!elNode) return;
    prefix = prefix || '';
    if (force) {
      elNode.textContent = prefix + target;
      elNode._tweenCurrent = target;
      return;
    }
    const start = typeof elNode._tweenCurrent === 'number' ? elNode._tweenCurrent : parseInt(elNode.textContent.replace(/[^\d-]/g, ''), 10) || 0;
    if (start === target) return;
    if (elNode._tweenRAF) cancelAnimationFrame(elNode._tweenRAF);
    const t0 = performance.now();
    function step(now) {
      const t = Math.min(1, (now - t0) / TWEEN_MS);
      const eased = 1 - Math.pow(1 - t, 4);
      const v = Math.round(start + (target - start) * eased);
      elNode.textContent = prefix + v;
      if (t < 1) {
        elNode._tweenRAF = requestAnimationFrame(step);
      } else {
        elNode._tweenCurrent = target;
        elNode._tweenRAF = null;
      }
    }
    elNode._tweenRAF = requestAnimationFrame(step);
  }

  // computeStripScope returns the metric-strip numbers for the
  // active tab. Reads from state.classTotals + state.projects (which
  // come pre-aggregated from the server) so this is O(1) regardless
  // of finding count.
  function computeStripScope(globalM) {
    const total = globalM.open_total || 0;
    const empty = { open: total, critical: globalM.open_critical || 0, high: globalM.open_high || 0, global: total, label: '' };
    if (!state.activeTab || state.activeTab === '') return empty;

    if (state.activeTab === '__my_projects__') {
      const cp = state.classTotals['code-project'];
      if (!cp) return Object.assign({}, empty, { label: 'MY PROJECTS' });
      return {
        open: cp.count || 0,
        critical: (cp.severity_counts && cp.severity_counts.critical) || 0,
        high: (cp.severity_counts && cp.severity_counts.high) || 0,
        global: total,
        label: 'MY PROJECTS',
      };
    }
    // Specific project id.
    const proj = state.projects.find((p) => p.id === state.activeTab);
    if (!proj) return Object.assign({}, empty, { label: state.activeTab });
    return {
      open: proj.count || 0,
      critical: (proj.severity_counts && proj.severity_counts.critical) || 0,
      high: (proj.severity_counts && proj.severity_counts.high) || 0,
      global: total,
      label: proj.label || proj.id,
    };
  }

  // ----- Project tabs (v6) -----------------------------------------
  //
  // Tab semantics:
  //   - ALL                 → no row-level filter; pre-v6 view
  //   - MY PROJECTS         → rows whose ANY location is class=code-project
  //   - <project_id>        → rows whose ANY location matches that id
  // Filtering happens client-side in rowMatchesActiveTab(); the
  // server endpoint can also do it but skipping that round-trip
  // keeps tab clicks instant.
  function rowMatchesActiveTab(row) {
    if (!state.activeTab) return true;
    const locs = collectRowLocations(row);
    if (state.activeTab === '__my_projects__') {
      return locs.some((l) => l.project_class === 'code-project');
    }
    return locs.some((l) => l.project_id === state.activeTab);
  }

  function collectRowLocations(row) {
    const out = [];
    for (const g of row.groups || []) {
      for (const p of g.paths || []) out.push(p);
    }
    return out;
  }

  // Max tabs visible inline before the overflow `+ N more ▾` button
  // takes over. Beyond this threshold the tail goes behind the
  // switcher modal — single click → searchable list. Picked so the
  // first row of tabs stays readable on a typical 1440-1920px wide
  // dashboard without horizontal scrolling.
  const TAB_OVERFLOW_THRESHOLD = 8;

  function renderTabs() {
    const wrap = $('tabrow');
    const inner = $('tabrow-tabs');
    if (!wrap || !inner) return;

    // Hide the row entirely in the single-project case (1-project
    // regression guarantee). Also hidden when there are no projects
    // at all (fresh daemon, empty store).
    const codeProjects = state.projects.filter((p) => p.class === 'code-project');
    if (codeProjects.length <= 1) {
      wrap.setAttribute('hidden', '');
      renderNoiseGroup();
      return;
    }
    wrap.removeAttribute('hidden');

    inner.innerHTML = '';

    // MY PROJECTS union tab.
    inner.append(makeTabButton({
      id: '__my_projects__',
      label: 'MY PROJECTS',
      count: state.classTotals['code-project'] ? state.classTotals['code-project'].count : 0,
      severity: state.classTotals['code-project'] ? state.classTotals['code-project'].severity_counts : null,
      isUnion: true,
    }));

    // Code-project tabs. Server already sorts severity-first so we
    // just take the head; the tail goes behind the overflow button.
    const visible = codeProjects.slice(0, TAB_OVERFLOW_THRESHOLD);
    const hidden = codeProjects.slice(TAB_OVERFLOW_THRESHOLD);

    // Always keep the active tab visible — if the user picked one
    // that landed in the overflow set, swap it into the visible
    // slice. Without this, clicking a deep-overflow tab via the
    // switcher would briefly leave the row showing "nothing active."
    if (state.activeTab && hidden.some((p) => p.id === state.activeTab) && state.activeTab !== '__my_projects__') {
      const idx = hidden.findIndex((p) => p.id === state.activeTab);
      const activeProj = hidden.splice(idx, 1)[0];
      // Drop the last visible tab to make room (least-priority by
      // server-sort), put the active one at the end of visible.
      hidden.unshift(visible.pop());
      visible.push(activeProj);
    }

    for (const p of visible) {
      inner.append(makeTabButton({
        id: p.id,
        label: p.label,
        count: p.count,
        severity: p.severity_counts,
        isUnion: false,
      }));
    }

    if (hidden.length > 0) {
      inner.append(makeOverflowButton(hidden.length));
    }

    renderNoiseGroup();

    // ✓ flash for projects that resolved to zero (D10).
    // Detect: any id in lastRenderProjectCounts had count > 0 AND
    // now has count == 0 (or no longer appears in state.projects).
    // We do a one-shot DOM overlay that hangs for FLASH_MS then
    // schedules a re-render to drop the resolved entry from the
    // tabs list naturally.
    detectAndFlashResolvedTabs(codeProjects);
  }

  // Project resolution flash --------------------------------------
  // Tracks the per-project count from the previous render so we can
  // detect transitions to zero. When detected, paint a brief ✓ in
  // the place where the tab used to be, then schedule a re-render
  // that drops the tab naturally (because it's no longer in
  // state.projects).
  const FLASH_MS = 1200;
  function detectAndFlashResolvedTabs(currentCodeProjects) {
    if (!state._lastProjectCounts) {
      state._lastProjectCounts = {};
      for (const p of currentCodeProjects) state._lastProjectCounts[p.id] = p.count;
      return;
    }
    const current = {};
    for (const p of currentCodeProjects) current[p.id] = p.count;
    for (const [id, prev] of Object.entries(state._lastProjectCounts)) {
      const now = current[id] || 0;
      if (prev > 0 && now === 0 && !state._flashingTabs.has(id)) {
        flashResolvedTab(id, prev);
      }
    }
    state._lastProjectCounts = current;
  }
  function flashResolvedTab(id, prevCount) {
    if (!state._flashingTabs) state._flashingTabs = new Set();
    state._flashingTabs.add(id);
    // Inject a flash chip into the tab row in the place where the
    // tab WOULD have been. Cheapest path: re-render with a sentinel
    // and let CSS animate it.
    const inner = $('tabrow-tabs');
    if (!inner) return;
    const chip = el(
      'span',
      { class: 'tab-resolve-flash', dataset: { tab: id }, ariaLabel: 'project resolved' },
      document.createTextNode('✓ resolved'),
    );
    inner.append(chip);
    setTimeout(() => {
      state._flashingTabs.delete(id);
      try { chip.remove(); } catch (_) {}
    }, FLASH_MS);
  }

  // makeOverflowButton: opens the switcher modal pre-filtered to the
  // overflow set. The modal already supports type-to-jump; the
  // overflow button is just a more-discoverable entry point.
  function makeOverflowButton(hiddenCount) {
    const node = el(
      'button',
      {
        class: 'tab-overflow',
        title: `${hiddenCount} more project${hiddenCount === 1 ? '' : 's'}`,
        onclick: openSwitcher,
      },
      document.createTextNode('+ '),
      el('span', { class: 'more-count', text: '' + hiddenCount }),
      document.createTextNode(' more ▾'),
    );
    return node;
  }

  function makeTabButton({ id, label, count, severity, isUnion }) {
    const dot = dotClassFor(severity);
    const active = id === state.activeTab;
    const node = el(
      'button',
      {
        class: 'tab' + (isUnion ? ' union' : '') + (active ? ' active' : ''),
        dataset: { tab: id },
        onclick: () => setActiveTab(id),
      },
    );
    if (!isUnion) {
      node.append(el('span', { class: 'tab-dot ' + dot }));
    }
    node.append(el('span', { class: 'tab-name', text: label || id }));
    if (typeof count === 'number') {
      node.append(el('span', { class: 'tab-count', text: '· ' + count }));
    }
    return node;
  }

  function dotClassFor(severityCounts) {
    if (!severityCounts) return 'clean';
    if (severityCounts.critical) return 'crit';
    if (severityCounts.high) return 'high';
    return 'clean';
  }

  function renderNoiseGroup() {
    const toggle = $('noise-toggle');
    const expandedEl = $('noise-expanded');
    const tabsEl = $('noise-tabs');
    const countEl = $('noise-count');
    const warnEl = $('noise-warn');
    if (!toggle || !expandedEl || !tabsEl || !countEl) return;

    const others = state.projects.filter((p) => p.class !== 'code-project');
    if (others.length === 0) {
      toggle.setAttribute('hidden', '');
      expandedEl.classList.remove('show');
      return;
    }
    toggle.removeAttribute('hidden');

    // Aggregate count for the collapsed-bar label.
    let totalCount = 0, crit = 0, high = 0;
    for (const p of others) {
      totalCount += p.count || 0;
      crit += (p.severity_counts && p.severity_counts.critical) || 0;
      high += (p.severity_counts && p.severity_counts.high) || 0;
    }
    countEl.textContent = totalCount.toLocaleString() + ' findings';

    if (warnEl) {
      if (crit > 0) {
        warnEl.textContent = '● ' + crit + ' critical here';
      } else if (high > 0) {
        warnEl.textContent = '● ' + high + ' high here';
      } else {
        warnEl.textContent = '';
      }
    }

    // Auto-expand when a crit or high is present (D11). User
    // override (noiseExpandedManual) wins for the session.
    if (state.noiseExpandedManual !== null) {
      state.noiseExpanded = state.noiseExpandedManual;
    } else {
      state.noiseExpanded = crit > 0 || high > 0;
    }
    toggle.setAttribute('data-expanded', state.noiseExpanded ? 'true' : 'false');
    expandedEl.classList.toggle('show', state.noiseExpanded);

    // Inner tabs for each non-code-project bucket.
    tabsEl.innerHTML = '';
    for (const p of others) {
      tabsEl.append(makeTabButton({
        id: p.id || ('__class__' + p.class),
        label: p.label,
        count: p.count,
        severity: p.severity_counts,
        isUnion: false,
      }));
    }
  }

  function setActiveTab(id) {
    state.activeTab = id;
    persistActiveTab(id);
    updateURLFragment(id);
    scheduleRender();
  }

  // URL fragment + localStorage sync ---------------------------------
  function updateURLFragment(id) {
    try {
      if (!id || id === '') history.replaceState(null, '', '#');
      else history.replaceState(null, '', '#project=' + encodeURIComponent(id));
    } catch (_) { /* ignore in case the browser blocks it (file://) */ }
  }
  function readURLFragment() {
    if (!location.hash) return null;
    const m = location.hash.match(/[#&]project=([^&]+)/);
    if (m) {
      try { return decodeURIComponent(m[1]); } catch { return null; }
    }
    return null;
  }
  function persistActiveTab(id) {
    try { localStorage.setItem('audr.activeTab', id || ''); } catch (_) {}
  }
  function restoreActiveTab() {
    try {
      const fragId = readURLFragment();
      if (fragId !== null) return fragId;
      const v = localStorage.getItem('audr.activeTab');
      if (v !== null) return v;
    } catch (_) {}
    return '__my_projects__';
  }

  // Toggle noise group manually (user click overrides auto-expand).
  function toggleNoiseGroup() {
    // If currently auto-tracking and the auto-state is expanded,
    // user click should collapse (and stick). And vice versa.
    state.noiseExpandedManual = !state.noiseExpanded;
    try { localStorage.setItem('audr.noiseExpandedManual', JSON.stringify(state.noiseExpandedManual)); } catch (_) {}
    scheduleRender();
  }
  function restoreNoiseManualOverride() {
    try {
      const v = localStorage.getItem('audr.noiseExpandedManual');
      if (v === null) return null;
      return JSON.parse(v);
    } catch (_) { return null; }
  }

  // ----- Findings list --------------------------------------------
  //
  // state.findings holds rolled-up vulnerability rows from
  // /api/findings/rollup (see comment on `state` above). Each row's
  // identity is dedup_group_key; severity is `worst_severity` across
  // member findings. Filtering / grouping match the v1.2 surface so
  // the filter chips and severity sections behave identically — the
  // only behaviour change is "one row per CVE, expand to see paths"
  // instead of "one row per path."
  function filteredFindings() {
    const { category, severity } = state.filters;
    return state.findings.filter((row) => {
      if (!rowMatchesActiveTab(row)) return false;
      if (category !== 'all' && row.category !== category) return false;
      if (severity !== 'all' && row.worst_severity !== severity) return false;
      return true;
    });
  }

  const SEV_ORDER = ['critical', 'high', 'medium', 'low'];
  const SEV_CLASS = { critical: 'crit', high: 'high', medium: 'medium', low: 'low' };
  const SEV_LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };

  const AUTH_LABEL = {
    you: 'YOU CAN FIX',
    maintainer: 'PLUGIN MAINTAINER FIXES',
    upstream: 'MARKETPLACE / UPSTREAM',
  };
  // Numerical glyphs that read at a glance in expanded detail headers.
  // Kept text-only (no emoji) so they fit the monospace voice and
  // copy-paste cleanly into bug reports / screenshots.
  const AUTH_GLYPH = { you: '①', maintainer: '②', upstream: '③' };

  function renderFindingRow(row) {
    const key = row.dedup_group_key;
    const isOpen = state.expanded.has(key);
    const pathLabel = row.path_count === 1 ? '1 path' : `${row.path_count} paths`;
    return el(
      'article',
      {
        class: 'finding',
        dataset: { key, severity: row.worst_severity, category: row.category },
        'aria-expanded': isOpen ? 'true' : 'false',
        onclick: (e) => {
          // Buttons inside the expanded detail manage their own state;
          // ignore their bubbles so the row doesn't collapse on click.
          if (e.target.closest('.copy-btn, .file-issue-btn, .auth-paths, .snippet-pre')) return;
          if (isOpen) state.expanded.delete(key);
          else state.expanded.add(key);
          render();
        },
      },
      el('div', { class: 'finding-bar ' + SEV_CLASS[row.worst_severity] }),
      el(
        'div',
        { class: 'finding-body' },
        el(
          'div',
          { class: 'finding-line1' },
          el('span', { class: 'sev-label ' + SEV_CLASS[row.worst_severity], text: SEV_LABEL[row.worst_severity] }),
          el('span', { class: 'cat-tag', text: (row.category || '').toUpperCase() }),
          el('span', { class: 'finding-title', text: row.title || row.rule_id }),
          el('span', { class: 'path-count', text: pathLabel }),
        ),
        el(
          'div',
          { class: 'finding-meta' },
          el('span', { text: 'first seen ' + formatRelative(row.first_seen) }),
          el('span', { text: 'rule ' + row.rule_id }),
        ),
        isOpen ? expandedDetail(row) : null,
      ),
    );
  }

  // expandedDetail renders the three fix-authority sub-groups inside
  // an opened vulnerability row. Each sub-group reuses the existing
  // .detail-section / .copy-btn visual language; the only new chrome
  // is the AUTH_GLYPH heading prefix and the override-snippet F3
  // disclaimer line.
  function expandedDetail(row) {
    const desc = row.description
      ? el('p', { class: 'detail-desc', text: row.description })
      : null;
    const groupSections = (row.groups || []).map((g) => renderAuthGroup(row, g));
    return el(
      'div',
      { class: 'expanded-detail rollup-detail' },
      el(
        'div',
        { class: 'detail-section detail-wide' },
        desc,
        ...groupSections,
      ),
    );
  }

  function renderAuthGroup(row, group) {
    const auth = group.fix_authority || 'you';
    const pathLabel = group.path_count === 1 ? '1 path' : `${group.path_count} paths`;
    const heading = el(
      'h4',
      { class: 'auth-heading auth-' + auth },
      el('span', { class: 'auth-glyph', text: AUTH_GLYPH[auth] || '·' }),
      el('span', { text: ' ' + (AUTH_LABEL[auth] || auth.toUpperCase()) }),
      el('span', { class: 'auth-count', text: pathLabel }),
    );
    return el(
      'div',
      { class: 'auth-group', dataset: { authority: auth } },
      heading,
      authActionFor(row, group),
      renderAuthPaths(group),
    );
  }

  // authActionFor renders the action area for one fix-authority bucket.
  // ① YOU CAN FIX: lazy-load the override snippet + copy button + F3 disclaimer.
  // ② PLUGIN MAINTAINER FIXES: lazy-load the GH issue URL + "File issue" button
  //    (falls back to "Copy report to clipboard" for unknown maintainers).
  // ③ MARKETPLACE / UPSTREAM: static note — only the upstream maintainer can fix.
  function authActionFor(row, group) {
    const firstPath = (group.paths || [])[0];
    if (!firstPath) return null;
    const fp = firstPath.fingerprint;
    const auth = group.fix_authority;
    if (auth === 'you') return renderYouAction(fp);
    if (auth === 'maintainer') return renderMaintainerAction(fp, group.secondary_notify);
    if (auth === 'upstream') {
      return el(
        'p',
        { class: 'detail-desc' },
        'Only the original maintainer can fix this. Re-scan after a patched release is published.',
      );
    }
    return null;
  }

  function renderYouAction(fingerprint) {
    const container = el('div', { class: 'auth-action' },
      el('div', { class: 'manual-steps', text: 'loading override snippet…' }),
    );
    apiGet('/api/remediate/snippet/' + encodeURIComponent(fingerprint))
      .then((data) => {
        container.replaceChildren();
        if (!data.snippet) {
          container.append(el('p', { class: 'detail-desc',
            text: 'No upstream fix available yet — track the advisory and rescan after a release.' }));
          return;
        }
        if (data.lockfile_format || data.lockfile_path) {
          container.append(el('div', { class: 'snippet-meta' },
            (data.lockfile_format ? `${data.lockfile_format} · ` : '') +
            'paste into ' + (data.lockfile_path || 'your manifest')));
        }
        container.append(el('pre', { class: 'manual-steps snippet-pre', text: data.snippet }));
        const btn = el('button', { class: 'copy-btn', type: 'button',
          onclick: (e) => { e.stopPropagation(); onCopyText(btn, data.snippet); } },
          'COPY SNIPPET');
        container.append(btn);
        if (data.disclaimer) {
          container.append(el('p', { class: 'snippet-disclaimer', text: data.disclaimer }));
        }
      })
      .catch((err) => {
        container.replaceChildren(
          el('p', { class: 'detail-desc', text: 'failed to load snippet: ' + err.message }),
        );
      });
    return container;
  }

  function renderMaintainerAction(fingerprint, vendorHint) {
    const container = el('div', { class: 'auth-action' },
      el('div', { class: 'detail-desc', text: 'loading maintainer link…' }),
    );
    apiGet('/api/remediate/maintainer/' + encodeURIComponent(fingerprint))
      .then((data) => {
        container.replaceChildren();
        const label = data.label_hint || vendorHint || 'plugin author';
        if (data.issue_url) {
          const btn = el('a', {
            class: 'copy-btn file-issue-btn',
            href: data.issue_url,
            target: '_blank',
            rel: 'noopener noreferrer',
            onclick: (e) => { e.stopPropagation(); },
          }, 'FILE ISSUE WITH ' + label.toUpperCase());
          container.append(btn);
        } else {
          // Unknown maintainer — clipboard-copy fallback so the user
          // can paste into whichever tracker the maintainer uses.
          const btn = el('button', { class: 'copy-btn', type: 'button',
            onclick: (e) => { e.stopPropagation(); onCopyText(btn, data.body_markdown); } },
            'COPY REPORT FOR ' + label.toUpperCase());
          container.append(btn);
          container.append(el('p', { class: 'detail-desc',
            text: 'No canonical issue tracker for this vendor — paste the copied report into whichever tracker they publish.' }));
        }
      })
      .catch((err) => {
        container.replaceChildren(
          el('p', { class: 'detail-desc', text: 'failed to load maintainer link: ' + err.message }),
        );
      });
    return container;
  }

  function renderAuthPaths(group) {
    const paths = group.paths || [];
    if (paths.length === 0) return null;
    const list = el('ol', { class: 'auth-paths' },
      ...paths.map((p) => el('li', {}, el('code', { text: p.path || '(no path)' }))),
    );
    if (group.path_count > paths.length) {
      list.append(el('li', { class: 'auth-paths-more',
        text: `… ${group.path_count - paths.length} more (server-capped; widen via ?cap=0)` }));
    }
    return list;
  }

  async function onCopyText(btn, text) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.append(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (_) {}
      ta.remove();
    }
    const original = btn.textContent;
    btn.textContent = 'COPIED ✓';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = original;
      btn.classList.remove('copied');
    }, 2000);
  }

  function renderFindings() {
    const root = $('findings');
    root.removeAttribute('aria-busy');
    root.replaceChildren();
    const filtered = filteredFindings();
    if (filtered.length === 0) {
      root.append(el('div', { class: 'empty', text: 'no findings match the current filters' }));
      return;
    }

    // Group rolled-up rows by worst severity, identical chrome to the
    // pre-v1.3 flat view (collapsed-by-default MEDIUM + LOW sections).
    const grouped = { critical: [], high: [], medium: [], low: [] };
    for (const row of filtered) (grouped[row.worst_severity] || []).push(row);

    for (const sev of SEV_ORDER) {
      const group = grouped[sev];
      if (group.length === 0) continue;
      const collapsed = state.sectionsCollapsed[sev];
      const section = el(
        'section',
        { class: 'sev-section', dataset: { severity: sev, collapsed: String(collapsed) } },
        el(
          'header',
          {
            class: 'sev-section-header ' + SEV_CLASS[sev],
            role: 'button',
            tabindex: '0',
            'aria-expanded': String(!collapsed),
            onclick: () => {
              state.sectionsCollapsed[sev] = !state.sectionsCollapsed[sev];
              render();
            },
            onkeydown: (e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                state.sectionsCollapsed[sev] = !state.sectionsCollapsed[sev];
                render();
              }
            },
          },
          el('span', { class: 'chev' }),
          el('span', { text: SEV_LABEL[sev] }),
          el('span', { class: 'count', text: `${group.length}` }),
        ),
        ...group.map(renderFindingRow),
      );
      root.append(section);
    }
  }

  function render() {
    renderTop();
    renderMetrics();
    renderTabs();
    renderBanners();
    renderScanProgress();
    renderFindings();
  }

  // scheduleRender coalesces multiple render() requests within a
  // single animation frame. SSE deltas land at burst rates (one event
  // per new/updated/resolved finding); with 1990+ findings during a
  // first-run scan, calling render() directly per event made the page
  // unresponsive — each render rebuilds the full finding list DOM. By
  // queuing render() onto the next rAF and dropping subsequent
  // schedule calls until that frame fires, we cap render frequency
  // at ~60Hz regardless of event burst rate.
  let renderQueued = false;
  function scheduleRender() {
    if (renderQueued) return;
    renderQueued = true;
    requestAnimationFrame(() => {
      renderQueued = false;
      render();
    });
  }

  // ----- Banner stack ---------------------------------------------
  // Stacks below the top bar. Scanner banners surface when a backend
  // is "unavailable" (sidecar not installed) or "error" (last scan
  // failed). daemon-state may also surface inotify-limit / remote-FS
  // hints; render them when present.
  function renderBanners() {
    const root = $('banners');
    root.replaceChildren();
    const banners = computeBanners();
    for (const b of banners) {
      if (state.dismissedBanners.has(b.id)) continue;
      root.append(renderBanner(b));
    }
  }

  function computeBanners() {
    const out = [];
    // Update-available banner — first in the stack so it never gets
    // hidden behind a half-screen of scanner warnings.
    const upd = (state.daemon || {}).update_available;
    if (upd && upd.version) {
      out.push({
        id: 'update:' + upd.version,
        kind: 'info',
        tag: 'UPDATE',
        text: `audr ${upd.version} is available (running ${(state.daemon && state.daemon.version) || 'unknown'}). Restart with the new binary to pick up newer rules.`,
        link: upd.url,
        linkLabel: 'View release',
      });
    }
    // Scanner banners — one per scanner that isn't ok.
    // "disabled" status is intentionally silent in the banner stack —
    // the scan-progress pill already shows DISABLED clearly, and a
    // banner per user-disabled category would clutter the dashboard
    // when the user has 2-3 turned off deliberately.
    for (const sc of state.scanners) {
      const stateName = sc.state || sc.status; // wire field, defensive
      if (!stateName || stateName === 'ok' || stateName === 'disabled') continue;
      const category = sc.name || sc.category;
      const fix = stateName === 'unavailable' || stateName === 'missing'
        ? guessInstallCommand(category)
        : '';
      out.push({
        id: `scanner:${category}:${stateName}`,
        kind: stateName === 'error' ? 'error' : 'warn',
        tag: `${(category || '?').toUpperCase()} ${stateName.toUpperCase()}`,
        text: sc.error_text || sc.errorText || defaultScannerMessage(category, stateName),
        fix,
      });
    }
    // Daemon-state hints — populated when daemon publishes them.
    const d = state.daemon || {};
    if (d.inotify_low) {
      out.push({
        id: 'inotify-low',
        kind: 'warn',
        tag: 'INOTIFY LIMIT',
        text: 'fsnotify watcher hit the kernel limit; some files won\'t trigger immediate rescans (periodic poll still covers them).',
        fix: 'echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.d/99-audr.conf && sudo sysctl -p',
      });
    }
    if (d.remote_fs_skipped) {
      out.push({
        id: 'remote-fs',
        kind: 'info',
        tag: 'REMOTE FS',
        text: `${d.remote_fs_skipped} mount(s) skipped (NFS / SMB / 9P / FUSE). Networked storage is intentionally excluded.`,
        fix: '',
      });
    }
    // classify.toml hint — surfaces ONLY when there are projects to
    // talk about (otherwise the banner is meaningless). Dismissable;
    // the dismissed state persists across reloads via the existing
    // dismissedBanners + localStorage mechanism the other banners use.
    if (state.projects.length > 0) {
      out.push({
        id: 'classify-hint',
        kind: 'info',
        tag: 'PROJECT TABS',
        text: 'Reclassify any folder by editing ~/.audr/classify.toml — the daemon hot-reloads on save.',
        fix: '',
      });
    }
    return out;
  }

  function renderBanner(b) {
    const node = el(
      'div',
      { class: 'banner ' + (b.kind === 'error' ? 'error' : b.kind === 'info' ? 'info' : '') },
      el('span', { class: 'banner-tag', text: b.tag }),
      el('span', { text: b.text }),
    );
    if (b.fix) {
      node.append(el('code', { class: 'fix', text: b.fix }));
    }
    if (b.link) {
      node.append(el('a', { href: b.link, target: '_blank', rel: 'noopener' }, b.linkLabel || 'open'));
    }
    node.append(el(
      'button',
      {
        class: 'dismiss',
        type: 'button',
        onclick: () => {
          state.dismissedBanners.add(b.id);
          renderBanners();
        },
      },
      'dismiss',
    ));
    return node;
  }

  function defaultScannerMessage(category, stateName) {
    if (stateName === 'unavailable' || stateName === 'missing') {
      return `${(category || 'scanner').toUpperCase()} scanner not installed — that category is being skipped.`;
    }
    if (stateName === 'error') {
      return `${(category || 'scanner').toUpperCase()} last scan errored — see daemon logs for detail.`;
    }
    if (stateName === 'outdated') {
      return `${(category || 'scanner').toUpperCase()} scanner is older than audr's minimum.`;
    }
    return `${(category || 'scanner').toUpperCase()}: ${stateName}`;
  }

  function guessInstallCommand(category) {
    if (category === 'secrets') return 'audr update-scanners --backend trufflehog --yes';
    if (category === 'deps')    return 'audr update-scanners --backend osv-scanner --yes';
    return '';
  }

  // ----- Scan-progress strip --------------------------------------
  // Always visible. Surfaces three states:
  //   1. STARTING UP    — daemon's first scan hasn't started yet
  //   2. INITIAL SCAN   — first full sweep of the machine, mid-flight
  //   3. RESCANNING     — periodic / change-triggered cycle, mid-flight
  //   4. WATCHING       — between scans, awaiting fsnotify or ticker
  //
  // Previous behavior hid the strip entirely between scans, which left
  // users wondering whether the daemon was doing anything at all.
  // Keeping it visible with a "WATCHING — last scan Xmin ago" line
  // resolves that.
  function renderScanProgress() {
    const root = $('scan-progress');
    const labelNode = $('scan-progress-text');
    const subNode = $('scan-progress-sub');

    root.removeAttribute('hidden');
    root.setAttribute('data-active', state.scanActive ? 'true' : 'false');

    let label, sub = '';
    if (state.scanActive) {
      if (state.firstScanCompleted) {
        label = 'RESCANNING';
        sub = 'change detected or periodic check';
      } else {
        label = 'INITIAL SCAN';
        sub = 'first full sweep of your machine';
      }
    } else if (state.firstScanCompleted) {
      label = 'WATCHING';
      sub = lastScanAgo();
    } else {
      label = 'STARTING UP';
      sub = 'first scan begins shortly';
    }
    labelNode.textContent = label;
    if (subNode) subNode.textContent = sub;

    const ol = $('scan-progress-categories');
    ol.replaceChildren();
    const byCategory = {};
    for (const sc of state.scanners) {
      const name = sc.name || sc.category;
      const stateName = sc.state || sc.status;
      if (name) byCategory[name] = stateName;
    }
    const scannerEnabled = (state.daemon && state.daemon.scanner_enabled) || {};
    for (const cat of SCAN_CATEGORIES) {
      const stateName = byCategory[cat];
      // User-disabled wins over sidecar status — even an installed
      // scanner shows DISABLED when the user has explicitly turned
      // it off. Use the daemon's snapshot signal (scanner_enabled)
      // as the source of truth so the pill matches what's in the
      // config file rather than the last scan's status.
      const userDisabled = scannerEnabled[cat] === false;
      let cls = 'pending';
      let stateLabel = 'PENDING';
      if (userDisabled || stateName === 'disabled') {
        cls = 'disabled';
        stateLabel = 'DISABLED';
      } else if (stateName === 'running') {
        cls = 'running';
        stateLabel = 'RUNNING';
      } else if (state.scanActive && !stateName) {
        cls = 'pending';
        stateLabel = 'QUEUED';
      } else if (stateName === 'ok')          { cls = 'ok';          stateLabel = 'OK'; }
      else if (stateName === 'error')         { cls = 'error';       stateLabel = 'ERROR'; }
      else if (stateName === 'unavailable' || stateName === 'missing') {
        cls = 'unavailable'; stateLabel = 'OFF';
      } else if (stateName === 'outdated')    { cls = 'unavailable'; stateLabel = 'OUTDATED'; }

      // userEnabled is the source of truth for the toggle: false
      // when the user explicitly disabled the category. Passed
      // verbatim to toggleScanner as currentlyEnabled.
      const userEnabled = !userDisabled;
      const labelEl = SCAN_CATEGORY_LABEL[cat];
      const toggleTitle = userEnabled
        ? `Click to disable ${labelEl} scanning`
        : `Click to enable ${labelEl} scanning`;
      ol.append(el(
        'li',
        {
          class: cls + ' toggleable',
          title: toggleTitle,
          role: 'button',
          tabindex: '0',
          onclick: () => toggleScanner(cat, userEnabled),
          onkeydown: (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              toggleScanner(cat, userEnabled);
            }
          },
        },
        el('span', { class: 'dot' }),
        el('span', { text: SCAN_CATEGORY_LABEL[cat] }),
        el('span', { style: 'margin-left:auto;color:var(--text-muted);', text: stateLabel }),
      ));
    }
  }

  // toggleScanner flips the enabled flag for a scanner category by
  // POSTing to /api/scanners. Optimistic UI: we flip
  // state.daemon.scanner_enabled immediately and re-render so the
  // user sees the new state without waiting for the server roundtrip.
  // The server's response replaces the local copy in case anything
  // diverged (e.g., concurrent CLI invocation).
  async function toggleScanner(category, currentlyEnabled) {
    const nextEnabled = !currentlyEnabled;
    if (!state.daemon) state.daemon = {};
    if (!state.daemon.scanner_enabled) state.daemon.scanner_enabled = {};
    state.daemon.scanner_enabled[category] = nextEnabled;
    scheduleRender();
    try {
      const r = await fetch('/api/scanners?t=' + encodeURIComponent(token), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ category, enabled: nextEnabled }),
      });
      if (r.ok) {
        const updated = await r.json();
        state.daemon.scanner_enabled = {
          'ai-agent': updated.ai_agent,
          'deps':     updated.deps,
          'secrets':  updated.secrets,
          'os-pkg':   updated.os_pkg,
        };
        scheduleRender();
      } else {
        // Roll back the optimistic flip and let the user know.
        state.daemon.scanner_enabled[category] = currentlyEnabled;
        scheduleRender();
      }
    } catch (e) {
      state.daemon.scanner_enabled[category] = currentlyEnabled;
      scheduleRender();
    }
  }

  // ----- Filter pills ---------------------------------------------
  function wireFilters() {
    document.querySelectorAll('.filter-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const group = btn.dataset.filter; // "category" | "severity"
        const value = btn.dataset.value;
        state.filters[group] = value;
        for (const sib of document.querySelectorAll(`.filter-btn[data-filter="${group}"]`)) {
          sib.classList.toggle('active', sib === btn);
        }
        render();
      });
    });
  }

  // ----- SSE event stream -----------------------------------------
  // Subscribe to the store's event bus. Server forwards:
  //   - scan-started / scan-completed: scan-cycle bookends
  //   - finding-opened: new finding (or reopened after resolution)
  //   - finding-updated: re-detected, fields may have changed
  //   - finding-resolved: scanner no longer detects it, transitioned to resolved
  //   - scanner-status: per-category status changed (ok/error/unavailable)
  //   - daemon-state: RUN/SLOW/PAUSE transitions (Phase 3+)
  function connectEvents() {
    const url = '/api/events?t=' + encodeURIComponent(token);
    const src = new EventSource(url);

    src.addEventListener('hello', () => { /* connected */ });
    src.addEventListener('heartbeat', () => { /* keep-alive */ });

    // v1.3: finding-level SSE events trigger a debounced re-fetch of
    // the rolled-up view. Incremental upsert doesn't map cleanly onto
    // rolled-up rows (one path event can move two rows: the affected
    // group's count, and possibly the worst-severity if a higher-sev
    // finding lands in the same dedup group). refreshRolledUp() is
    // cheap (single SQL group-by + aggregation) and gives the right
    // shape without re-implementing the aggregation in JS.
    src.addEventListener('finding-opened', () => refreshRolledUp());
    src.addEventListener('finding-updated', () => refreshRolledUp());
    src.addEventListener('finding-resolved', () => {
      if (state.metrics) {
        state.metrics.resolved_today = (state.metrics.resolved_today || 0) + 1;
        renderMetrics();
      }
      refreshRolledUp();
    });

    src.addEventListener('scanner-status', (e) => {
      const s = parseEvent(e);
      if (!s) return;
      const key = s.name || s.category;
      const idx = state.scanners.findIndex((x) => (x.name || x.category) === key);
      if (idx >= 0) state.scanners[idx] = s;
      else state.scanners.push(s);
      renderScanProgress();
      renderBanners();
    });

    src.addEventListener('scan-started', () => {
      state.scanActive = true;
      // Don't reset state.scanners — old per-category statuses are
      // still relevant context until the new run overwrites them.
      renderScanProgress();
    });
    src.addEventListener('scan-completed', () => {
      state.scanActive = false;
      state.firstScanCompleted = true;
      state.lastScanCompletedAt = Date.now();
      renderScanProgress();
    });
    src.addEventListener('daemon-state', (e) => {
      const d = parseEvent(e);
      if (!d || !state.daemon) return;
      state.daemon.state = d.state || state.daemon.state;
      state.daemon.state_note = d.state_note || '';
      renderTop();
    });

    src.onerror = () => {
      // EventSource auto-reconnects respecting the server's retry: hint.
      // Phase 5 polish can add a "reconnecting..." state-indicator badge.
    };
  }

  // refreshRolledUp re-fetches /api/findings/rollup and updates
  // state.findings + state.metrics in place. Called from SSE event
  // handlers (finding-opened / finding-updated / finding-resolved)
  // and from the "reload" link in the footer. Debounced via the same
  // rAF guard render uses, so a burst of N SSE events triggers at
  // most one network round-trip per frame.
  let rolledUpRefreshQueued = false;
  function refreshRolledUp() {
    if (rolledUpRefreshQueued) return;
    rolledUpRefreshQueued = true;
    requestAnimationFrame(async () => {
      rolledUpRefreshQueued = false;
      try {
        const snap = await apiGet('/api/findings/rollup');
        state.findings = snap.rows || [];
        if (snap.metrics) state.metrics = snap.metrics;
        // v6: project summaries flow with every rollup response.
        state.projects = snap.projects || [];
        state.classTotals = snap.class_totals || {};
        scheduleRender();
      } catch (_) {
        // Swallow the error — the next SSE event or manual reload
        // will retry. The metric strip stays on its last known
        // values; that's safer than blanking the UI on a transient
        // network blip.
      }
    });
  }

  function parseEvent(e) {
    try { return JSON.parse(e.data); } catch { return null; }
  }

  // ----- Helpers --------------------------------------------------
  function formatRelative(iso) {
    if (!iso) return '?';
    const t = new Date(iso).getTime();
    if (isNaN(t)) return iso;
    const delta = (Date.now() - t) / 1000;
    if (delta < 60) return 'just now';
    if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
    if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
    return `${Math.floor(delta / 86400)}d ago`;
  }

  // lastScanAgo formats state.lastScanCompletedAt as a human relative
  // phrase for the WATCHING sub-label. Empty string when no scan has
  // completed yet in this session (the dashboard JS doesn't yet read
  // the most-recent completed timestamp from the snapshot — that's
  // tracked as a v0.4.x followup).
  function lastScanAgo() {
    // If the dashboard loaded between scans we don't yet know when
    // the last one finished — surface a neutral phrase rather than
    // overclaim. After the next scan-completed SSE event the
    // timestamp populates and we switch to "last scan X min ago".
    // Plumbing the most-recent completed_at through the snapshot is
    // tracked as a v0.4.x followup.
    if (!state.lastScanCompletedAt) return 'fsnotify + 5min poll';
    const delta = (Date.now() - state.lastScanCompletedAt) / 1000;
    if (delta < 60)    return 'last scan just now';
    if (delta < 3600)  return `last scan ${Math.floor(delta / 60)} min ago`;
    if (delta < 86400) return `last scan ${Math.floor(delta / 3600)} hr ago`;
    return `last scan ${Math.floor(delta / 86400)} d ago`;
  }

  // ----- Boot -----------------------------------------------------
  async function load() {
    try {
      // v1.3: load the rolled-up shape from /api/findings/rollup,
      // then layer the daemon-info + scanners-status from the flat
      // /api/findings endpoint. The rollup endpoint intentionally
      // omits scanners[] to keep its payload focused on the dashboard
      // hot path — the once-per-load flat snapshot still owns the
      // banner-stack-relevant scanner status.
      const [rollup, flat] = await Promise.all([
        apiGet('/api/findings/rollup'),
        apiGet('/api/findings'),
      ]);
      state.findings = rollup.rows || [];
      state.metrics = rollup.metrics || flat.metrics;
      state.daemon = flat.daemon;
      state.scanners = flat.scanners || [];
      // v6: project summaries flow with every rollup response.
      state.projects = rollup.projects || [];
      state.classTotals = rollup.class_totals || {};
      // Restore the user's last-active tab (URL fragment wins over
      // localStorage). Verify the id still exists in the loaded
      // projects[]; if not (project resolved entirely between
      // sessions), fall back to MY PROJECTS.
      const want = restoreActiveTab();
      if (want === '__my_projects__' || want === '') {
        state.activeTab = want;
      } else if (state.projects.some((p) => p.id === want)) {
        state.activeTab = want;
      } else {
        state.activeTab = '__my_projects__';
      }
      state.noiseExpandedManual = restoreNoiseManualOverride();
      // A scanner row in the snapshot means at least one scan cycle
      // has completed (or the daemon recorded sidecar statuses
      // pre-cycle). Either way, treat first-run as past so the
      // progress strip doesn't surface unless an SSE scan-started
      // event flips scanActive.
      if (state.scanners.length > 0) {
        state.firstScanCompleted = true;
      }
      // If a scan is in flight when the dashboard loads, set
      // scanActive directly from the snapshot — we'd otherwise miss
      // the scan-started SSE event of an already-running scan and
      // wrongly show "WAITING FOR FIRST SCAN" until the scan
      // completed.
      if (state.daemon && state.daemon.scan_in_progress) {
        state.scanActive = true;
      }
      // Most-recent completed_at, surfaced via snapshot so the
      // WATCHING state can display a real "last scan X min ago"
      // clause on initial load instead of waiting for the next
      // scan-completed SSE event.
      if (state.daemon && state.daemon.last_scan_completed) {
        state.lastScanCompletedAt = state.daemon.last_scan_completed * 1000;
      }
      render();
    } catch (e) {
      document.getElementById('findings').replaceChildren(
        el('div', { class: 'empty', text: 'failed to load findings: ' + e.message }),
      );
    }
  }

  document.getElementById('reload').addEventListener('click', (e) => {
    e.preventDefault();
    load();
  });

  // ----- Project switcher modal (v6) ------------------------------
  // Triggered by:
  //   - clicking the "jump to project" affordance in the tab row
  //   - pressing '/' anywhere on the page (not inside a text input)
  //   - pressing Cmd+P / Ctrl+P (overrides the browser's default
  //     print shortcut while the dashboard tab is focused — common
  //     pattern in editor-style UIs like VS Code's command palette)
  //
  // Items are pre-sorted by the same severity priority the tab row
  // uses (server-side sort).
  let switcherFocusIndex = 0;
  function openSwitcher() {
    const overlay = $('switcher');
    if (!overlay) return;
    overlay.removeAttribute('hidden');
    renderSwitcherList(state.projects, '');
    const input = $('switcher-input');
    if (input) {
      input.value = '';
      setTimeout(() => input.focus(), 0);
    }
  }
  function closeSwitcher() {
    const overlay = $('switcher');
    if (overlay) overlay.setAttribute('hidden', '');
  }
  function renderSwitcherList(items, q) {
    const list = $('switcher-list');
    if (!list) return;
    list.innerHTML = '';
    const matches = items.filter((p) => {
      if (!q) return true;
      const needle = q.toLowerCase();
      return (
        (p.label || '').toLowerCase().includes(needle) ||
        (p.id || '').toLowerCase().includes(needle)
      );
    });
    if (switcherFocusIndex >= matches.length) switcherFocusIndex = 0;
    matches.forEach((p, i) => {
      const dot = dotClassFor(p.severity_counts);
      const row = el(
        'div',
        {
          class: 'switcher-item' + (i === switcherFocusIndex ? ' focused' : ''),
          onclick: () => {
            setActiveTab(p.id);
            closeSwitcher();
          },
        },
        el('span', { class: 'tab-dot ' + dot }),
        document.createTextNode(p.label || p.id),
        el('span', { class: 'item-count', text: '' + (p.count || 0) }),
      );
      list.append(row);
    });
  }
  const switcherTrigger = $('search-trigger');
  if (switcherTrigger) switcherTrigger.addEventListener('click', openSwitcher);
  const switcherOverlay = $('switcher');
  if (switcherOverlay) {
    switcherOverlay.addEventListener('click', (e) => {
      if (e.target === switcherOverlay) closeSwitcher();
    });
  }
  const switcherInput = $('switcher-input');
  if (switcherInput) {
    switcherInput.addEventListener('input', (e) => {
      switcherFocusIndex = 0;
      renderSwitcherList(state.projects, e.target.value);
    });
    switcherInput.addEventListener('keydown', (e) => {
      const items = state.projects; // mirror render filter
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        switcherFocusIndex = Math.min(items.length - 1, switcherFocusIndex + 1);
        renderSwitcherList(items, e.target.value);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        switcherFocusIndex = Math.max(0, switcherFocusIndex - 1);
        renderSwitcherList(items, e.target.value);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        const list = $('switcher-list');
        const focused = list && list.querySelector('.focused');
        if (focused) focused.click();
      }
    });
  }
  document.addEventListener('keydown', (e) => {
    // Global '/' opens the switcher unless the user is typing into
    // an input/textarea/contenteditable.
    const tag = (e.target && e.target.tagName) || '';
    const inField = tag === 'INPUT' || tag === 'TEXTAREA' || (e.target && e.target.isContentEditable);
    if (e.key === 'Escape') {
      closeSwitcher();
      return;
    }
    if (inField) return;
    if (e.key === '/' || ((e.metaKey || e.ctrlKey) && (e.key === 'p' || e.key === 'P'))) {
      e.preventDefault();
      openSwitcher();
    }
  });

  // ----- OTHER LOCATIONS group toggle -----------------------------
  const noiseToggle = $('noise-toggle');
  if (noiseToggle) noiseToggle.addEventListener('click', toggleNoiseGroup);

  // ----- URL fragment listener ------------------------------------
  // Browser back/forward should restore the tab in the fragment.
  window.addEventListener('hashchange', () => {
    const want = readURLFragment();
    if (want === null) return;
    if (want === '' || want === '__my_projects__' || state.projects.some((p) => p.id === want)) {
      state.activeTab = want || '__my_projects__';
      scheduleRender();
    }
  });

  // Carry the auth token across in-app navigation. Topbar nav links
  // are authored with bare paths in the HTML (no ?t=); on boot, we
  // append the token so clicking POLICY lands on /policy/edit with
  // the same auth cookie-shaped query the dashboard was opened with.
  // Same-origin only — prevents leaking the token to an external href
  // that some future template author might paste in by mistake.
  function annotateNavTokens() {
    if (!token) return;
    document.querySelectorAll('.nav-link').forEach((a) => {
      const href = a.getAttribute('href') || '';
      if (!href || href.startsWith('http')) return; // skip absolute hrefs
      const sep = href.includes('?') ? '&' : '?';
      a.setAttribute('href', href + sep + 't=' + encodeURIComponent(token));
    });
    // Mark the current route so the nav can show an active state.
    const here = window.location.pathname;
    document.querySelectorAll('.nav-link[data-route]').forEach((a) => {
      if (a.dataset.route === here) a.setAttribute('aria-current', 'page');
    });
  }

  wireFilters();
  annotateNavTokens();
  load();
  connectEvents();
})();
