// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, esc, _h, exportCSV, paginator, timeAgo, tabBar, txtColor } from '../api.js';

const _sel = `background:var(--bg-card);border:1px solid var(--border);color:var(--text);padding:5px 8px;font-family:inherit;font-size:11px;border-radius:3px`;

let cleanupPage = 1;
let _nodeList = null;
let _triageMode = false;
let _groupBy = null;   // null | 'package' | 'remediation'
let _cveSortCol = 'score';
let _cveSortAsc = false;
if (window.opencveMatchedOnly === undefined) window.opencveMatchedOnly = true;

export function toggleTriage() { _triageMode = !_triageMode; window.currentPage = 1; window.refreshView(); }
export function setCveGroup(mode) { _groupBy = (_groupBy === mode) ? null : mode; window.currentPage = 1; window.refreshView(); }
export function sortCves(col) {
  if (_cveSortCol === col) _cveSortAsc = !_cveSortAsc;
  else { _cveSortCol = col; _cveSortAsc = false; }
  const dd = document.getElementById('filter-sort');
  if (dd) dd.value = _cveSortCol;
  window.currentPage = 1;
  window.refreshView();
}

export function _exportCves() {
  let qs = 'cves?';
  if (_triageMode) qs += 'triage=true&';
  exportCSV(qs.replace(/&$/, ''));
}

// Intelligence tab sort state
let _intelSortCol = 'severity';
let _intelSortAsc = false;

const _sevOrder = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

function _sortIntel(items, col, asc) {
  return [...items].sort((a, b) => {
    let va, vb;
    if (col === 'severity') {
      va = _sevOrder[a.severity] || 0;
      vb = _sevOrder[b.severity] || 0;
    } else {
      va = a[col]; vb = b[col];
    }
    if (va == null) va = '';
    if (vb == null) vb = '';
    if (typeof va === 'number' && typeof vb === 'number') return asc ? va - vb : vb - va;
    if (typeof va === 'string') va = va.toLowerCase();
    if (typeof vb === 'string') vb = vb.toLowerCase();
    if (va < vb) return asc ? -1 : 1;
    if (va > vb) return asc ? 1 : -1;
    return 0;
  });
}

// Tab router
export async function renderCVEs(el) {
  const tab = window._cveTab || 'list';

  // Sync filter-sort dropdown with current sort column
  const dd = document.getElementById('filter-sort');
  if (dd) {
    if (dd.value !== _cveSortCol) _cveSortCol = dd.value;
    dd.value = _cveSortCol;
  }

  el.innerHTML = tabBar(
    [['list', 'CVEs'], ['intelligence', 'Intelligence'], ['cleanup', 'Cleanup']],
    tab, 'cve'
  ) + '<div id="cve-tab-content"></div>';

  // Toggle CVE-specific filters based on active tab
  const cveFiltersOnly = tab === 'list';
  ['filter-target-type', 'filter-source', 'filter-kev', 'filter-workflow', 'filter-sort'].forEach(id => {
    const f = document.getElementById(id);
    if (f) f.style.display = cveFiltersOnly ? '' : 'none';
  });
  const sevFilter = document.getElementById('filter-severity');
  if (sevFilter) sevFilter.style.display = (tab === 'list' || tab === 'intelligence') ? '' : 'none';

  // Use el.querySelector to find within detached elements (refreshView uses tmp)
  const c = el.querySelector('#cve-tab-content');
  if (tab === 'list') await _renderList(c);
  else if (tab === 'intelligence') await _renderIntelligence(c);
  else await _renderCleanup(c);
}

// Tab 1 : CVE list (existing)
async function _renderList(el) {
  const fs = getFilterSeverity();
  const ft = document.getElementById('filter-target-type').value;
  const src = document.getElementById('filter-source').value;
  const kev = document.getElementById('filter-kev').value;
  const wf = document.getElementById('filter-workflow')?.value || '';
  const q = document.getElementById('search').value.trim();

  // Load settings to know which severities to exclude
  const settings = await api('/settings/alerts').catch(() => ({}));
  const excl = new Set();
  if (settings.cve_count_exclude_medium === 'true') excl.add('medium');
  if (settings.cve_count_exclude_low === 'true') excl.add('low');

  let url = `/cves?page=${currentPage}&per_page=50`;
  if (fs) url += `&severity=${fs}`;
  if (ft) url += `&target_type=${ft}`;
  if (src) url += `&source=${src}`;
  if (kev) url += `&exploited=${kev}`;
  if (wf) url += `&workflow_status=${wf}`;
  url += `&sort=${_cveSortCol}&order=${_cveSortAsc ? 'asc' : 'desc'}`;
  if (q.length >= 2) url += `&search=${encodeURIComponent(q)}`;
  const nid = getFilterNode();
  if (nid) url += `&hostname=${encodeURIComponent(nid)}`;
  if (_triageMode) url += '&triage=true';
  if (_groupBy) url += `&group_by=${_groupBy}`;
  const d = await api(url);

  // Toolbar: triage + group toggles
  const _tb = (active) => `btn-toggle${active ? ' active' : ''}`;
  let html = `<div class="flex items-center gap-8 mb-10 flex-wrap">
    <button data-action="toggleTriage" class="${_tb(_triageMode)}">Triage</button>
    ${_triageMode ? '<span class="text-xs text-accent">KEV + critical score + fixable high/crit</span>' : ''}
    <span class="ml-auto flex gap-xs">
      <button data-action="setCveGroup" data-value="" class="${_tb(!_groupBy)}">Flat</button>
      <button data-action="setCveGroup" data-value="package" class="${_tb(_groupBy==='package')}">By Package</button>
      <button data-action="setCveGroup" data-value="remediation" class="${_tb(_groupBy==='remediation')}">By Fix</button>
      <button data-action="_exportCves" class="${_tb(false)}" title="Export CSV">CSV</button>
    </span>
  </div>`;

  if (d.grouped) {
    // Grouped rendering
    const items = d.items;
    const showFix = d.grouped === 'remediation';
    html += `<div class="table-wrap"><table>
      <thead><tr><th>Package</th><th>Version</th><th>CVEs</th><th>Nodes</th><th>Score</th><th>Severity</th><th>KEV</th>${showFix ? '<th>Fix Status</th><th>Fixed Ver</th>' : ''}<th>Nodes</th></tr></thead><tbody>`;
    if (!items.length) html += `<tr><td colspan="${showFix?10:8}" class="empty">No groups</td></tr>`;
    for (const g of items) {
      const sc = g.max_score >= 70 ? 'red' : g.max_score >= 40 ? 'orange' : 'text-dim';
      const kevTag = g.exploited ? '<span class="badge-kev">KEV</span>' : '';
      const fixC = g.fix_status === 'fixed_available' ? 'green' : g.fix_status === 'not_affected' ? 'accent' : 'text-dim';
      const hosts = (g.hostnames || []).slice(0, 4).join(', ');
      const more = (g.hostnames || []).length > 4 ? ` +${g.hostnames.length - 4}` : '';
      const cves = (g.cve_ids || []).slice(0, 3).map(c => `<span class="clickable text-accent text-xs" data-action="showCVEDetail" data-id="${c}">${esc(c)}</span>`).join(', ');
      const moreC = (g.cve_ids || []).length > 3 ? ` <span class="text-dim text-xs">+${g.cve_ids.length - 3}</span>` : '';
      html += `<tr>
        <td title="${(g.cve_ids||[]).join(', ')}">${esc(g.target)}<div class="cve-target-sub">${cves}${moreC}</div></td>
        <td class="text-sm">${esc(g.installed_ver || '')}</td>
        <td><strong>${g.cve_count}</strong></td>
        <td>${g.node_count}</td>
        <td><span class="${txtColor(sc)} text-bold">${g.max_score}</span></td>
        <td><span class="badge ${g.max_severity}">${esc(g.max_severity || '?')}</span></td>
        <td>${kevTag}</td>
        ${showFix ? `<td class="${txtColor(fixC)} text-sm">${esc((g.fix_status||'unfixed').replace(/_/g,' '))}</td><td class="text-green text-sm">${esc(g.fixed_ver || '—')}</td>` : ''}
        <td class="text-xs">${esc(hosts)}${more ? `<span class="text-dim">${more}</span>` : ''}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';
  } else {
    // Flat rendering (existing)
    const items = (!fs && excl.size) ? d.items.filter(c => !excl.has(c.severity)) : d.items;
    const cArrow = c => _cveSortCol === c ? (_cveSortAsc ? ' ▲' : ' ▼') : ' ▲▼';
    const cTh = (label, col) => `<th class="clickable" data-action="sortCves" data-id="${col}">${label}${cArrow(col)}</th>`;
    html += `<div class="table-wrap"><table>
      <thead><tr><th>CVE</th>${cTh('Score', 'score')}${cTh('Severity', 'severity')}${cTh('CVSS', 'cvss')}<th>Fix</th><th>Target</th><th>Node</th><th>Workflow</th></tr></thead><tbody>`;
    if (!items.length) html += '<tr><td colspan="8" class="empty">No CVEs</td></tr>';
    for (const c of items) {
      const fixClass = c.fix_status === 'fixed_available' ? 'green'
                     : c.fix_status === 'not_affected'    ? 'accent'
                     : c.fix_status === 'under_investigation' ? 'orange' : 'text-dim';
      const kevTag = c.exploited
        ? ' <span class="badge-kev">KEV</span>'
        : '';
      const scoreColor = c.score >= 70 ? 'red' : c.score >= 40 ? 'orange' : 'text-dim';
      const justifIcon = c.justification ? ' <span title="' + esc(c.justification) + '" class="justif-icon">&#9432;</span>' : '';
      const ocveUrl = `https://app.opencve.io/cve/${c.cve_id}`;
      const wf = c.workflow_status || 'open';
      const wfColors = {open:'text-dim',acknowledged:'accent',in_progress:'orange',mitigated:'green',resolved:'green',false_positive:'purple',accepted_risk:'yellow'};
      const wfOpts = ['open','acknowledged','in_progress','mitigated','resolved','false_positive','accepted_risk'];
      const wfSelect = `<select data-change="setCveWorkflow" data-cve="${c.cve_id}" data-node="${c.node_id}" class="form-select-inline ${txtColor(wfColors[wf]||'text-dim')}">${wfOpts.map(o=>`<option value="${o}" ${o===wf?'selected':''} class="${txtColor(wfColors[o]||'text-dim')}">${o.replace(/_/g,' ')}</option>`).join('')}</select>`;
      html += `<tr${c.exploited ? ' class="row-kev"' : ''}>
        <td class="clickable" data-action="showCVEDetail" data-id="${c.cve_id}">${esc(c.cve_id)}${justifIcon} <a href="${esc(ocveUrl)}" target="_blank" rel="noopener" data-stop title="OpenCVE" class="text-dim text-xs no-underline">&#8599;</a></td>
        <td><span class="${txtColor(scoreColor)} text-bold">${c.score}</span>${kevTag}</td>
        <td><span class="badge ${c.severity}">${esc(c.severity)}</span></td>
        <td>${c.cvss_score || '-'}</td>
        <td class="${txtColor(fixClass)} text-sm">${esc((c.fix_status || 'unfixed').replace(/_/g,' '))}</td>
        <td>${esc(c.target)}</td>
        <td class="clickable" data-action="showNode" data-id="${c.node_id}">${esc(c.hostname)}</td>
        <td>${wfSelect}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';
  }
  html += paginator(d.total, d.page, d.per_page);
  el.innerHTML = html;
}

// Tab 2 : Intelligence (OpenCVE alerts)
async function _renderIntelligence(el) {
  _intelEl = el;
  const fs = getFilterSeverity();
  let url = `/opencve/alerts?page=${currentPage}&per_page=50&matched_only=${opencveMatchedOnly}`;
  if (fs) url += `&severity=${fs}`;
  const [d, advisories] = await Promise.all([
    api(url),
    api(`/cve-feeds/advisories?per_page=20&matched_only=${opencveMatchedOnly}`)
      .catch(() => ({ items: [], total: 0 })),
  ]);
  const items = _sortIntel(d.items, _intelSortCol, _intelSortAsc);

  const arrow = c => _intelSortCol === c ? (_intelSortAsc ? ' ▲' : ' ▼') : ' ▲▼';
  const th = (label, col) => `<th class="clickable" data-action="_intelSort" data-id="${col}">${label}${arrow(col)}</th>`;

  let html = `<div class="mb-12 flex items-center gap-lg">
    <label class="flex items-center gap-sm cursor-pointer text-md text-dim">
      <input type="checkbox" ${opencveMatchedOnly ? 'checked' : ''}
        data-change="opencveMatchedOnly"
        class="f-accent-color">
      Infra only
    </label>
    <span class="text-sm text-dim">${d.matched_only ? 'Showing CVEs detected on your infrastructure' : 'Showing all OpenCVE alerts'}</span>
  </div>`;

  // Feed advisories (CERT-FR + custom RSS/Atom) — surfaced before OpenCVE
  // table so the user sees high-context bulletins first.
  const advItems = advisories.items || [];
  html += `<div class="detail-section mb-16">
    <h3>Advisory feeds <span class="text-sm text-dim">(${advisories.total || 0}${opencveMatchedOnly ? ' impacting your infra' : ''})</span></h3>`;
  if (!advItems.length) {
    html += `<div class="empty">No advisories${opencveMatchedOnly ? ' matching your inventory' : ''} yet. Configure feeds in <a href="#settings" class="link">Settings &gt; CVE</a>.</div>`;
  } else {
    html += `<div class="table-wrap"><table>
      <tr><th>Source</th><th>Title</th><th>Sev</th><th>CVEs</th><th>Nodes</th><th>Published</th></tr>`;
    for (const a of advItems) {
      const cveBadges = (a.cve_ids || []).slice(0, 3).map(c =>
        `<span class="clickable text-mono text-xs" data-action="showCVEDetail" data-id="${esc(c)}">${esc(c)}</span>`
      ).join(' ');
      const more = (a.cve_ids || []).length > 3 ? ` <span class="text-xs text-dim">+${a.cve_ids.length - 3}</span>` : '';
      const sevBadge = a.severity
        ? `<span class="badge ${a.severity}">${esc(a.severity)}</span>`
        : '<span class="text-dim">—</span>';
      const titleCell = a.url
        ? `<a href="${esc(a.url)}" target="_blank" rel="noopener" class="link truncate-w-300">${esc(a.title)}</a>`
        : `<span class="truncate-w-300">${esc(a.title)}</span>`;
      const matchedCls = a.matched_node_count > 0 ? 'text-orange text-bold' : 'text-dim';
      html += `<tr>
        <td class="text-mono text-xs">${esc(a.source_label || a.feed_name || '')}</td>
        <td>${titleCell}</td>
        <td>${sevBadge}</td>
        <td>${cveBadges}${more}</td>
        <td class="${matchedCls}">${a.matched_node_count || 0}</td>
        <td class="text-xs text-dim">${a.published_at ? timeAgo(a.published_at) : '—'}</td>
      </tr>`;
    }
    html += '</table></div>';
  }
  html += '</div>';

  const cols = opencveMatchedOnly ? 9 : 8;
  html += `<div class="table-wrap"><table>
    <tr>${th('CVE','cve_id')}${th('Severity','severity')}${th('CVSS','cvss_v3')}${th('Vendor','vendor')}${th('Product','product')}${th('Title','title')}${opencveMatchedOnly ? th('Nodes','affected_nodes') : ''}<th>Impact</th>${th('Date','created_at')}</tr>`;
  if (!items.length) html += `<tr><td colspan="${cols}" class="empty">${opencveMatchedOnly ? 'No OpenCVE alerts match your infrastructure' : 'No OpenCVE alerts'}</td></tr>`;
  for (const a of items) {
    html += `<tr>
      <td class="clickable" data-action="showCVEDetail" data-id="${a.cve_id}">${esc(a.cve_id)}</td>
      <td><span class="badge ${a.severity}">${esc(a.severity)}</span></td>
      <td>${a.cvss_v3 || '-'}</td>
      <td>${esc(a.vendor || '')}</td>
      <td>${esc(a.product || '')}</td>
      <td class="truncate-w-300">${esc(a.title || '')}</td>
      ${opencveMatchedOnly ? `<td class="text-accent">${a.affected_nodes || 0}</td>` : ''}
      <td><button data-action="showImpact" data-id="${a.cve_id}" class="chip-accent-btn">Impact</button></td>
      <td>${timeAgo(a.created_at)}</td>
    </tr>`;
  }
  html += '</table></div>';
  html += paginator(d.total, d.page, d.per_page);
  el.innerHTML = html;

}

let _intelEl = null;
export function _intelSort(col) {
  if (_intelSortCol === col) _intelSortAsc = !_intelSortAsc;
  else { _intelSortCol = col; _intelSortAsc = col === 'severity' ? false : true; }
  if (_intelEl) _renderIntelligence(_intelEl);
}

// Tab 3 : Cleanup
async function _renderCleanup(el) {
  // Load node list for dropdown
  if (!_nodeList) {
    try { const d = await api('/nodes/list'); _nodeList = d.items || []; } catch { _nodeList = []; }
  }
  const nodeOpts = _nodeList.map(n => `<option value="${esc(n.id)}">${esc(n.hostname)}</option>`).join('');

  el.innerHTML = `
    <div class="cleanup-row">
      <label class="text-sm text-dim">Node
        <select id="cl-node" class="form-select-chip">
          <option value="">All nodes</option>
          ${_h(nodeOpts)}
        </select>
      </label>
      <label class="text-sm text-dim">Package
        <input id="cl-pkg" placeholder="Search..." class="form-select-chip w-120">
      </label>
      <label class="text-sm text-dim">Severity
        <select id="cl-severity" class="form-select-chip">
          <option value="">All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </label>
      <label class="text-sm text-dim">Target
        <select id="cl-target" class="form-select-chip">
          <option value="">All</option>
          <option value="package">Package</option>
          <option value="container">Container</option>
        </select>
      </label>
      <label class="text-sm text-dim">Fix Status
        <select id="cl-fix" class="form-select-chip">
          <option value="">All</option>
          <option value="fixed_available">Fixed available</option>
          <option value="unfixed">Unfixed</option>
          <option value="not_affected">Not affected</option>
          <option value="will_not_fix">Won't fix</option>
        </select>
      </label>
      <label class="text-sm text-dim">Status
        <select id="cl-status" class="form-select-chip">
          <option value="open">Open</option>
          <option value="">All</option>
          <option value="mitigated">Mitigated</option>
          <option value="ignored">Ignored</option>
          <option value="resolved">Resolved</option>
        </select>
      </label>
      <label class="text-sm text-dim">Older than (days)
        <input id="cl-days" type="number" min="0" placeholder="—" class="form-select-chip w-60">
      </label>
      <label class="text-sm text-dim">KEV
        <select id="cl-kev" class="form-select-chip">
          <option value="">All</option>
          <option value="true">KEV only</option>
          <option value="false">Non-KEV</option>
        </select>
      </label>
      <label class="text-sm text-dim">OS
        <select id="cl-os" class="form-select-chip">
          <option value="">All</option>
          <option value="debian">Debian</option>
          <option value="rocky">Rocky Linux</option>
          <option value="arch">Arch Linux</option>
          <option value="ubuntu">Ubuntu</option>
          <option value="alpine">Alpine</option>
        </select>
      </label>
      <label class="text-sm text-dim">Arch
        <select id="cl-arch" class="form-select-chip">
          <option value="">All</option>
          <option value="x86_64">x86_64</option>
          <option value="aarch64">aarch64 / ARM</option>
          <option value="armv7">armv7</option>
        </select>
      </label>
      <button data-action="cleanupPreview" class="btn btn-primary pad-5-12">Preview</button>
    </div>
    <div id="cl-preview" class="mb-16"></div>
    <div id="cl-actions" class="hidden mb-16">
      <div class="flex gap-8 flex-wrap mb-8">
        <span class="bulk-label">Bulk (all matching):</span>
        <button data-action="cleanupExec" data-id="resolve" class="btn btn-primary pad-4-10">Resolve all</button>
        <button data-action="cleanupExec" data-id="ignore" class="btn btn-warning pad-4-10">Ignore all</button>
        <button data-action="cleanupExec" data-id="delete" class="btn btn-danger pad-4-10">Delete all</button>
        <span class="bulk-sep"></span>
        <button data-action="cleanupAutoResolve" class="btn btn-primary pad-4-10">Auto-resolve (not_affected + won't fix)</button>
        <button data-action="cleanupPurgeOrphans" class="btn btn-warning pad-4-10">Purge orphan CVEs</button>
        <button data-action="cleanupRescan" class="btn btn-surface pad-4-10">Rescan via OpenCVE</button>
      </div>
      <div id="cl-selected-actions" class="hidden flex gap-8 flex-wrap">
        <span class="bulk-sel-count" id="cl-sel-count">0 selected</span>
        <button data-action="cleanupExecSelected" data-id="resolve" class="btn btn-primary pad-4-10">Resolve selected</button>
        <button data-action="cleanupExecSelected" data-id="ignore" class="btn btn-warning pad-4-10">Ignore selected</button>
        <button data-action="cleanupExecSelected" data-id="delete" class="btn btn-danger pad-4-10">Delete selected</button>
      </div>
    </div>
    <div id="cl-result" class="mb-12"></div>
    <div id="cl-table"></div>`;

  await cleanupPreview();
}

function _getCleanupFilters() {
  const f = {};
  const sev = document.getElementById('cl-severity')?.value;
  const tgt = document.getElementById('cl-target')?.value;
  const fix = document.getElementById('cl-fix')?.value;
  const st = document.getElementById('cl-status')?.value;
  const days = document.getElementById('cl-days')?.value;
  const kev = document.getElementById('cl-kev')?.value;
  const os = document.getElementById('cl-os')?.value;
  const arch = document.getElementById('cl-arch')?.value;
  const node = document.getElementById('cl-node')?.value;
  const pkg = document.getElementById('cl-pkg')?.value?.trim();
  if (sev) f.severity = sev;
  if (tgt) f.target_type = tgt;
  if (fix) f.fix_status = fix;
  if (st) f.status = st;
  if (days) f.older_than_days = parseInt(days);
  if (kev) f.exploited = kev;
  if (os) f.os = os;
  if (arch) f.arch = arch;
  if (node) f.node_id = node;
  if (pkg) f.pkg_name = pkg;
  return f;
}

function _filterQuery(f) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) {
    if (v != null && v !== '') p.set(k, v);
  }
  return p.toString();
}

export async function cleanupPreview() {
  const f = _getCleanupFilters();
  const qs = _filterQuery(f);
  const prev = document.getElementById('cl-preview');
  const actions = document.getElementById('cl-actions');
  const tbl = document.getElementById('cl-table');
  if (!prev) return;
  prev.innerHTML = '<span class="text-dim">Loading...</span>';

  try {
    const d = await api(`/findings/cleanup/preview?${qs}`);

    const sevBadges = Object.entries(d.by_severity)
      .filter(([, v]) => v > 0)
      .map(([k, v]) => `<span class="badge ${esc(k)} text-xs">${esc(k)}: ${esc(v)}</span>`)
      .join(' ');

    const fixBadges = Object.entries(d.by_fix_status)
      .filter(([, v]) => v > 0)
      .map(([k, v]) => {
        const cls = k === 'fixed_available' ? 'green' : k === 'not_affected' ? 'accent' : 'text-dim';
        return `<span class="${txtColor(cls)} text-sm">${esc(k.replace(/_/g,' '))}: ${esc(v)}</span>`;
      })
      .join(' &middot; ');

    prev.innerHTML = `
      <div class="bg-card border rounded p-12">
        <div class="cve-total">${esc(d.total)} <span class="text-md text-dim">CVEs matching</span></div>
        <div class="mt-6 text-sm">
          Host packages: <b>${esc(d.host_count)}</b> &middot; Containers: <b>${esc(d.container_count)}</b>
        </div>
        <div class="mt-6 flex gap-sm flex-wrap">${_h(sevBadges)}</div>
        <div class="mt-4">${_h(fixBadges)}</div>
      </div>`;

    actions.style.display = d.total > 0 ? 'flex' : 'none';

    // Load table
    if (d.total > 0) {
      const list = await api(`/findings/cleanup/list?${qs}&page=${cleanupPage}&per_page=50`);
      _renderCleanupTable(tbl, list);
    } else {
      tbl.innerHTML = '';
    }
  } catch (e) {
    prev.innerHTML = `<span class="text-red">Error: ${esc(e.message)}</span>`;
  }
}

function _renderCleanupTable(el, data) {
  let html = `<div class="table-wrap"><table>
    <tr><th><input type="checkbox" id="cl-select-all" data-change="clToggleAll" class="f-accent-color"></th><th>CVE</th><th>Severity</th><th>CVSS</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Fix Status</th><th>Type</th><th>Node</th><th>OS</th><th>Scanned</th></tr>`;
  if (!data.items.length) {
    html += '<tr><td colspan="12" class="empty">No results</td></tr>';
  }
  for (const c of data.items) {
    const fixClass = c.fix_status === 'fixed_available' ? 'green'
                   : c.fix_status === 'not_affected' ? 'accent'
                   : c.fix_status === 'will_not_fix' ? 'orange' : 'text-dim';
    const kevTag = c.exploited
      ? ' <span class="badge-kev">KEV</span>'
      : '';
    const scanned = c.scanned_at ? new Date(c.scanned_at).toLocaleDateString() : '-';
    const osShort = (c.os || '').replace('GNU/Linux', '').trim();
    html += `<tr>
      <td><input type="checkbox" class="cl-check f-accent-color" value="${c.id}" data-change="clUpdateCount"></td>
      <td class="clickable" data-action="showCVEDetail" data-id="${esc(c.cve_id)}">${esc(c.cve_id)}${kevTag}</td>
      <td><span class="badge ${c.severity}">${esc(c.severity)}</span></td>
      <td>${c.cvss_score || '-'}</td>
      <td class="text-sm">${esc(c.pkg_name)}</td>
      <td class="text-xs text-dim">${esc(c.installed_ver)}</td>
      <td class="text-xs text-green">${esc(c.fixed_ver || '-')}</td>
      <td class="${txtColor(fixClass)} text-sm">${esc((c.fix_status || 'unfixed').replace(/_/g,' '))}</td>
      <td class="text-xs">${c.target_type === 'container' ? esc(c.image || 'container') : 'host'}</td>
      <td>${esc(c.hostname)}</td>
      <td class="text-xs text-dim">${esc(osShort)}</td>
      <td class="text-xs text-dim">${scanned}</td>
    </tr>`;
  }
  html += '</table></div>';
  html += paginator(data.total, data.page, data.per_page);
  el.innerHTML = html;
}

function _getSelectedIds() {
  return [...document.querySelectorAll('.cl-check:checked')].map(cb => cb.value);
}

export async function cleanupExec(action) {
  const f = _getCleanupFilters();
  const hasFilter = Object.keys(f).length > 0;
  if (!hasFilter) {
    alert('Select at least one filter before bulk action.');
    return;
  }
  const labels = { resolve: 'RESOLVE', ignore: 'IGNORE', delete: 'DELETE' };
  if (!confirm(`${labels[action]} all matching CVEs? This cannot be undone for delete.`)) return;

  const res = document.getElementById('cl-result');
  try {
    const body = { action, ...f };
    const r = await fetch('/api/v1/findings/cleanup/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (d.error) {
      res.innerHTML = `<span class="text-red">${esc(d.error)}</span>`;
    } else {
      res.innerHTML = `<span class="text-green">${esc(d.affected)} CVEs ${esc(action)}d</span>`;
      await cleanupPreview();
    }
  } catch (e) {
    res.innerHTML = `<span class="text-red">Error: ${esc(e.message)}</span>`;
  }
}

export async function cleanupAutoResolve() {
  if (!confirm('Auto-resolve all open CVEs with fix_status not_affected or will_not_fix?')) return;
  const res = document.getElementById('cl-result');
  try {
    const r = await fetch('/api/v1/findings/auto-resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const d = await r.json();
    res.innerHTML = `<span class="text-green">${esc(d.resolved)} CVEs auto-resolved (not_affected: ${esc(d.breakdown.not_affected)}, won't fix: ${esc(d.breakdown.will_not_fix)})</span>`;
    await cleanupPreview();
  } catch (e) {
    res.innerHTML = `<span class="text-red">Error: ${esc(e.message)}</span>`;
  }
}

export async function cleanupExecSelected(action) {
  const ids = _getSelectedIds();
  if (!ids.length) { alert('Select at least one CVE.'); return; }
  const labels = { resolve: 'RESOLVE', ignore: 'IGNORE', delete: 'DELETE' };
  if (!confirm(`${labels[action]} ${ids.length} selected CVEs?`)) return;

  const res = document.getElementById('cl-result');
  try {
    const r = await fetch('/api/v1/findings/cleanup/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, ids }),
    });
    const d = await r.json();
    if (d.error) {
      res.innerHTML = `<span class="text-red">${esc(d.error)}</span>`;
    } else {
      res.innerHTML = `<span class="text-green">${esc(d.affected)} CVEs ${esc(action)}d</span>`;
      await cleanupPreview();
    }
  } catch (e) {
    res.innerHTML = `<span class="text-red">Error: ${esc(e.message)}</span>`;
  }
}

export function _clToggleAll(checked) {
  document.querySelectorAll('.cl-check').forEach(cb => { cb.checked = checked; });
  _clUpdateCount();
}

export function _clUpdateCount() {
  const count = _getSelectedIds().length;
  const el = document.getElementById('cl-sel-count');
  const actions = document.getElementById('cl-selected-actions');
  if (el) el.textContent = `${count} selected`;
  if (actions) actions.style.display = count > 0 ? 'flex' : 'none';
}

export async function cleanupPurgeOrphans() {
  const res = document.getElementById('cl-result');
  res.innerHTML = '<span class="text-dim">Counting orphan CVEs...</span>';
  let preview;
  try {
    preview = await api('/findings/orphan-cves/preview');
  } catch (e) {
    res.innerHTML = `<span class="text-red">Error: ${esc(e.message)}</span>`;
    return;
  }
  const cves = preview.cves_total || 0;
  const secrets = preview.secrets_total || 0;
  const imgCount = preview.image_count || 0;
  if (cves === 0 && secrets === 0) {
    res.innerHTML = `
      <div class="bg-card border rounded p-12">
        <div class="text-md">No orphan findings.</div>
        <div class="mt-4 text-sm text-dim">
          Every container CVE is still tied to an image present in
          <code>container_images</code>. Nothing to purge.
        </div>
      </div>`;
    return;
  }
  const rows = (preview.images || []).map(i =>
    `<tr><td class="text-mono text-sm">${esc(i.image)}</td><td class="text-right">${esc(i.cve_count)}</td></tr>`
  ).join('');
  const secretsSuffix = secrets ? ` + ${esc(secrets)} secrets` : '';
  res.innerHTML = `
    <div class="bg-card border rounded p-12">
      <div class="cve-total">${esc(cves)} <span class="text-md text-dim">orphan CVEs</span></div>
      <div class="mt-6 text-sm">
        Across <b>${esc(imgCount)}</b> image(s) no longer in <code>container_images</code>
        &middot; Secrets: <b>${esc(secrets)}</b>
      </div>
      <div class="mt-6 text-xs text-dim">
        Findings keep their audit trail (cve_status row with justification
        <code>image_orphan_manual_purge</code>). A later rescan won't reopen them.
      </div>
      <div class="mt-12 table-wrap">
        <table>
          <tr><th>Image</th><th class="text-right">CVEs</th></tr>
          ${_h(rows)}
        </table>
      </div>
      <div class="mt-12 flex gap-8">
        <button data-action="cleanupPurgeOrphansConfirm" class="btn btn-warning pad-4-10">
          Resolve ${esc(cves)} CVEs${_h(secretsSuffix)}
        </button>
        <button data-action="cleanupPurgeOrphansCancel" class="btn btn-surface pad-4-10">Cancel</button>
      </div>
    </div>`;
}

export async function cleanupPurgeOrphansCancel() {
  const res = document.getElementById('cl-result');
  if (res) res.innerHTML = '';
}

export async function cleanupPurgeOrphansConfirm() {
  const res = document.getElementById('cl-result');
  res.innerHTML = '<span class="text-dim">Purging...</span>';
  try {
    const r = await fetch('/api/v1/findings/orphan-cves/purge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const d = await r.json();
    if (d.status !== 'ok') {
      res.innerHTML = `<span class="text-red">Error: ${esc(JSON.stringify(d))}</span>`;
      return;
    }
    res.innerHTML = `<span class="text-green">${esc(d.cves_resolved)} CVEs resolved, ${esc(d.secrets_resolved)} secrets resolved</span>`;
    await cleanupPreview();
  } catch (e) {
    res.innerHTML = `<span class="text-red">Error: ${esc(e.message)}</span>`;
  }
}

export async function cleanupRescan() {
  const res = document.getElementById('cl-result');
  res.innerHTML = '<span class="text-dim">Rescanning via OpenCVE... this may take a minute.</span>';
  try {
    const r = await fetch('/api/v1/opencve/rescan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ limit: 200 }),
    });
    const d = await r.json();
    if (d.error) {
      res.innerHTML = `<span class="text-orange">${esc(d.error)}</span>`;
    } else {
      const kevSuffix = d.kev_propagated ? `, ${esc(d.kev_propagated)} KEV propagated` : '';
      res.innerHTML = `<span class="text-green">Rescan: ${esc(d.scanned)} checked, ${esc(d.updated)} updated, ${esc(d.errors)} errors${_h(kevSuffix)}</span>`;
      await cleanupPreview();
    }
  } catch (e) {
    res.innerHTML = `<span class="text-red">Error: ${esc(e.message)}</span>`;
  }
}
