// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, paginator, timeAgo, txtColor } from '../api.js';

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
const SEV_COLORS = { critical: 'red', high: 'orange', medium: 'yellow', low: 'green', unknown: 'text-dim' };

let _sortCol = 'cvss';
let _sortAsc = false;
let _filterFix = 'all';
let _searchQ = '';

function sortItems(items, col, asc) {
  return [...items].sort((a, b) => {
    let va, vb;
    if (col === 'severity') {
      va = SEV_ORDER[a.max_severity] ?? 4;
      vb = SEV_ORDER[b.max_severity] ?? 4;
    } else if (col === 'cvss') {
      va = a.max_cvss ?? 0; vb = b.max_cvss ?? 0;
    } else if (col === 'cves') {
      va = a.cve_count; vb = b.cve_count;
    } else if (col === 'nodes') {
      va = a.node_count; vb = b.node_count;
    } else if (col === 'fix') {
      va = a.has_fix ? 1 : 0; vb = b.has_fix ? 1 : 0;
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

export async function renderUpdates(el) {
  const search = (document.getElementById('search')?.value || '').trim();
  const pkgQ = (window.getFilterPackage?.() || '').trim();
  const nodeId = window.getFilterNode?.() || '';
  const severity = window.getFilterSeverity?.() || '';

  let qs = `?page=${currentPage}&per_page=50`;
  // Per-view in-view search (package/CVE) takes precedence over the
  // global #search, then over the package filter input.
  const localQ = _searchQ.trim();
  const effectiveQ = localQ || search || (pkgQ.length >= 2 ? pkgQ : '');
  if (effectiveQ) qs += `&search=${encodeURIComponent(effectiveQ)}`;
  if (nodeId) qs += `&hostname=${encodeURIComponent(nodeId)}`;
  if (severity) qs += `&severity=${severity}`;
  if (_filterFix !== 'all') qs += `&fix_status=${_filterFix}`;

  const [d, summary] = await Promise.all([
    api(`/pkg-updates${qs}`),
    api('/pkg-updates/summary'),
  ]);

  const items = sortItems(d.items, _sortCol, _sortAsc);

  const arrow = c => _sortCol === c ? (_sortAsc ? ' ▲' : ' ▼') : ' ▲▼';
  const th = (label, col) => `<th class="clickable" data-action="_updSort" data-id="${col}">${label}${arrow(col)}</th>`;

  const fixBtns = [
    ['all', 'All'],
    ['fixed_available', 'Fixable'],
    ['unfixed', 'Unfixed'],
  ];
  const fixFilter = fixBtns.map(([v, l]) =>
    `<button data-action="_updFilter" data-id="${v}" class="upd-filter-btn${_filterFix === v ? ' active' : ''}">${l}</button>`
  ).join('');

  let html = `<div class="flex gap-sm flex-wrap items-center mb-12">
    <input type="text" placeholder="Search package, CVE\u2026" value="${esc(_searchQ)}"
           data-change="updatesSearch" class="f-filter w-200">
  </div>`;
  html += `<div class="flex gap-sm mb-14 items-center flex-wrap">
    ${fixFilter}
    <span class="text-md text-dim">
      ${summary.packages_with_cves} packages affected \u2014
      <span class="text-red">${summary.critical} critical</span>,
      <span class="text-green">${summary.fixable} fixable</span>${summary.exploited ? `, <span class="text-red text-bold">${summary.exploited} exploited</span>` : ''}
    </span>
  </div>`;

  html += `<div class="table-wrap"><table>
    <thead><tr>${th('Package', 'pkg_name')}${th('Installed', 'installed_ver')}${th('Fixed', 'fix')}${th('Severity', 'severity')}${th('CVSS', 'cvss')}${th('CVEs', 'cves')}${th('Nodes', 'nodes')}<th>KEV</th><th>CVE IDs</th><th>Seen</th></tr></thead><tbody>`;

  if (!items.length) {
    html += '<tr><td colspan="10" class="empty">No vulnerable packages found</td></tr>';
  }

  for (const r of items) {
    const sev = r.max_severity || 'unknown';
    const sevColor = SEV_COLORS[sev] || 'text-dim';
    const fixBadge = r.has_fix
      ? `<span class="text-green text-bold">${esc(r.fixed_ver || 'yes')}</span>`
      : '<span class="text-dim">\u2014</span>';
    const kevBadge = r.exploited
      ? '<span class="text-red text-bold">KEV</span>'
      : '';

    // Show max 3 CVE IDs, then "+N more"
    const cveList = r.cve_ids || [];
    const shown = cveList.slice(0, 3);
    const more = cveList.length > 3 ? ` <span class="text-dim text-xs">+${cveList.length - 3}</span>` : '';
    const cveLinks = shown.map(c =>
      `<span class="clickable text-xs" data-action="showCVEDetail" data-id="${esc(c)}">${esc(c)}</span>`
    ).join(', ') + more;

    const hosts = (r.hostnames || []).slice(0, 3).map(h => esc(h)).join(', ');
    const moreHosts = (r.hostnames || []).length > 3 ? ` +${r.hostnames.length - 3}` : '';

    html += `<tr>
      <td class="clickable text-bold" data-action="showPackageHosts" data-id="${esc(r.pkg_name)}">${esc(r.pkg_name)}</td>
      <td class="text-mono text-sm">${esc(r.installed_ver || '\u2014')}</td>
      <td>${fixBadge}</td>
      <td><span class="badge ${sev} ${txtColor(sevColor)} text-bold">${sev}</span></td>
      <td class="text-mono text-sm">${r.max_cvss != null ? r.max_cvss.toFixed(1) : '\u2014'}</td>
      <td class="text-bold">${r.cve_count}</td>
      <td class="text-sm text-dim" title="${esc((r.hostnames || []).join(', '))}">${r.node_count} <span class="text-xs">(${hosts}${moreHosts})</span></td>
      <td>${kevBadge}</td>
      <td class="upd-cve-cell">${cveLinks}</td>
      <td class="text-xs text-dim">${r.last_seen ? timeAgo(r.last_seen) : '\u2014'}</td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  html += paginator(d.total, d.page, d.per_page);
  el.innerHTML = html;

}

export function _updSort(col) {
  if (_sortCol === col) _sortAsc = !_sortAsc;
  else { _sortCol = col; _sortAsc = col === 'pkg_name'; }
  window.refreshView();
}

export function _updFilter(f) {
  _filterFix = f;
  window.currentPage = 1;
  window.refreshView();
}

export function updatesSearch(v) {
  _searchQ = v || '';
  window.currentPage = 1;
  window.refreshView();
}
