// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, esc, exportCSV, paginator, timeAgo, typeBadges, txtColor } from '../api.js';

let _sortCol = null;
let _sortAsc = true;
let _searchQ = '';

export async function renderNodes(el) {
  const ft = getFilterType();
  const env = getFilterSeverity();  // repurposed as env filter for nodes
  const hostQ = getFilterNode();
  let url = `/nodes?page=${currentPage}&per_page=50`;
  if (ft) url += `&type=${ft}`;
  if (env) url += `&environment=${env}`;
  if (hostQ) url += `&hostname=${encodeURIComponent(hostQ)}`;
  if (_searchQ.trim()) url += `&search=${encodeURIComponent(_searchQ.trim())}`;
  if (_sortCol) url += `&sort_by=${_sortCol}&sort_dir=${_sortAsc ? 'asc' : 'desc'}`;
  const [d, settings] = await Promise.all([
    api(url),
    api('/settings/alerts').catch(() => ({})),
  ]);

  const exMed = settings.cve_count_exclude_medium === 'true';
  const exLow = settings.cve_count_exclude_low === 'true';
  const filterNote = [exLow ? 'low' : '', exMed ? 'med' : ''].filter(Boolean).join('+');
  const allLabel = filterNote ? `ALL (excl ${filterNote})` : 'ALL';

  const arrow = c => _sortCol === c ? (_sortAsc ? ' ▲' : ' ▼') : ' ▲▼';
  const th = (label, col) => `<th class="clickable" data-action="sortNodes" data-id="${col}">${label}${arrow(col)}</th>`;

  let html = `<div class="flex gap-sm flex-wrap items-center mb-12">
    <input type="text" placeholder="Search type, env, OS…" value="${esc(_searchQ)}"
           data-change="nodesSearch" class="f-filter w-200">
    <span class="ml-auto"><button data-action="_exportNodes" class="btn btn-ghost" title="Export CSV">CSV</button></span>
  </div>`;
  html += `<div class="table-wrap"><table>
    <thead><tr>
      ${th('Hostname', 'hostname')}
      <th>Type</th>
      ${th('Env', 'env')}
      ${th('OS', 'os')}
      ${th('Pkgs', 'pkgs')}
      ${th('Containers', 'containers')}
      <th class="clickable text-center" data-action="sortNodes" data-id="cve_host">CVEs HOST${arrow('cve_host')}<br><span class="text-xs fw-400"><span class="text-red">CRIT</span> / <span class="text-orange">${allLabel}</span></span></th>
      <th class="clickable text-center" data-action="sortNodes" data-id="cve_ctr">CVEs CTR${arrow('cve_ctr')}<br><span class="text-xs fw-400"><span class="text-red">CRIT</span> / <span class="text-orange">${allLabel}</span></span></th>
      ${th('Last scan', 'last_seen')}
    </tr></thead><tbody>`;
  if (!d.items.length) html += '<tr><td colspan="9" class="empty">No nodes</td></tr>';
  const envColors = {production:'red',staging:'orange',development:'accent',lab:'text-dim'};
  const envOpts = ['production','staging','development','lab'];
  for (const n of d.items) {
    const osName = n.os || '';
    const hCrit = n.cve_package_critical || 0;
    const hAll = n.cve_package_count || 0;
    const cCrit = n.cve_container_critical || 0;
    const cAll = n.cve_container_count || 0;
    const ec = envColors[n.environment] || 'text-dim';
    html += `<tr>
      <td class="clickable" data-action="showNode" data-id="${n.id}">${esc(n.hostname)}</td>
      <td>${typeBadges(n.type)}</td>
      <td><select data-change="setNodeEnv" data-id="${n.id}" class="form-select-inline ${txtColor(ec)}">
        ${envOpts.map(e=>`<option value="${e}" ${n.environment===e?'selected':''} class="${txtColor(envColors[e]||'text-dim')}">${e.slice(0,4)}</option>`).join('')}
      </select></td>
      <td class="clickable" data-action="showOsNodes" data-id="${esc(osName)}">${esc(osName)} ${esc(n.os_version || '')}</td>
      <td class="clickable" data-action="showNode" data-id="${n.id}">${n.package_count}</td>
      <td class="clickable" data-action="showNode" data-id="${n.id}">${n.container_count}</td>
      <td class="clickable text-center" data-action="showNode" data-id="${n.id}">
        <span class="text-red text-bolder">${hCrit}</span>
        <span class="text-dim text-xs">/</span>
        <span class="text-orange">${hAll}</span>
      </td>
      <td class="clickable text-center" data-action="showNode" data-id="${n.id}">
        <span class="text-red text-bolder">${cCrit}</span>
        <span class="text-dim text-xs">/</span>
        <span class="text-orange">${cAll}</span>
      </td>
      <td>${timeAgo(n.last_seen)}</td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  html += paginator(d.total, d.page, d.per_page);
  el.innerHTML = html;
}

export function sortNodes(col) {
  if (_sortCol === col) _sortAsc = !_sortAsc;
  else { _sortCol = col; _sortAsc = col === 'hostname'; }
  window.currentPage = 1;
  window.refreshView();
}

export function _exportNodes() { exportCSV('nodes'); }

export function nodesSearch(v) {
  _searchQ = v || '';
  window.currentPage = 1;
  window.refreshView();
}
