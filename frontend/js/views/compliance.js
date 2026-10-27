// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, esc, exportCSV, txtColor } from '../api.js';

let _sortCol = null;
let _sortAsc = false;
let _filterEnv = '';
let _searchHost = '';

export async function renderCompliance(el) {
  let url = '/compliance?';
  if (_sortCol) url += `sort_by=${_sortCol}&sort_dir=${_sortAsc ? 'asc' : 'desc'}&`;
  if (_filterEnv) url += `environment=${_filterEnv}&`;
  if (_searchHost) url += `search=${encodeURIComponent(_searchHost)}&`;
  const d = await api(url.replace(/[&?]$/, ''));

  const arrow = c => _sortCol === c ? (_sortAsc ? ' ▲' : ' ▼') : ' ▲▼';
  const th = (label, col) => `<th class="clickable" data-action="sortCompliance" data-id="${col}">${label}${arrow(col)}</th>`;

  let html = `<div class="flex gap-sm flex-wrap items-center mb-12">
    <input type="text" placeholder="Search node..." value="${esc(_searchHost)}" data-change="filterComplianceHost" class="f-filter w-160">
    <select data-change="filterComplianceEnv" class="f-filter">
      <option value="">All env</option>
      <option value="production" ${_filterEnv==='production'?'selected':''}>prod</option>
      <option value="staging" ${_filterEnv==='staging'?'selected':''}>staging</option>
      <option value="development" ${_filterEnv==='development'?'selected':''}>dev</option>
      <option value="lab" ${_filterEnv==='lab'?'selected':''}>lab</option>
    </select>
    <span class="ml-auto"><button data-action="_exportCompliance" class="btn btn-ghost" title="Export CSV">CSV</button></span>
  </div>`;

  html += `<div class="table-wrap"><table>
    <thead><tr>${th('Node', 'hostname')}${th('Env', 'env')}${th('SCA Score', 'sca_score')}${th('Misconfigs', 'misconf_total')}${th('Misconfigs Crit', 'misconf_critical')}${th('CVEs Open', 'cve_open_total')}${th('CVEs Crit', 'cve_critical')}<th>Drift</th><th>Drift High</th></tr></thead><tbody>`;
  if (!d.items.length) html += '<tr><td colspan="9" class="empty">No data</td></tr>';
  for (const c of d.items) {
    const scaColor = c.sca_score >= 80 ? 'green' : c.sca_score >= 50 ? 'orange' : c.sca_score > 0 ? 'red' : 'text-dim';
    const envColor = {production:'red',staging:'orange',development:'accent',lab:'text-dim'}[c.environment] || 'text-dim';
    html += `<tr>
      <td class="clickable" data-action="showNode" data-id="${c.node_id}">${esc(c.hostname)}</td>
      <td><span class="${txtColor(envColor)} text-xs">${esc((c.environment||'prod').slice(0,4))}</span></td>
      <td><span class="${txtColor(scaColor)} text-bold">${c.sca_score || '\u2014'}</span></td>
      <td>${c.misconf_total || 0}</td>
      <td>${c.misconf_critical ? '<span class="badge critical">' + c.misconf_critical + '</span>' : '0'}</td>
      <td>${c.cve_open_total || 0}</td>
      <td>${c.cve_critical_open ? '<span class="badge critical">' + c.cve_critical_open + '</span>' : '0'}</td>
      <td>${c.drift_total || 0}</td>
      <td>${c.drift_high ? '<span class="badge high">' + c.drift_high + '</span>' : '0'}</td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  el.innerHTML = html;
}

export function sortCompliance(col) {
  if (_sortCol === col) _sortAsc = !_sortAsc;
  else { _sortCol = col; _sortAsc = col === 'hostname'; }
  window.refreshView();
}

export function filterComplianceEnv(val) {
  _filterEnv = val;
  window.refreshView();
}

export function filterComplianceHost(val) {
  _searchHost = val;
  window.refreshView();
}

export function _exportCompliance() { exportCSV('compliance'); }
