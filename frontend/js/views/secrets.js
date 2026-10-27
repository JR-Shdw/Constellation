// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, paginator, timeAgo, txtColor } from '../api.js';

const _STATUSES = ['open', 'false_positive', 'resolved', 'accepted_risk'];
const _COLORS = {open:'text-dim', false_positive:'purple', resolved:'green', accepted_risk:'yellow'};

let _sortCol = null;
let _sortAsc = true;
let _filterStatus = '';
let _filterSev = '';
let _searchQ = '';

export async function renderSecrets(el) {
  let url = `/secrets?page=${currentPage}&per_page=50`;
  const nid = window.getFilterNode?.() || '';
  if (nid) url += `&hostname=${encodeURIComponent(nid)}`;
  if (_filterStatus) url += `&status=${_filterStatus}`;
  if (_filterSev) url += `&severity=${_filterSev}`;
  if (_searchQ) url += `&search=${encodeURIComponent(_searchQ)}`;
  if (_sortCol) url += `&sort_by=${_sortCol}&sort_dir=${_sortAsc ? 'asc' : 'desc'}`;
  const d = await api(url);

  const arrow = c => _sortCol === c ? (_sortAsc ? ' ▲' : ' ▼') : ' ▲▼';
  const th = (label, col) => `<th class="clickable" data-action="sortSecrets" data-id="${col}">${label}${arrow(col)}</th>`;

  let html = `<div class="flex gap-sm flex-wrap mb-12">
    <input type="text" placeholder="Search node, file, type..." value="${esc(_searchQ)}" data-change="filterSecretsSearch" class="f-filter-sm w-180">
    <select data-change="filterSecretsStatus" class="f-filter-sm">
      <option value="">All status</option>
      ${_STATUSES.map(s => `<option value="${s}" ${_filterStatus === s ? 'selected' : ''} class="${txtColor(_COLORS[s]||'text-dim')}">${s.replace(/_/g, ' ')}</option>`).join('')}
    </select>
    <select data-change="filterSecretsSev" class="f-filter-sm">
      <option value="">All severities</option>
      <option value="critical" ${_filterSev==='critical'?'selected':''}>critical</option>
      <option value="high" ${_filterSev==='high'?'selected':''}>high</option>
      <option value="medium" ${_filterSev==='medium'?'selected':''}>medium</option>
      <option value="low" ${_filterSev==='low'?'selected':''}>low</option>
    </select>
  </div>`;

  html += `<div class="table-wrap"><table>
    <thead><tr>${th('Target', 'target')}<th>File</th><th>Type</th><th>Title</th>${th('Severity', 'severity')}<th>Source</th>${th('Node', 'hostname')}${th('Detected', 'detected_at')}${th('Status', 'status')}</tr></thead><tbody>`;
  if (!d.items.length) html += '<tr><td colspan="9" class="empty">No secrets detected</td></tr>';
  for (const s of d.items) {
    const target = s.target_type === 'container'
      ? `<span class="badge">container</span> ${esc(s.image || '\u2014')}`
      : '<span class="badge secondary">host</span>';
    const ago = s.detected_at ? timeAgo(s.detected_at) : '\u2014';
    const st = s.status || 'open';
    const stSelect = `<select data-change="patchSecret" data-id="${s.id}" class="form-select-inline ${txtColor(_COLORS[st]||'text-dim')}">${_STATUSES.map(o=>`<option value="${o}" ${o===st?'selected':''} class="${txtColor(_COLORS[o]||'text-dim')}">${o.replace(/_/g,' ')}</option>`).join('')}</select>`;
    html += `<tr${st !== 'open' ? ' class="opacity-50"' : ''}>
      <td>${target}</td>
      <td title="${esc(s.file_path)}">${esc(truncPath(s.file_path))}</td>
      <td>${esc(s.secret_type || '')}</td>
      <td>${esc(s.title || '')}</td>
      <td><span class="badge ${s.severity}">${esc(s.severity)}</span></td>
      <td>${esc(s.source)}</td>
      <td class="clickable" data-action="showNode" data-id="${s.node_id}">${esc(s.hostname)}</td>
      <td class="dim">${ago}</td>
      <td>${stSelect}</td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  html += paginator(d.total, d.page, d.per_page);
  el.innerHTML = html;
}

export function sortSecrets(col) {
  if (_sortCol === col) _sortAsc = !_sortAsc;
  else { _sortCol = col; _sortAsc = col === 'hostname'; }
  window.currentPage = 1;
  window.refreshView();
}

export function filterSecretsStatus(val) { _filterStatus = val; window.currentPage = 1; window.refreshView(); }
export function filterSecretsSev(val) { _filterSev = val; window.currentPage = 1; window.refreshView(); }
export function filterSecretsSearch(val) { _searchQ = val; window.currentPage = 1; window.refreshView(); }

export async function patchSecret(secretId, status) {
  await fetch(`${API}/secrets/${secretId}`, {
    method: 'PATCH',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ status }),
  });
  window.refreshView();
}

function truncPath(p) {
  if (!p || p.length <= 50) return p || '';
  return '…' + p.slice(-47);
}
