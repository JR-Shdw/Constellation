// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, paginator, txtColor } from '../api.js';

const _STATUSES = ['open', 'acknowledged', 'mitigated', 'resolved', 'false_positive', 'accepted_risk'];
const _COLORS = {open:'text-dim', acknowledged:'accent', mitigated:'green', resolved:'green', false_positive:'purple', accepted_risk:'yellow'};

let _sortCol = null;
let _sortAsc = true;
let _filterStatus = '';

export async function renderMisconf(el) {
  const nid = getFilterNode();
  let url = `/misconfigurations?page=${currentPage}&per_page=50`;
  if (nid) url += `&hostname=${encodeURIComponent(nid)}`;
  const fs = getFilterSeverity();
  if (fs) url += `&severity=${fs}`;
  if (_filterStatus) url += `&status=${_filterStatus}`;
  if (_sortCol) url += `&sort_by=${_sortCol}&sort_dir=${_sortAsc ? 'asc' : 'desc'}`;
  const d = await api(url);

  const arrow = c => _sortCol === c ? (_sortAsc ? ' ▲' : ' ▼') : ' ▲▼';
  const th = (label, col) => `<th class="clickable" data-action="sortMisconf" data-id="${col}">${label}${arrow(col)}</th>`;

  let html = `<div class="flex gap-8 mb-10 flex-wrap">
    <select data-change="filterMisconfStatus" class="f-filter">
      <option value="">All status</option>
      ${_STATUSES.map(s => `<option value="${s}" ${_filterStatus === s ? 'selected' : ''} class="${txtColor(_COLORS[s]||'text-dim')}">${s.replace(/_/g, ' ')}</option>`).join('')}
    </select>
  </div>`;

  const filterTable = (window.getFilterTable?.() || '').trim().toLowerCase();
  let visibleItems = d.items;
  if (filterTable) {
    visibleItems = d.items.filter(m =>
      (m.rule_id || '').toLowerCase().includes(filterTable) ||
      (m.target || '').toLowerCase().includes(filterTable) ||
      (m.rule_title || '').toLowerCase().includes(filterTable) ||
      (m.message || '').toLowerCase().includes(filterTable)
    );
  }

  html += `<div class="table-wrap"><table>
    <thead><tr>${th('Rule', 'rule_id')}${th('Severity', 'severity')}<th>Target</th><th>Title</th>${th('Node', 'hostname')}${th('Status', 'status')}</tr></thead><tbody>`;
  if (!visibleItems.length) html += '<tr><td colspan="6" class="empty">No misconfigurations</td></tr>';
  for (const m of visibleItems) {
    const sevClass = m.severity || 'unknown';
    const st = m.status || 'open';
    const stSelect = `<select data-change="patchMisconf" data-id="${m.id}" class="form-select-inline ${txtColor(_COLORS[st]||'text-dim')}">${_STATUSES.map(o=>`<option value="${o}" ${o===st?'selected':''} class="${txtColor(_COLORS[o]||'text-dim')}">${o.replace(/_/g,' ')}</option>`).join('')}</select>`;
    html += `<tr${st !== 'open' ? ' class="opacity-50"' : ''}>
      <td class="text-mono text-sm">${esc(m.rule_id)}</td>
      <td><span class="badge ${sevClass}">${esc(m.severity)}</span></td>
      <td class="text-sm" title="${esc(m.target || '')}">${esc(truncTarget(m.target))}</td>
      <td class="truncate-w-300" title="${esc(m.message || '')}">${esc(m.rule_title || m.message || '')}</td>
      <td class="clickable" data-action="showNode" data-id="${m.node_id}">${esc(m.hostname)}</td>
      <td>${stSelect}</td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  html += paginator(d.total, d.page, d.per_page);
  el.innerHTML = html;
}

export function sortMisconf(col) {
  if (_sortCol === col) _sortAsc = !_sortAsc;
  else { _sortCol = col; _sortAsc = col === 'rule_id' || col === 'hostname'; }
  window.currentPage = 1;
  window.refreshView();
}

export function filterMisconfStatus(val) {
  _filterStatus = val;
  window.currentPage = 1;
  window.refreshView();
}

export async function patchMisconf(id, status) {
  await fetch(`${API}/misconfigurations/${id}`, {
    method: 'PATCH',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ status }),
  });
  window.refreshView();
}

function truncTarget(t) {
  if (!t || t.length <= 40) return t || '—';
  return '…' + t.slice(-37);
}
