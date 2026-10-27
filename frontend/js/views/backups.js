// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, API, esc, exportCSV, formatBytes, paginator, timeAgo, txtColor } from '../api.js';

let _items = [];
let _sortCol = 'hostname';
let _sortAsc = true;
let _selected = new Set();
let _nodesList = [];
let _searchQ = '';

function sortItems(items, col, asc) {
  return [...items].sort((a, b) => {
    let va = a[col], vb = b[col];
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

function render(el) {
  const q = _searchQ.trim().toLowerCase();
  const filtered = q
    ? _items.filter(b =>
        (b.repo_name || '').toLowerCase().includes(q) ||
        (b.path || '').toLowerCase().includes(q)
      )
    : _items;
  const items = sortItems(filtered, _sortCol, _sortAsc);

  const total = items.length;
  const ok = items.filter(b => b.status === 'success' && !b.overdue).length;
  const failed = items.filter(b => b.status === 'failure').length;
  const overdue = items.filter(b => b.overdue).length;
  const totalSize = items.reduce((s, b) => s + (b.size_total || 0), 0);

  const arrow = c => _sortCol === c ? (_sortAsc ? ' ▲' : ' ▼') : ' ▲▼';
  const th = (label, col) => `<th class="clickable" data-action="backupSort" data-id="${col}">${label}${arrow(col)}</th>`;

  let html = `<div class="flex gap-sm flex-wrap items-center mb-12">
    <input type="text" placeholder="Search repo, path…" value="${esc(_searchQ)}"
           data-change="backupsSearch" class="f-filter w-200">
    <span class="ml-auto"><button data-action="_exportBackup" class="btn btn-ghost" title="Export CSV">CSV</button></span>
  </div>`;
  html += `<div class="stats-grid mb-16">
    <div class="stat-card"><div class="label">Repos</div><div class="value">${total}</div></div>
    <div class="stat-card"><div class="label">OK</div><div class="value green">${ok}</div></div>
    <div class="stat-card"><div class="label">Failed</div><div class="value red">${failed}</div></div>
    <div class="stat-card"><div class="label">Overdue</div><div class="value ${overdue ? 'orange' : ''}">${overdue}</div></div>
    <div class="stat-card"><div class="label">Total Size</div><div class="value">${formatBytes(totalSize)}</div></div>
  </div>`;

  // Toolbar
  html += `<div class="flex gap-sm items-center mb-12">
    <button data-action="backupDeleteSelected" class="btn-bulk-del" ${_selected.size ? '' : 'disabled'}>Delete selected (${_selected.size})</button>
    <label class="text-md text-dim ml-auto">
      <input type="checkbox" data-change="backupToggleAll" ${_selected.size === total && total > 0 ? 'checked' : ''}> Select all
    </label>
  </div>`;

  html += `<div class="table-wrap"><table>
    <tr><th class="th-w-30"></th>${th('Node', 'hostname')}${th('Repo', 'repo_name')}${th('Status', 'status')}${th('Last run', 'last_run')}${th('Duration', 'duration_secs')}${th('Files', 'files_total')}${th('Added', 'size_added')}${th('Total size', 'size_total')}${th('Snapshots', 'snapshots_total')}${th('30d runs', 'total_runs')}${th('Success', 'success_rate')}</tr>`;

  if (!items.length) html += '<tr><td colspan="12" class="empty">No backup data</td></tr>';

  const nodeOpts = _nodesList.map(n => `<option value="${n.id}">${esc(n.hostname)}</option>`).join('');

  for (const b of items) {
    const stColor = b.overdue ? 'red' : b.status === 'success' ? 'green' : b.status === 'failure' ? 'red' : 'text-dim';
    const stText = b.overdue ? 'OVERDUE' : esc(b.status || '—');
    const dur = b.duration_secs ? `${Math.floor(b.duration_secs / 60)}m${b.duration_secs % 60}s` : '—';
    const files = b.files_total ? `${b.files_total.toLocaleString()} <span class="text-dim text-xs">(+${b.files_new || 0} new, ${b.files_changed || 0} chg)</span>` : '—';
    const rateColor = (b.success_rate || 0) >= 90 ? 'green' : (b.success_rate || 0) >= 70 ? 'orange' : 'red';
    const errTip = b.error_msg ? ` title="${esc(b.error_msg)}"` : '';
    const chk = _selected.has(b.repo_id) ? 'checked' : '';

    // Node cell: show hostname or dropdown to assign
    let nodeCell;
    if (b.node_id && b.hostname) {
      nodeCell = `<span class="clickable" data-action="showNode" data-id="${b.node_id}">${esc(b.hostname)}</span>
        <span class="clickable bk-pencil" data-action="backupShowNodePicker" data-id="${b.repo_id}" title="Change node">✎</span>`;
    } else {
      nodeCell = `<select class="bk-node-select" data-change="backupAssignNode" data-id="${b.repo_id}">
        <option value="">— assign node —</option>${nodeOpts}</select>`;
    }

    html += `<tr${b.overdue ? ' class="row-overdue"' : ''}>
      <td><input type="checkbox" ${chk} data-change="backupToggle" data-id="${b.repo_id}"></td>
      <td>${nodeCell}</td>
      <td>${esc(b.repo_name)}</td>
      <td${errTip}><span class="${txtColor(stColor)} text-bold">${stText}</span></td>
      <td>${b.last_run ? timeAgo(b.last_run) : '—'}</td>
      <td>${dur}</td>
      <td class="text-sm">${files}</td>
      <td>${formatBytes(b.size_added || 0)}</td>
      <td>${formatBytes(b.size_total || 0)}</td>
      <td>${b.snapshots_total || '—'}</td>
      <td>${b.total_runs || '—'}</td>
      <td><span class="${txtColor(rateColor)}">${b.success_rate != null ? b.success_rate + '%' : '—'}</span></td>
    </tr>`;
  }
  html += '</table></div>';
  el.innerHTML = html;
}

export async function renderBackups(el) {
  let bkUrl = '/backup/summary';
  const nid = getFilterNode();
  if (nid) bkUrl += `?hostname=${encodeURIComponent(nid)}`;

  const [d, nodeData] = await Promise.all([
    api(bkUrl),
    api('/nodes/list'),
  ]);
  _items = d.items;
  _nodesList = nodeData.items || nodeData;
  _selected = new Set();

  _el = el;
  render(el);
}

let _el = null;

function _rerender() { if (_el) render(_el); }

export function backupSort(col) {
  if (_sortCol === col) _sortAsc = !_sortAsc;
  else { _sortCol = col; _sortAsc = true; }
  _rerender();
}

export function backupToggle(id, checked) {
  if (checked) _selected.add(id); else _selected.delete(id);
  _rerender();
}

export function backupToggleAll(checked) {
  if (checked) _items.forEach(b => _selected.add(b.repo_id));
  else _selected.clear();
  _rerender();
}

export async function backupDeleteSelected() {
  if (!_selected.size) return;
  const names = _items.filter(b => _selected.has(b.repo_id)).map(b => b.repo_name);
  if (!confirm(`Delete ${names.length} repo(s)?\n\n${names.join('\n')}\n\nAll run history will be lost.`)) return;
  await fetch(API + '/backup/repos/delete', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ ids: [..._selected] }),
  });
  _selected.clear();
  window.refreshView();
}

export async function backupAssignNode(repoId, nodeId) {
  if (!nodeId) return;
  await fetch(API + `/backup/repos/${repoId}`, {
    method: 'PATCH', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ node_id: nodeId }),
  });
  window.refreshView();
}

export function backupShowNodePicker(repoId, el) {
  const existing = document.getElementById('node-picker-popup');
  if (existing) existing.remove();
  const sel = document.createElement('select');
  sel.id = 'node-picker-popup';
  sel.style.cssText = 'font-size:11px;background:var(--bg-card);color:var(--text);border:1px solid var(--accent);border-radius:3px;padding:2px 4px;position:absolute;z-index:100';
  sel.innerHTML = `<option value="">— cancel —</option>` + _nodesList.map(n => `<option value="${esc(n.id)}">${esc(n.hostname)}</option>`).join('');
  sel.onchange = async () => {
    if (sel.value) await backupAssignNode(repoId, sel.value);
    sel.remove();
  };
  sel.onblur = () => sel.remove();
  el.parentElement.appendChild(sel);
  sel.focus();
}

export function _exportBackup() { exportCSV('backup'); }

export function backupsSearch(v) {
  _searchQ = v || '';
  window.refreshView();
}
