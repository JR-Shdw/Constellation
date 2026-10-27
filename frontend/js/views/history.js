// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, timeAgo, paginator } from '../api.js';

let _tab = 'live';
let _auditItems = [];
let _searchQ = '';

export async function renderHistory(el) {
  let html = `<div class="tab-bar">
    <button class="tab-btn${_tab === 'live' ? ' tab-active' : ''}" data-action="_historyTab" data-id="live">Live</button>
    <button class="tab-btn${_tab === 'archives' ? ' tab-active' : ''}" data-action="_historyTab" data-id="archives">Archives</button>
  </div>`;

  if (_tab === 'archives') {
    html += await _renderArchives();
  } else {
    html += await _renderLive();
  }
  el.innerHTML = html;
}

async function _renderLive() {
  const page = window.currentPage || 1;
  const perPage = 50;
  const hostQ = (window.getFilterNode?.() || '').trim();
  let url = `/audit?page=${page}&per_page=${perPage}`;
  if (_searchQ.trim()) url += `&search=${encodeURIComponent(_searchQ.trim())}`;
  if (hostQ) url += `&hostname=${encodeURIComponent(hostQ)}`;
  const d = await api(url);
  const items = d.items || [];
  _auditItems = items;
  const total = d.total || 0;

  let html = `<div class="flex gap-sm flex-wrap items-center mb-12">
    <input type="text" placeholder="Search actor, action, target…" value="${esc(_searchQ)}"
           data-change="historySearch" class="f-filter w-200">
  </div>`;
  html += `<div class="flex gap-sm items-center mb-8">
    <span class="text-dim text-md">${total} entries (last 30 days)</span>
    <span class="ml-auto flex gap-xs">
      <button class="btn btn-surface" data-action="exportAuditJson">Export JSON</button>
      <button class="btn btn-surface" data-action="exportAuditCsv">Export CSV</button>
    </span>
  </div>`;

  html += `<table class="data-table"><thead><tr>
    <th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th>
  </tr></thead><tbody>`;
  for (const e of items) {
    const detail = typeof e.detail === 'object' && e.detail
      ? JSON.stringify(e.detail) : (e.detail || '-');
    const target = (e.target_type || '-')
      + (e.target_id ? ` / ${e.target_id}` : '');
    html += `<tr>
      <td>${timeAgo(e.created_at)}</td>
      <td>${esc(e.actor || '-')}</td>
      <td><span class="badge">${esc(e.action)}</span></td>
      <td>${esc(target)}</td>
      <td class="truncate-w-300 nowrap"
          title="${esc(detail)}">${esc(detail)}</td>
    </tr>`;
  }
  html += '</tbody></table>';
  html += paginator(total, page, perPage);
  return html;
}

async function _renderArchives() {
  const d = await api('/audit/archives');
  const archives = d.archives || [];

  let html = `<div class="flex gap-sm items-center mb-8">
    <span class="text-dim text-md">${archives.length} archive${archives.length !== 1 ? 's' : ''}</span>
    <span class="ml-auto">
      <button class="btn btn-primary" data-action="compactAudit">Compact now</button>
    </span>
  </div>`;

  if (!archives.length) {
    return html + '<p class="history-empty">No archives yet. Use Compact to archive entries older than 30 days.</p>';
  }

  html += `<table class="data-table"><thead><tr>
    <th>Date</th><th>Entries</th><th>Size</th><th>Format</th><th>Actions</th>
  </tr></thead><tbody>`;
  for (const a of archives) {
    const sizeKb = (a.size_bytes / 1024).toFixed(1);
    html += `<tr>
      <td><strong>${esc(a.archive_date)}</strong></td>
      <td>${a.entries_count}</td>
      <td>${sizeKb} KB</td>
      <td><span class="badge${a.compressed ? '' : ' secondary'}">${a.compressed ? 'gzip' : 'plain'}</span></td>
      <td class="flex gap-xs">
        <button class="btn btn-primary" data-action="viewArchive" data-id="${esc(a.archive_date)}">View</button>
        <button class="btn btn-surface" data-action="downloadArchive" data-id="${esc(a.archive_date)}">DL</button>
        <button class="btn btn-danger" data-action="deleteArchive" data-id="${esc(a.archive_date)}">Del</button>
      </td>
    </tr>`;
  }
  html += '</tbody></table>';
  html += '<div id="archive-view"></div>';
  return html;
}

// Actions

export function _historyTab(tab) {
  _tab = tab;
  window.currentPage = 1;
  window.loadView();
}

export function historySearch(v) {
  _searchQ = v || '';
  window.currentPage = 1;
  window.refreshView();
}

export async function viewArchive(dateStr) {
  try {
    const d = await api(`/audit/archives/${dateStr}`);
    const entries = d.entries || [];
    let html = `<div class="mt-12 border rounded p-12">
      <div class="flex justify-between mb-8">
        <strong class="text-accent">${esc(dateStr)} — ${entries.length} entries</strong>
        <button class="btn btn-surface" data-action="hideEl" data-target="archive-view">Close</button>
      </div>
      <table class="data-table"><thead><tr>
        <th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th>
      </tr></thead><tbody>`;
    for (const e of entries) {
      const detail = typeof e.detail === 'object' && e.detail
        ? JSON.stringify(e.detail) : (e.detail || '-');
      const target = (e.target_type || '-')
        + (e.target_id ? ` / ${e.target_id}` : '');
      html += `<tr>
        <td class="nowrap">${esc(e.created_at || '')}</td>
        <td>${esc(e.actor || '')}</td>
        <td><span class="badge">${esc(e.action || '')}</span></td>
        <td>${esc(target)}</td>
        <td class="truncate-w-300 nowrap">${esc(detail)}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';
    document.getElementById('archive-view').innerHTML = html;
  } catch (e) {
    document.getElementById('archive-view').innerHTML =
      `<p class="history-error">${esc(e.message || 'Failed to load archive')}</p>`;
  }
}

export async function downloadArchive(dateStr) {
  try {
    const d = await api(`/audit/archives/${dateStr}`);
    const content = JSON.stringify(d.entries || [], null, 2);
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-${dateStr}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch { /* silent */ }
}

export async function deleteArchive(dateStr) {
  if (!confirm(`Delete audit archive for ${dateStr}?`)) return;
  try {
    const r = await fetch(`${API}/audit/archives/${dateStr}`, { method: 'DELETE' });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      alert(d.detail || 'Cannot delete archive');
      return;
    }
    window.loadView();
  } catch (e) {
    alert(e.message || 'Cannot delete archive');
  }
}

export async function compactAudit() {
  if (!confirm('Archive audit entries older than 30 days?')) return;
  try {
    const r = await fetch(`${API}/audit/compact`, { method: 'POST' });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      alert(d.detail || 'Compact failed');
      return;
    }
    const d = await r.json();
    alert(`Archived ${d.archived} day(s), ${d.entries} entries`);
    window.loadView();
  } catch (e) {
    alert(e.message || 'Compact failed');
  }
}

export function exportAuditJson() {
  if (!_auditItems.length) return alert('No audit data to export');
  const content = JSON.stringify(_auditItems, null, 2);
  _downloadBlob(content, 'application/json', 'cmdb-audit.json');
}

export function exportAuditCsv() {
  if (!_auditItems.length) return alert('No audit data to export');
  const fields = ['created_at', 'actor', 'action', 'target_type', 'target_id', 'detail'];
  const csvEsc = v => {
    const s = String(v ?? '');
    return s.includes(',') || s.includes('"') || s.includes('\n')
      ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const rows = [fields.join(',')];
  for (const e of _auditItems) {
    rows.push(fields.map(f => {
      const v = e[f];
      return csvEsc(typeof v === 'object' ? JSON.stringify(v) : v);
    }).join(','));
  }
  _downloadBlob(rows.join('\n'), 'text/csv', 'cmdb-audit.csv');
}

function _downloadBlob(content, mime, filename) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
