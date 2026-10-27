// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, esc, exposureTags, paginator } from '../api.js';

let _sortCol = null;
let _sortAsc = true;
let _searchQ = '';

export async function renderContainers(el) {
  const q = document.getElementById('search').value.trim();
  const tagQ = document.getElementById('search-version').value.trim();
  let url = `/containers?page=${currentPage}&per_page=50`;
  // Per-view search (name/image/tag) — covers all pages via backend ?search=.
  // Falls back to the global #search if the in-view input is empty.
  const localQ = _searchQ.trim();
  const effectiveQ = localQ || (q.length >= 2 ? q : '');
  if (effectiveQ) url += `&search=${encodeURIComponent(effectiveQ)}`;
  if (tagQ) url += `&tag=${encodeURIComponent(tagQ)}`;
  const nid = getFilterNode();
  if (nid) url += `&hostname=${encodeURIComponent(nid)}`;
  if (_sortCol) url += `&sort_by=${_sortCol}&sort_dir=${_sortAsc ? 'asc' : 'desc'}`;
  const d = await api(url);

  const arrow = c => _sortCol === c ? (_sortAsc ? ' ▲' : ' ▼') : ' ▲▼';
  const th = (label, col) => `<th class="clickable" data-action="sortContainers" data-id="${col}">${label}${arrow(col)}</th>`;

  let html = `<div class="flex gap-sm flex-wrap items-center mb-12">
    <input type="text" placeholder="Search container, image, tag…" value="${esc(_searchQ)}"
           data-change="containersSearch" class="f-filter w-200">
  </div>`;
  html += `<div class="table-wrap"><table>
    <thead><tr>${th('Name', 'name')}${th('Image', 'image')}${th('Tag', 'tag')}${th('Exposure', 'exposure')}${th('Nodes', 'hosts')}</tr></thead><tbody>`;
  if (!d.items.length) html += '<tr><td colspan="5" class="empty">No containers</td></tr>';
  for (const c of d.items) {
    const hosts = (c.hostnames || []).join(', ');
    html += `<tr>
      <td class="clickable" data-action="showImageHosts" data-id="${esc(c.image)}">${esc(c.name)}</td>
      <td class="clickable" data-action="showImageHosts" data-id="${esc(c.image)}">${esc(c.image)}</td>
      <td>${esc(c.tag || '')}</td>
      <td>${exposureTags(c)}</td>
      <td>${c.host_count || 1}${c.host_count > 1 ? ' <span class="text-dim">(' + esc(hosts) + ')</span>' : ' <span class="text-dim">' + esc(hosts) + '</span>'}</td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  html += paginator(d.total, d.page, d.per_page);
  el.innerHTML = html;
}

export function sortContainers(col) {
  if (_sortCol === col) _sortAsc = !_sortAsc;
  else { _sortCol = col; _sortAsc = col === 'name' || col === 'image'; }
  window.currentPage = 1;
  window.refreshView();
}

export function containersSearch(v) {
  _searchQ = v || '';
  window.currentPage = 1;
  window.refreshView();
}
