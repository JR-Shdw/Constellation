// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, paginator, timeAgo, txtColor } from '../api.js';

const LISTEN_OPTS = ['docker_internal', 'localhost', 'private_network', 'internet'];
const REGISTRY_OPTS = ['dockerhub', 'ghcr', 'gitlab', 'harbor'];

let _sortCol = 'update';
let _sortAsc = false;
let _searchQ = '';
let _filterExposure = '';
let _filterRegistry = '';

const _isVer = s => /^v?\d+/.test(s || '');
const _sfx = s => { const m = (s||'').match(/^v?\d+(?:\.\d+)*(.*)/); return m ? m[1].replace(/^-/,'').toLowerCase() : ''; };

function _updatable(r) {
  if (!r.update_available) return false;
  // comparable version-tag update
  if (_isVer(r.current_tag) && _isVer(r.latest_tag_available) && _sfx(r.current_tag) === _sfx(r.latest_tag_available)) return true;
  // latest-pinned tag: newer image digest published under the same tag
  return !!r.latest_digest;
}

function sortRepos(items, col, asc) {
  return [...items].sort((a, b) => {
    let va, vb;
    if (col === 'update') {
      // 2 = update available, 1 = up to date, 0 = unknown/not comparable
      va = _updatable(a) ? 2 : (_isVer(a.current_tag) && _isVer(a.latest_tag_available) ? 1 : 0);
      vb = _updatable(b) ? 2 : (_isVer(b.current_tag) && _isVer(b.latest_tag_available) ? 1 : 0);
    } else {
      va = a[col]; vb = b[col];
    }
    if (va == null) va = '';
    if (vb == null) vb = '';
    if (typeof va === 'number' && typeof vb === 'number') return asc ? va - vb : vb - va;
    if (typeof va === 'boolean') { va = va ? 1 : 0; vb = vb ? 1 : 0; return asc ? va - vb : vb - va; }
    if (typeof va === 'string') va = va.toLowerCase();
    if (typeof vb === 'string') vb = vb.toLowerCase();
    if (va < vb) return asc ? -1 : 1;
    if (va > vb) return asc ? 1 : -1;
    return 0;
  });
}

export async function renderCrepositories(el) {
  let url = `/repositories?page=${currentPage}&per_page=50`;
  if (_searchQ) url += `&search=${encodeURIComponent(_searchQ)}`;
  if (_filterExposure) url += `&listen=${_filterExposure}`;
  if (_filterRegistry) url += `&registry=${_filterRegistry}`;
  const d = await api(url);
  const updCount = d.items.filter(r => _updatable(r)).length;
  const items = sortRepos(d.items, _sortCol, _sortAsc);

  const arrow = c => _sortCol === c ? (_sortAsc ? ' ▲' : ' ▼') : ' ▲▼';
  const th = (label, col) => `<th class="clickable" data-action="repoSort" data-id="${col}">${label}${arrow(col)}</th>`;

  let html = `
  <div class="flex gap-sm flex-wrap items-center mb-12">
    <input type="text" placeholder="Search project, image, node..." value="${esc(_searchQ)}" data-change="repoSearch" class="f-filter w-200">
    <select data-change="repoFilterExposure" class="f-filter">
      <option value="">All exposure</option>
      ${LISTEN_OPTS.map(o => `<option value="${o}" ${_filterExposure === o ? 'selected' : ''}>${o}</option>`).join('')}
    </select>
    <select data-change="repoFilterRegistry" class="f-filter">
      <option value="">All registries</option>
      ${REGISTRY_OPTS.map(o => `<option value="${o}" ${_filterRegistry === o ? 'selected' : ''}>${o}</option>`).join('')}
    </select>
  </div>
  <div class="flex gap-sm mb-14 items-center flex-wrap">
    <button data-action="showAddRepoForm" class="btn btn-primary btn-md">+ Add</button>
    <button data-action="checkAllRepos" class="btn btn-surface btn-md">↺ Check all versions</button>
    ${updCount ? `<span class="text-orange text-md">${updCount} update(s) available</span>` : ''}
  </div>
  <div id="repo-form" class="detail-panel">
    <div class="grid-auto-180 gap-sm mb-10">
      <input id="rf-project" placeholder="Project name" class="form-input">
      <input id="rf-image" placeholder="image:  e.g. grafana/grafana" class="form-input">
      <input id="rf-tag" placeholder="Current tag  e.g. 12.2.0" class="form-input">
      <select id="rf-registry" class="form-input">${REGISTRY_OPTS.map(o=>`<option>${o}</option>`).join('')}</select>
      <select id="rf-listen" class="form-input">${LISTEN_OPTS.map(o=>`<option>${o}</option>`).join('')}</select>
      <label class="flex items-center gap-sm text-md text-dim">
        <input type="checkbox" id="rf-auto" class="f-accent-color"> auto-update candidate
      </label>
    </div>
    <div class="flex gap-sm">
      <button data-action="submitAddRepo" class="btn btn-success btn-md">Save</button>
      <button data-action="hideEl" data-target="repo-form" class="bg-hover text-default border pad-5-14 cursor-pointer font-inherit text-md rounded-sm">Cancel</button>
    </div>
  </div>`;

  html += `<div class="table-wrap"><table>
    <thead><tr>${th('Project','project_name')}${th('Image','image_name')}${th('Registry','registry')}${th('Current','current_tag')}${th('Latest','latest_tag_available')}${th('Update','update')}${th('Exposure','listen')}${th('Auto','auto_update_candidate')}${th('Node','hostname')}${th('Checked','last_checked')}<th></th></tr></thead><tbody>`;
  if (!items.length) html += '<tr><td colspan="11" class="empty">No repositories — click + Add to create one</td></tr>';
  for (const r of items) {
    const cur = r.current_tag || '';
    const lat = r.latest_tag_available || '';
    const comparable = cur && lat && _isVer(cur) && _isVer(lat) && _sfx(cur) === _sfx(lat);
    let updBadge;
    if (r.update_available && comparable) {
      updBadge = `<span class="text-orange text-bold">${esc(lat)}</span>`;
    } else if (r.update_available && r.latest_digest) {
      // latest-pinned tag: a newer image was published under the same tag
      updBadge = '<span class="text-orange text-bold" title="New image digest published for this tag">new image</span>';
    } else if (lat && comparable) {
      updBadge = '<span class="text-green">up to date</span>';
    } else {
      updBadge = '<span class="text-dim">—</span>';
    }
    const listenColor = r.listen === 'internet' ? 'red' : r.listen === 'private_network' ? 'orange' : 'text-dim';
    const id = r.id;
    html += `<tr id="repo-row-${id}">
      <td>${esc(r.project_name)}</td>
      <td class="repo-edit-cell" title="Click to edit" data-action="editRepoField" data-id="${id}" data-field="image_name" data-value="${esc(r.image_name)}">${esc(r.image_name)} <span class="text-dim text-xxs">✎</span></td>
      <td class="text-xs text-dim">${esc(r.registry || 'dockerhub')}</td>
      <td class="text-mono text-sm">${esc(cur || '—')}</td>
      <td class="repo-edit-cell" title="Click to edit" data-action="editRepoField" data-id="${id}" data-field="latest_tag_available" data-value="${esc(lat)}">${esc(lat || '—')} <span class="text-dim text-xxs">✎</span></td>
      <td>${updBadge}</td>
      <td>
        <select data-change="patchRepo" data-id="${id}" data-field="listen" class="form-select-inline-sm ${txtColor(listenColor)}">
          ${LISTEN_OPTS.map(o=>`<option value="${o}" ${r.listen===o?'selected':''}>${o}</option>`).join('')}
        </select>
      </td>
      <td>
        <input type="checkbox" ${r.auto_update_candidate?'checked':''} data-change="patchRepoChecked" data-id="${id}" data-field="auto_update_candidate" class="f-accent-green-sm">
      </td>
      <td class="clickable text-sm" data-action="showNode" data-id="${r.node_id}">${esc(r.hostname || '—')}</td>
      <td class="text-xs text-dim">${r.last_checked ? timeAgo(r.last_checked) : '—'}</td>
      <td class="nowrap">
        <button data-action="checkOneRepo" data-id="${id}" title="Check version" class="btn btn-surface-alt">↺</button>
        <button data-action="deleteRepo" data-id="${id}" title="Delete" class="btn btn-ghost-red">✕</button>
      </td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  html += paginator(d.total, d.page, d.per_page);
  el.innerHTML = html;

}

export function repoSort(col) {
  if (_sortCol === col) _sortAsc = !_sortAsc;
  else { _sortCol = col; _sortAsc = col === 'update' ? false : true; }
  window.refreshView();
}
export function repoSearch(v) { _searchQ = v; window.currentPage = 1; window.refreshView(); }
export function repoFilterExposure(v) { _filterExposure = v; window.currentPage = 1; window.refreshView(); }
export function repoFilterRegistry(v) { _filterRegistry = v; window.currentPage = 1; window.refreshView(); }

export function showAddRepoForm() {
  document.getElementById('repo-form').style.display = 'block';
  document.getElementById('rf-image').focus();
}

export async function submitAddRepo() {
  const payload = {
    project_name: document.getElementById('rf-project').value.trim(),
    image_name:   document.getElementById('rf-image').value.trim(),
    current_tag:  document.getElementById('rf-tag').value.trim(),
    registry:     document.getElementById('rf-registry').value,
    listen:       document.getElementById('rf-listen').value,
    auto_update_candidate: document.getElementById('rf-auto').checked,
  };
  if (!payload.image_name) return;
  const r = await fetch(API + '/repositories', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload),
  });
  if (r.ok) window.refreshView();
}

export async function patchRepo(id, field, value) {
  await fetch(`${API}/repositories/${id}`, {
    method: 'PATCH',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({[field]: value}),
  });
}

export async function checkOneRepo(id) {
  const btn = document.querySelector(`button[data-action="checkOneRepo"][data-id="${id}"]`);
  if (btn) { btn.textContent = '…'; btn.disabled = true; }
  await fetch(`${API}/repositories/${id}/check`, {method: 'POST'});
  window.refreshView();
}

export async function deleteRepo(id) {
  if (!confirm('Delete this repository entry?')) return;
  await fetch(`${API}/repositories/${id}`, {method: 'DELETE'});
  window.refreshView();
}

export function editRepoField(id, field, currentValue, td) {
  if (td.querySelector('input')) return; // already editing
  const input = document.createElement('input');
  input.value = currentValue;
  input.style.cssText = 'background:var(--bg);border:1px solid var(--accent);color:var(--text);font-family:monospace;font-size:11px;padding:2px 4px;width:100%';
  input.onkeydown = async (e) => {
    if (e.key === 'Enter') {
      const val = input.value.trim();
      if (val && val !== currentValue) {
        await patchRepo(id, field, val);
      }
      window.refreshView();
    }
    if (e.key === 'Escape') window.refreshView();
  };
  input.onblur = () => window.refreshView();
  td.textContent = '';
  td.appendChild(input);
  input.focus();
  input.select();
}

export async function checkAllRepos() {
  const btn = document.querySelector('button[data-action="checkAllRepos"]');
  if (btn) { btn.textContent = 'Checking…'; btn.disabled = true; }
  await fetch(API + '/repositories/check-all', {method:'POST'});
  window.refreshView();
}
