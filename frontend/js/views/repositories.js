// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, timeAgo } from '../api.js';

const OS_FAMILIES = ['debian','ubuntu','centos','rocky','rhel','fedora','archlinux','aix','generic'];

const OS_LABELS = {
  debian: 'Debian', ubuntu: 'Ubuntu', centos: 'CentOS', rocky: 'Rocky',
  rhel: 'RHEL', fedora: 'Fedora', archlinux: 'Arch Linux', aix: 'AIX', generic: 'Generic',
};

let _searchQ = '';

export async function renderRepositories(el) {
  const d = await api('/pkg-repos');
  const all = d.items || [];
  const q = _searchQ.trim().toLowerCase();
  const items = q
    ? all.filter(r =>
        (r.name || '').toLowerCase().includes(q) ||
        (r.distribution || '').toLowerCase().includes(q) ||
        (r.components || '').toLowerCase().includes(q) ||
        (r.url || '').toLowerCase().includes(q) ||
        (r.description || '').toLowerCase().includes(q)
      )
    : all;

  // Group by OS
  const byOs = {};
  for (const r of items) {
    if (!byOs[r.os_family]) byOs[r.os_family] = [];
    byOs[r.os_family].push(r);
  }

  const officialCount = items.filter(r => r.repo_type === 'official').length;
  const customCount = items.filter(r => r.repo_type === 'custom').length;

  let html = `<div class="flex gap-sm flex-wrap items-center mb-12">
    <input type="text" placeholder="Search repo, distribution…" value="${esc(_searchQ)}"
           data-change="repositoriesSearch" class="f-filter w-200">
  </div>`;
  html += `<div class="flex gap-sm mb-14 items-center flex-wrap">
    <button data-action="showAddPkgRepoForm" class="btn btn-primary btn-md">+ Add Repository</button>
    <button data-action="runCheckUpdates" class="btn btn-success btn-md">Check updates</button>
    <span id="check-updates-status" class="text-md text-dim"></span>
    <span class="text-md text-dim ml-auto">${items.length} repos (${officialCount} official, ${customCount} custom)</span>
  </div>`;

  // Add form (hidden by default)
  html += `<div id="pkg-repo-form" class="detail-panel">
    <div class="os-grid-200">
      <input id="pr-name" placeholder="Name (e.g. bookworm-main)" class="f-iinput">
      <select id="pr-os" class="f-iinput">
        ${OS_FAMILIES.map(o => `<option value="${o}">${OS_LABELS[o]}</option>`).join('')}
      </select>
      <input id="pr-url" placeholder="URL" class="f-iinput">
      <select id="pr-type" class="f-iinput">
        <option value="official">Official</option>
        <option value="custom" selected>Custom</option>
      </select>
      <input id="pr-dist" placeholder="Distribution (e.g. bookworm)" class="f-iinput">
      <input id="pr-comp" placeholder="Components (e.g. main contrib)" class="f-iinput">
      <input id="pr-gpg" placeholder="GPG key URL (optional)" class="f-iinput">
      <input id="pr-desc" placeholder="Description (optional)" class="f-iinput">
    </div>
    <div class="flex gap-sm">
      <button data-action="submitPkgRepo" class="btn btn-primary btn-md">Save</button>
      <button data-action="hideEl" data-target="pkg-repo-form" class="btn btn-neutral">Cancel</button>
    </div>
  </div>`;

  // Repos grouped by OS
  if (!items.length) {
    html += '<div class="empty">No package repositories configured</div>';
  } else {
    for (const os of OS_FAMILIES) {
      const repos = byOs[os];
      if (!repos || !repos.length) continue;
      const custom = repos.filter(r => r.repo_type === 'custom').length;

      html += `<div class="detail-section mb-16">
        <h3 class="flex items-center gap-sm">
          <span class="os-icon ${esc(os)}">${OS_LABELS[os]}</span>
          <span class="text-sm text-dim text-normal">${repos.length} repo${repos.length > 1 ? 's' : ''}${custom ? ` (${custom} custom)` : ''}</span>
        </h3>
        <div class="table-wrap"><table>
          <tr><th>Name</th><th>Type</th><th>URL</th><th>Distro</th><th>Components</th><th>Enabled</th><th></th></tr>`;

      for (const r of repos) {
        const typeBadge = r.repo_type === 'custom'
          ? '<span class="text-orange text-xs text-bold">custom</span>'
          : '<span class="text-dim text-xs">official</span>';
        const enabledBadge = r.enabled
          ? '<span class="text-green">ON</span>'
          : '<span class="text-dim">OFF</span>';

        html += `<tr>
          <td class="text-bold">${esc(r.name)}</td>
          <td>${typeBadge}</td>
          <td class="url-cell" title="${esc(r.url)}">${esc(r.url)}</td>
          <td class="text-sm text-dim">${esc(r.distribution || '—')}</td>
          <td class="text-sm text-dim">${esc(r.components || '—')}</td>
          <td>${enabledBadge}</td>
          <td class="nowrap">
            <button data-action="editPkgRepo" data-id="${r.id}" title="Edit" class="btn btn-primary">Edit</button>
            <button data-action="togglePkgRepo" data-id="${r.id}" data-value="${!r.enabled}" title="${r.enabled ? 'Disable' : 'Enable'}" class="btn btn-surface-alt">${r.enabled ? 'Off' : 'On'}</button>
            <button data-action="deletePkgRepo" data-id="${r.id}" title="Delete" class="btn btn-danger">Del</button>
          </td>
        </tr>`;
      }
      html += '</table></div></div>';
    }
  }

  el.innerHTML = html;
}

export function showAddPkgRepoForm() {
  document.getElementById('pkg-repo-form').classList.toggle('hidden');
}

export async function submitPkgRepo() {
  const name = document.getElementById('pr-name').value.trim();
  const url = document.getElementById('pr-url').value.trim();
  if (!name || !url) return alert('Name and URL required');

  await fetch(API + '/pkg-repos', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      name,
      os_family: document.getElementById('pr-os').value,
      url,
      repo_type: document.getElementById('pr-type').value,
      distribution: document.getElementById('pr-dist').value.trim() || null,
      components: document.getElementById('pr-comp').value.trim() || null,
      gpg_key_url: document.getElementById('pr-gpg').value.trim() || null,
      description: document.getElementById('pr-desc').value.trim() || null,
    }),
  });
  loadView();
}

export async function editPkgRepo(id) {
  const r = await fetch(API + '/pkg-repos');
  const d = await r.json();
  const repo = (d.items || []).find(x => x.id === id);
  if (!repo) return;

  const url = prompt('URL:', repo.url);
  if (url === null) return;
  const body = {};
  if (url !== repo.url) body.url = url;

  const desc = prompt('Description:', repo.description || '');
  if (desc !== null && desc !== (repo.description || '')) body.description = desc || null;

  if (!Object.keys(body).length) return;

  await fetch(API + `/pkg-repos/${id}`, {
    method: 'PATCH',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });
  loadView();
}

export async function togglePkgRepo(id, enabled) {
  await fetch(API + `/pkg-repos/${id}`, {
    method: 'PATCH',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ enabled }),
  });
  loadView();
}

export async function deletePkgRepo(id) {
  if (!confirm('Delete this repository?')) return;
  await fetch(API + `/pkg-repos/${id}`, { method: 'DELETE' });
  loadView();
}

function _setCheckStatus(el, text, kind, detail) {
  if (!el) return;
  const color = kind === 'err' ? 'var(--red)' : kind === 'ok' ? 'var(--green)' : 'var(--orange)';
  el.textContent = '';
  el.style.color = color;
  const main = document.createElement('span');
  main.textContent = text;
  el.appendChild(main);
  if (detail) {
    el.appendChild(document.createElement('br'));
    const sub = document.createElement('span');
    sub.style.fontSize = '11px';
    sub.style.color = 'var(--text-dim)';
    sub.textContent = detail;
    el.appendChild(sub);
  }
}

export function repositoriesSearch(v) {
  _searchQ = v || '';
  window.refreshView();
}

export async function runCheckUpdates() {
  const span = document.getElementById('check-updates-status');
  _setCheckStatus(span, 'Checking repos...', '');
  try {
    const r = await fetch(API + '/pkg-repos/check-updates', { method: 'POST' });
    const d = await r.json();
    if (r.ok) {
      const groups = (d.groups || [])
        .map(g => `${g.os}${g.codename ? '/' + g.codename : ''}: ${g.updated}`)
        .join(', ');
      _setCheckStatus(
        span,
        `${d.repos_checked} repos checked, ${d.packages_updated} updates found`,
        'ok',
        groups || null,
      );
    } else {
      _setCheckStatus(span, d.detail || 'Error', 'err');
    }
  } catch (e) {
    _setCheckStatus(span, `Error: ${e.message}`, 'err');
  }
}
