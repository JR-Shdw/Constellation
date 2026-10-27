// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, esc, paginator } from '../api.js';

let _sortCol = 'name';
let _sortAsc = true;
let _upgradeOnly = false;

function _trackerUrl(name, os) {
  const o = (os || '').toLowerCase();
  if (o.includes('ubuntu')) return `https://packages.ubuntu.com/${encodeURIComponent(name)}`;
  if (o.includes('arch')) return `https://archlinux.org/packages/?q=${encodeURIComponent(name)}`;
  return `https://tracker.debian.org/pkg/${encodeURIComponent(name)}`;
}

function _trackerLink(name, os) {
  return ` <a href="${_trackerUrl(name, os)}" target="_blank" rel="noopener" data-stop title="Package tracker" class="text-dim text-xs no-underline">&#8599;</a>`;
}

export async function renderPackages(el) {
  const q = document.getElementById('search').value.trim();
  const verQ = document.getElementById('search-version').value.trim();
  const pkgQ = (window.getFilterPackage?.() || '').trim();
  let url = `/packages?page=${currentPage}&per_page=50`;
  if (q.length >= 2) url += `&search=${encodeURIComponent(q)}`;
  else if (pkgQ.length >= 2) url += `&search=${encodeURIComponent(pkgQ)}`;
  if (verQ) url += `&version=${encodeURIComponent(verQ)}`;
  const nid = getFilterNode();
  if (nid) url += `&hostname=${encodeURIComponent(nid)}`;
  if (_upgradeOnly) url += '&upgrade_only=true';
  if (_sortCol !== 'name' || !_sortAsc) {
    url += `&sort_by=${_sortCol}&sort_dir=${_sortAsc ? 'asc' : 'desc'}`;
  }
  const d = await api(url);

  const arrow = c => _sortCol === c ? (_sortAsc ? ' ▲' : ' ▼') : ' ▲▼';
  const upBtn = _upgradeOnly
    ? '<span class="pkg-toggle-pill" data-action="toggleUpgradeFilter">Upgrade only ✕</span>'
    : '<span class="bg-card border pad-2-8 rounded-sm text-sm cursor-pointer text-dim" data-action="toggleUpgradeFilter">Upgrade only</span>';

  let html = `<div class="mb-8">${upBtn}</div>`;
  html += `<div class="table-wrap"><table>
    <thead><tr>
      <th class="sortable" data-action="sortPackages" data-id="name">Package${arrow('name')}</th>
      <th>Version</th>
      <th class="sortable" data-action="sortPackages" data-id="upgrade">Upgrade${arrow('upgrade')}</th>
      <th>Arch</th>
      <th class="sortable" data-action="sortPackages" data-id="hosts">Nodes${arrow('hosts')}</th>
    </tr></thead><tbody>`;
  if (!d.items.length) html += '<tr><td colspan="5" class="empty">No packages</td></tr>';
  for (const p of d.items) {
    const hosts = (p.hostnames || []).join(', ');
    const tl = _trackerLink(p.name, p.os);
    const upgrade = p.available_ver && p.available_ver !== p.version
      ? `<a href="${_trackerUrl(p.name, p.os)}" target="_blank" rel="noopener" class="text-green text-sm text-bold no-underline">${esc(p.available_ver)}</a> <span class="pkg-upd-tag">UPD</span>`
      : '<span class="text-dim text-sm">—</span>';
    html += `<tr>
      <td class="clickable" data-action="showPackageHosts" data-id="${esc(p.name)}">${esc(p.name)}${tl}</td>
      <td class="text-mono text-sm">${esc(p.version)}</td>
      <td>${upgrade}</td>
      <td>${esc(p.arch || '')}</td>
      <td>${p.host_count || 1}${p.host_count > 1 ? ' <span class="text-dim">(' + esc(hosts) + ')</span>' : ' <span class="text-dim">' + esc(hosts) + '</span>'}</td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  html += paginator(d.total, d.page, d.per_page);
  el.innerHTML = html;
}

export function sortPackages(col) {
  if (_sortCol === col) _sortAsc = !_sortAsc;
  else { _sortCol = col; _sortAsc = col === 'name'; }
  window.currentPage = 1;
  window.refreshView();
}

export function toggleUpgradeFilter() {
  _upgradeOnly = !_upgradeOnly;
  window.currentPage = 1;
  window.refreshView();
}
