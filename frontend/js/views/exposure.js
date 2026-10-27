// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, esc, exposureBadge, txtColor } from '../api.js';

const _EXPOSURES = ['internet', 'vpn', 'private', 'docker_internal', 'localhost', 'none', 'unknown'];
const _EXP_COLORS = {internet:'red',vpn:'accent',private:'yellow',docker_internal:'text-dim',localhost:'green',none:'text-dim',unknown:'text-dim'};
// Sort state
let _sortCol = 'exposure';
let _sortAsc = true;
let _filterExp = '';

const _expOrder = {internet:0,vpn:1,private:2,localhost:3,docker_internal:4,none:5,unknown:6};

function _flagBadge(cid, flag, label, color, active, locked) {
  const cls = `exp-flag-badge${active ? ` on ${color}` : ''}${locked ? ' locked' : ''}`;
  const tip = locked
    ? `${label} — locked manual (shift+click to release group)`
    : `Toggle ${label} (locks all flags; shift+click to release)`;
  return `<span data-stop data-action="toggleFlag" data-id="${cid}" data-flag="${flag}" data-value="${!active}" class="${cls}" title="${tip}">${label}</span>`;
}

export async function renderExposure(el) {
  const d = await api('/exposure');

  // Summary cards
  let html = '<div class="stats-grid mb-20">';
  for (const s of d.summary) {
    const color = _EXP_COLORS[s.exposure] || 'text-dim';
    html += `<div class="stat-card">
      <div class="label">${esc(s.exposure)}</div>
      <div class="value ${txtColor(color)}">${s.container_count}</div>
      <div class="text-xs text-dim">${s.traefik_count} traefik · ${s.authelia_count} auth · ${s.geoip_count || 0} geoip</div>
    </div>`;
  }
  html += '</div>';

  // Filter — exposure type only (host filter handled by global #filter-node)
  html += `<div class="flex gap-sm flex-wrap mb-12">
    <select id="exp-filter-exp" data-change="expFilterExp" class="f-filter">
      <option value="">All exposure</option>
      ${_EXPOSURES.map(e => `<option value="${e}" ${_filterExp === e ? 'selected' : ''}>${e}</option>`).join('')}
    </select>
  </div>`;

  // Filter items — host comes from global filter, exposure type from local select
  const filterHost = (window.getFilterNode?.() || '').trim().toLowerCase();
  const filterTable = (window.getFilterTable?.() || '').trim().toLowerCase();
  let items = d.items;
  if (filterHost) items = items.filter(c => (c.hostname || '').toLowerCase().includes(filterHost));
  if (_filterExp) items = items.filter(c => c.exposure === _filterExp);
  if (filterTable) items = items.filter(c =>
    (c.name || '').toLowerCase().includes(filterTable) ||
    (c.image || '').toLowerCase().includes(filterTable) ||
    (c.networks || []).join(' ').toLowerCase().includes(filterTable)
  );

  // Sort items
  items = [...items].sort((a, b) => {
    let va, vb;
    if (_sortCol === 'exposure') {
      va = _expOrder[a.exposure] ?? 9;
      vb = _expOrder[b.exposure] ?? 9;
    } else {
      va = (a[_sortCol] || '').toLowerCase();
      vb = (b[_sortCol] || '').toLowerCase();
    }
    if (va < vb) return _sortAsc ? -1 : 1;
    if (va > vb) return _sortAsc ? 1 : -1;
    return 0;
  });

  // Table with sortable headers
  const arrow = c => _sortCol === c ? (_sortAsc ? ' ▲' : ' ▼') : ' ▲▼';
  const th = (label, col) => `<th class="clickable cursor-pointer no-select" data-action="_expSort" data-id="${col}">${label}${arrow(col)}</th>`;

  html += `<div class="table-wrap"><table>
    <thead><tr>${th('Container','name')}${th('Image','image')}${th('Exposure','exposure')}<th>Flags</th><th>Networks</th>${th('Node','hostname')}</tr></thead><tbody>`;
  if (!items.length) html += '<tr><td colspan="6" class="empty">No containers</td></tr>';
  for (const c of items) {
    const nets = (c.networks || []).join(', ') || '—';
    const cid = c.container_id || '';
    const fLocked = !!c.flags_manual;
    const flags = `<span class="exp-flags-row">${_flagBadge(cid, 'traefik', 'TFK', 'accent', c.traefik, fLocked)}${_flagBadge(cid, 'authelia', 'AUTH', 'green', c.authelia, fLocked)}${_flagBadge(cid, 'geoip', 'GEO', 'orange', c.geoip, fLocked)}${_flagBadge(cid, 'firewall', 'FW', 'yellow', c.firewall, fLocked)}</span>`;
    const expLockTip = c.exposure_manual
      ? 'Manual override — shift+click to reset to auto'
      : 'Click to override — shift+click resets if locked';
    const lockIcon = c.exposure_manual ? '<span class="exp-lock" title="Manual override">🔒</span>' : '';
    html += `<tr>
      <td>${esc(c.name)}</td>
      <td class="clickable" data-action="showImageHosts" data-id="${esc(c.image||'')}">${esc(c.image)}:${esc(c.tag || 'latest')}</td>
      <td id="exp-${cid}" class="clickable position-relative" data-action="editExposure" data-id="${cid}" data-value="${c.exposure || 'unknown'}" title="${expLockTip}">${exposureBadge(c.exposure)}${lockIcon}</td>
      <td>${flags}</td>
      <td class="text-sm text-dim">${esc(nets)}</td>
      <td class="clickable" data-action="showNode" data-id="${c.node_id}">${esc(c.hostname)}</td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  el.innerHTML = html;
}

// Sort + filter handlers
export function _expSort(col) {
  if (_sortCol === col) _sortAsc = !_sortAsc;
  else { _sortCol = col; _sortAsc = true; }
  window.refreshView();
}
export function expFilterExp(v) { _filterExp = v; window.refreshView(); }

export async function editExposure(containerId, current, ev) {
  if (!containerId) return;
  // Shift+click → release the manual lock, no picker.
  if (ev && ev.shiftKey) {
    await fetch(`/api/v1/containers/${containerId}/exposure`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reset_manual: 'exposure' }),
    });
    window.refreshView();
    return;
  }
  const cell = document.getElementById('exp-' + containerId);
  if (!cell || cell.querySelector('.exp-picker')) return;

  let picker = '<div class="exp-picker">';
  for (const e of _EXPOSURES) {
    const color = _EXP_COLORS[e] || 'text-dim';
    const cls = `exp-picker-opt ${txtColor(color)}${e === current ? ' selected' : ''}`;
    picker += `<div data-stop data-action="saveExposure" data-id="${containerId}" data-value="${e}" class="${cls}">${e}</div>`;
  }
  picker += '</div>';
  cell.insertAdjacentHTML('beforeend', picker);

  const close = (ev) => {
    if (!cell.contains(ev.target)) {
      const p = cell.querySelector('.exp-picker');
      if (p) p.remove();
      document.removeEventListener('click', close);
    }
  };
  setTimeout(() => document.addEventListener('click', close), 0);
}

export async function saveExposure(containerId, exposure) {
  await fetch(`/api/v1/containers/${containerId}/exposure`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ exposure }),
  });
  window.refreshView();
}

export async function toggleFlag(containerId, flag, value, el, ev) {
  // Shift+click → release the flags lock, no toggle.
  if (ev && ev.shiftKey) {
    await fetch(`/api/v1/containers/${containerId}/exposure`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reset_manual: 'flags' }),
    });
    window.refreshView();
    return;
  }
  if (el) {
    const colors = {traefik:'accent', authelia:'green', geoip:'orange', firewall:'yellow'};
    const color = colors[flag] || 'text-dim';
    if (value) {
      el.style.background = 'var(--bg-hover)';
      el.style.color = `var(--${color})`;
      el.style.borderColor = `var(--${color})`;
    } else {
      el.style.background = 'transparent';
      el.style.color = 'var(--border)';
      el.style.borderColor = 'var(--border)';
    }
    el.dataset.value = String(!value);
  }
  await fetch(`/api/v1/containers/${containerId}/exposure`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ [flag]: value }),
  });
}
