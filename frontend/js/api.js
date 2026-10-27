// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
// API + Utilities
export const API = '/api/v1';

export function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// Attestation marker for HTML chunks already escaped at the source
// (every interpolated value passed through esc() or a safe helper).
// The XSS-ratchet test (tests/test_innerhtml_safety.py) treats _h(x) as
// trusted — wrap deliberately, only after auditing the producer.
export const _h = s => s == null ? '' : String(s);

// Stale-while-revalidate cache
const _apiCache = new Map();
const _API_TTL = {
  '/nodes/list': 60000,
  '/cicd/stats': 25000,
  '/scan/status': 30000,
  '/settings/vault/status': 300000,
  '/settings/vault/secrets': 300000,
  '/stats': 20000,
};

function _cacheTTL(path) {
  for (const [prefix, ttl] of Object.entries(_API_TTL)) {
    if (path.startsWith(prefix)) return ttl;
  }
  return 0;
}

export function clearApiCache() {
  _apiCache.clear();
}

export async function api(path) {
  const ttl = _cacheTTL(path);
  const cached = _apiCache.get(path);

  if (cached && ttl > 0) {
    const age = Date.now() - cached.ts;
    if (age < ttl) return cached.data;
    // Stale — return cached data, refetch in background
    fetch(API + path).then(r => r.ok ? r.json() : null).then(d => {
      if (d) _apiCache.set(path, { data: d, ts: Date.now() });
    }).catch(() => {});
    return cached.data;
  }

  const r = await fetch(API + path);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  const data = await r.json();
  if (ttl > 0) _apiCache.set(path, { data, ts: Date.now() });
  return data;
}

export function timeAgo(ts) {
  if (!ts) return 'never';
  const d = new Date(ts);
  const now = new Date();
  const secs = Math.floor((now - d) / 1000);
  if (secs < 60) return secs + 's ago';
  if (secs < 3600) return Math.floor(secs/60) + 'm ago';
  if (secs < 86400) return Math.floor(secs/3600) + 'h ago';
  return Math.floor(secs/86400) + 'd ago';
}

export function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

export function typeBadges(type, max = 2) {
  if (!type) return '';
  const types = type.split(',').map(t => t.trim()).filter(Boolean);
  const show = types.slice(0, max);
  return show.map(t => {
    const c = {bare_metal:'purple',vm:'accent',container_host:'green',bastion:'orange',workstation:'text-dim',host:'accent'}[t] || 'text-dim';
    return `<span class="badge ${txtColor(c)}">${esc(t)}</span>`;
  }).join(' ') + (types.length > max ? ` <span class="text-dim text-xs">+${types.length - max}</span>` : '');
}

export function exposureBadge(exp) {
  const colors = {internet:'red',vpn:'accent',private:'yellow',localhost:'green',docker_internal:'text-dim',none:'text-dim',unknown:'text-dim'};
  return `<span class="${txtColor(colors[exp]||'text-dim')}">${esc(exp || 'unknown')}</span>`;
}

export function exposureTags(c) {
  let html = exposureBadge(c.exposure);
  if (c.traefik)  html += ' <span class="exposure-tag text-accent">TFK</span>';
  if (c.authelia) html += ' <span class="exposure-tag text-green">AUTH</span>';
  if (c.geoip)    html += ' <span class="exposure-tag text-orange">GEO</span>';
  if (c.firewall) html += ' <span class="exposure-tag text-yellow">FW</span>';
  return html;
}

export function paginator(total, page, perPage) {
  const pages = Math.ceil(total / perPage);
  if (pages <= 1) return '';
  return `<div class="pagination">
    <button data-action="goPage" data-page="${page - 1}" ${page <= 1 ? 'disabled' : ''}>Prev</button>
    <span>Page ${page} / ${pages} (${total} items)</span>
    <button data-action="goPage" data-page="${page + 1}" ${page >= pages ? 'disabled' : ''}>Next</button>
  </div>`;
}

// Map a color token (green, red, orange, accent, yellow, purple, text-dim, dim)
// to the matching `.text-*` CSS class. Handles the `text-dim` alias so callers
// can pass it interchangeably with `dim`.
export const txtColor = c => (c === 'text-dim' || c === 'dim') ? 'text-dim' : `text-${c}`;

// CSV Export
export function exportCSV(path) {
  const a = document.createElement('a');
  a.href = API + '/export/' + path;
  a.download = '';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

// Tab bar: blue underline active, grey inactive
export function tabBar(tabs, activeKey, tabGroup) {
  let html = '<div class="tab-bar">';
  for (const [key, label] of tabs) {
    const cls = activeKey === key ? ' tab-active' : '';
    html += `<button class="tab-btn${cls}" data-action="setTab" data-tab="${key}" data-group="${tabGroup}">${label}</button>`;
  }
  html += '</div>';
  return html;
}

export function toast(msg, type = 'info') {
  let box = document.getElementById('toast-box');
  if (!box) {
    box = document.createElement('div');
    box.id = 'toast-box';
    box.className = 'toast-container';
    document.body.appendChild(box);
  }
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  box.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity 0.3s'; }, 2700);
  setTimeout(() => t.remove(), 3000);
}
