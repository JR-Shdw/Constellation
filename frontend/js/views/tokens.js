// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, tabBar, txtColor } from '../api.js';

const SCOPES = [
  'collect', 'read', 'backup', 'cicd', 'deployments', 'managers',
  'automation', 'repositories', 'findings', 'misconf', 'settings', 'tokens',
];

let _searchQ = '';

function permBadge(mode) {
  if (!mode) return '';
  const cls = mode === 'rw' ? 'perm-rw' : mode === 'w' ? 'perm-w' : 'perm-r';
  return `<span class="perm-badge ${cls}">${mode}</span>`;
}

export async function renderTokens(el) {
  const tab = window.tokensTab || 'matrix';

  let html = tabBar(
    [['matrix', 'Permission Matrix'], ['create', 'Create Token']],
    tab, 'tokens'
  );

  if (tab === 'create') {
    html += _renderCreateForm();
    el.innerHTML = html;
    return;
  }

  // Matrix tab
  let d;
  try {
    d = await api('/tokens');
  } catch (e) {
    el.innerHTML = html + `<div class="empty">Cannot load tokens: ${esc(e.message)}</div>`;
    return;
  }
  const allItems = d.items || [];

  if (!allItems.length) {
    el.innerHTML = html + '<div class="empty">No API tokens — env tokens (.env) are not listed here</div>';
    return;
  }

  // Two-bar filter: shared #filter-node (token name contains "node-…")
  // + per-view specific search (token name / hint).
  const hostQ = (window.getFilterNode?.() || '').trim().toLowerCase();
  const q = _searchQ.trim().toLowerCase();
  const items = allItems.filter(t => {
    if (hostQ && !(t.name || '').toLowerCase().includes(hostQ)) return false;
    if (q && !(
      (t.name || '').toLowerCase().includes(q) ||
      (t.token_hint || '').toLowerCase().includes(q)
    )) return false;
    return true;
  });

  // Stats (computed on full list — gives a stable picture independent of search)
  const active = allItems.filter(t => t.active).length;
  const revoked = allItems.filter(t => !t.active).length;
  const expiredCount = allItems.filter(t => t.active && t.expires_at && new Date(t.expires_at) < new Date()).length;
  const nodeTokens = allItems.filter(t => t.name.startsWith('node-') && t.active);
  html += `<div class="flex gap-sm flex-wrap items-center mb-12">
    <input type="text" placeholder="Search token, hint…" value="${esc(_searchQ)}"
           data-change="tokensSearch" class="f-filter w-200">
  </div>`;
  html += `<div class="flex gap-lg items-center mb-16 flex-wrap">
    <span class="text-md text-dim">
      <span class="text-green">${active} active</span> ·
      <span class="text-red">${revoked} revoked</span>
      ${expiredCount ? ` · <span class="text-orange">${expiredCount} expired</span>` : ''}
      ${nodeTokens.length ? ` · <span class="text-accent">${nodeTokens.length} node tokens</span>` : ''}
    </span>
    ${nodeTokens.length ? `<button data-action="revokeAllNodeTokens" class="btn btn-surface btn-outline-red">Revoke All Node Tokens</button>` : ''}
    ${expiredCount ? `<button data-action="deleteExpiredTokens" class="btn btn-surface btn-outline-orange">Clean Expired</button>` : ''}
  </div>`;

  // Permission matrix table
  html += `<div class="table-wrap"><table class="token-matrix">
    <tr>
      <th>Token</th><th>Hint</th><th>Status</th>
      ${SCOPES.map(s => `<th class="scope-header">${esc(s)}</th>`).join('')}
      <th>Actions</th>
    </tr>`;

  for (const t of items) {
    const perms = t.permissions || {};
    const isAdmin = perms.admin === 'rw';
    const expired = t.expires_at && new Date(t.expires_at) < new Date();
    const rowClass = (t.active && !expired) ? '' : ' class="opacity-40"';
    const statusColor = !t.active ? 'red' : expired ? 'orange' : 'green';
    const statusLabel = !t.active ? 'revoked' : expired ? 'expired' : 'active';
    const expiresLabel = t.expires_at
      ? new Date(t.expires_at).toLocaleString('fr-FR', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'})
      : '';

    html += `<tr${rowClass}>
      <td class="text-bold nowrap">${esc(t.name)}${expiresLabel ? `<div class="text-xxs ${txtColor(expired ? 'red' : 'text-dim')}">${expired ? '⏱ expired' : '⏱ ' + expiresLabel}</div>` : ''}</td>
      <td class="text-xs text-dim font-mono">${esc(t.token_hint || '')}</td>
      <td><span class="${txtColor(statusColor)} text-sm">${statusLabel}</span></td>`;

    for (const scope of SCOPES) {
      const mode = isAdmin ? 'rw' : (perms[scope] || '');
      html += `<td>${isAdmin ? '<span class="perm-badge perm-rw" title="admin">*</span>' : permBadge(mode)}</td>`;
    }

    html += `<td class="nowrap">`;
    if (t.active) {
      html += `<button data-action="revokeToken" data-id="${t.id}" class="btn btn-warning btn-sm" title="Revoke">Revoke</button> `;
    } else {
      html += `<button data-action="activateToken" data-id="${t.id}" class="btn btn-primary btn-sm" title="Activate">Activate</button> `;
    }
    html += `<button data-action="regenerateToken" data-id="${t.id}" class="btn btn-success btn-sm" title="Regenerate">Regen</button> `;
    html += `<button data-action="deleteToken" data-id="${t.id}" class="btn btn-danger btn-sm" title="Delete">Del</button>`;
    html += `</td></tr>`;
  }
  html += '</table></div>';

  // Legend
  html += `<div class="mt-12 flex gap-lg text-sm text-dim">
    <span>${permBadge('r')} read</span>
    <span>${permBadge('w')} write</span>
    <span>${permBadge('rw')} read+write</span>
    <span><span class="perm-badge perm-rw">*</span> admin (all scopes)</span>
  </div>`;

  el.innerHTML = html;
}

function _renderCreateForm() {
  let html = `<div class="detail-section">
    <h3>Create API Token</h3>
    <div class="detail-grid gap-row-col w-500">
      <span class="k">Name</span>
      <input id="tk-name" placeholder="ansible-collect" class="form-input">
      <span class="k">Description</span>
      <input id="tk-desc" placeholder="Ansible inventory collection" class="form-input">
    </div>
    <h4 class="section-h">Permissions</h4>
    <div class="grid-auto-180-gap-sm">`;

  for (const scope of SCOPES) {
    html += `<label class="flex items-center gap-sm text-md">
      <span class="w-90-min">${esc(scope)}</span>
      <select id="tk-perm-${scope}" class="form-input w-70 pad-2-4">
        <option value="">—</option>
        <option value="r">r</option>
        <option value="w">w</option>
        <option value="rw">rw</option>
      </select>
    </label>`;
  }

  html += `</div>
    <label class="flex items-center gap-sm mt-12 text-md text-orange">
      <input type="checkbox" id="tk-admin"> Admin (all scopes rw)
    </label>
    <div class="mt-12">
      <span class="k text-md text-dim">Expires in</span>
      <select id="tk-ttl" class="form-input w-180 ml-8">
        <option value="">Never</option>
        <option value="1">1 hour</option>
        <option value="4">4 hours</option>
        <option value="24">24 hours</option>
        <option value="168">7 days</option>
        <option value="720">30 days</option>
        <option value="2160">90 days</option>
      </select>
    </div>
    <label class="honey-checkbox mt-12">
      <input type="checkbox" id="tk-honey">
      <strong>Honeytoken (decoy)</strong>
      <span class="dim">— any auth using this token fires a CRITICAL alert. Pick an attractive name (monitoring-collect, portainer-readonly) so attackers want to try it.</span>
    </label>
    <button data-action="createToken" class="btn btn-primary btn-xl mt-16">Create Token</button>
    <div id="tk-result" class="mt-12"></div>
  </div>`;
  return html;
}

export async function createToken() {
  const name = document.getElementById('tk-name').value.trim();
  if (!name) return alert('Name required');
  const desc = document.getElementById('tk-desc').value.trim();
  const isAdmin = document.getElementById('tk-admin').checked;

  const permissions = {};
  if (isAdmin) {
    permissions.admin = 'rw';
  } else {
    for (const scope of SCOPES) {
      const val = document.getElementById(`tk-perm-${scope}`).value;
      if (val) permissions[scope] = val;
    }
  }

  if (!Object.keys(permissions).length) return alert('Select at least one permission');

  const ttlHours = parseInt(document.getElementById('tk-ttl').value) || 0;
  const isHoney = document.getElementById('tk-honey')?.checked || false;
  const payload = {name, description: desc, permissions};
  if (ttlHours > 0) {
    payload.expires_at = new Date(Date.now() + ttlHours * 3600000).toISOString();
  }
  if (isHoney) payload.is_honey = true;

  const r = await fetch(API + '/tokens', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload),
  });
  const d = await r.json();
  if (!r.ok) return alert(d.detail || 'Error');

  document.getElementById('tk-result').innerHTML = `
    <div class="token-reveal">
      <div class="text-orange text-bolder mb-8">Token created — copy it now, it won't be shown again!</div>
      <code class="token-reveal-code">${esc(d.token)}</code>
    </div>`;
}

export async function revokeToken(id) {
  await fetch(API + `/tokens/${id}/revoke`, {method: 'POST'});
  loadView();
}

export async function activateToken(id) {
  await fetch(API + `/tokens/${id}/activate`, {method: 'POST'});
  loadView();
}

export async function regenerateToken(id) {
  if (!confirm('Regenerate? The old token will be immediately invalidated.')) return;
  const r = await fetch(API + `/tokens/${id}/regenerate`, {method: 'POST'});
  const d = await r.json();
  if (d.token) {
    alert(`New token (copy now!):\n\n${d.token}`);
  }
  loadView();
}

export async function deleteToken(id) {
  if (!confirm('Permanently delete this token?')) return;
  await fetch(API + `/tokens/${id}`, {method: 'DELETE'});
  loadView();
}

export async function revokeAllNodeTokens() {
  if (!confirm('Revoke ALL node-* tokens? Ansible collect will stop working until new tokens are deployed.')) return;
  try {
    const d = await api('/tokens');
    const nodeTokens = (d.items || []).filter(t => t.name.startsWith('node-') && t.active);
    for (const t of nodeTokens) {
      await fetch(API + `/tokens/${t.id}/revoke`, {method: 'POST'});
    }
    alert(`${nodeTokens.length} node token(s) revoked.`);
  } catch (e) {
    alert('Error: ' + e.message);
  }
  loadView();
}

export async function deleteExpiredTokens() {
  if (!confirm('Delete all expired tokens? This is irreversible.')) return;
  try {
    const d = await api('/tokens');
    const expired = (d.items || []).filter(t => t.expires_at && new Date(t.expires_at) < new Date());
    for (const t of expired) {
      await fetch(API + `/tokens/${t.id}`, {method: 'DELETE'});
    }
    alert(`${expired.length} expired token(s) deleted.`);
  } catch (e) {
    alert('Error: ' + e.message);
  }
  loadView();
}

export function tokensSearch(v) {
  _searchQ = v || '';
  window.refreshView();
}
