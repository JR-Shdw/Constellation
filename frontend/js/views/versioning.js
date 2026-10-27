// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, timeAgo, txtColor } from '../api.js';

function ciBadge(has) {
  return has
    ? '<span class="text-green text-bold">Yes</span>'
    : '<span class="text-dim">No</span>';
}

function statusBadge(status) {
  const colors = {
    success: 'green', failure: 'red', error: 'red',
    running: 'blue', pending: 'orange',
  };
  const c = colors[status] || 'text-dim';
  return `<span class="${txtColor(c)} text-bold">${esc(status || '—')}</span>`;
}

export async function renderVersioning(el) {
  const d = await api('/cicd/repos');
  const repos = d.items || [];

  const total = repos.length;
  const withCi = repos.filter(r => r.has_pipeline).length;
  const withoutCi = total - withCi;
  const now = Date.now();
  const week = 7 * 86400 * 1000;
  const active = repos.filter(
    r => r.last_commit_at && (now - new Date(r.last_commit_at).getTime()) < week
  ).length;

  let html = `<div class="flex items-center gap-lg mb-12">
    <button data-action="syncCicd" class="btn btn-primary btn-md">Sync Now</button>
    <span id="sync-result" class="text-sm text-dim"></span>
  </div>`;
  html += `<div class="stats-grid mb-16">
    <div class="stat-card"><div class="label">Total repos</div><div class="value">${total}</div></div>
    <div class="stat-card"><div class="label">With CI/CD</div><div class="value green">${withCi}</div></div>
    <div class="stat-card"><div class="label">Without CI/CD</div><div class="value text-dim">${withoutCi}</div></div>
    <div class="stat-card"><div class="label">Active (7d)</div><div class="value">${active}</div></div>
  </div>`;

  html += `<div class="table-wrap"><table>
    <tr><th>Repo</th><th>Owner</th><th>Language</th><th>Branch</th><th>Branches</th><th>CI/CD</th><th>Pipeline</th><th>#</th><th>Last commit</th><th>Success (30d)</th></tr>`;

  if (!repos.length) {
    html += '<tr><td colspan="10" class="empty">No repositories — click Sync Now to populate</td></tr>';
  }
  for (const r of repos) {
    const link = r.url
      ? `<a href="${esc(r.url)}" target="_blank" class="text-default">${esc(r.repo_name)} ↗</a>`
      : esc(r.repo_name);
    const priv = r.private
      ? ' <span class="text-dim text-xs">private</span>'
      : '';
    const branches = r.branches
      ? (Array.isArray(r.branches) ? r.branches.length : 0)
      : 0;
    const rate = r.success_rate !== null && r.success_rate !== undefined ? r.success_rate : null;
    const rc = rate !== null ? (rate >= 90 ? 'green' : rate >= 70 ? 'orange' : 'red') : 'text-dim';

    html += `<tr>
      <td>${link}${priv}</td>
      <td class="text-sm">${esc(r.owner || '—')}</td>
      <td class="text-sm">${esc(r.language || '—')}</td>
      <td class="text-sm">${esc(r.default_branch || '—')}</td>
      <td class="text-center">${branches}</td>
      <td>${ciBadge(r.has_pipeline)}</td>
      <td>${statusBadge(r.last_pipeline_status)}</td>
      <td class="text-sm text-dim">${r.last_pipeline_number ? '#' + r.last_pipeline_number : '—'}</td>
      <td>${r.last_commit_at ? timeAgo(r.last_commit_at) : '—'}</td>
      <td>${rate !== null ? `<span class="${txtColor(rc)}">${rate}%</span>` : '—'}</td>
    </tr>`;
  }
  html += '</table></div>';

  el.innerHTML = html;
}

function _setStatus(el, text, kind) {
  if (!el) return;
  el.textContent = text;
  el.style.color = kind === 'err' ? 'var(--red)' : kind === 'ok' ? 'var(--green)' : '';
}

export async function syncCicd() {
  const res = document.getElementById('sync-result');
  _setStatus(res, 'Syncing...', '');
  try {
    const r = await fetch(API + '/cicd/sync', { method: 'POST' });
    const d = await r.json();
    if (d.error || d.detail) {
      _setStatus(res, d.detail || d.error, 'err');
      return;
    }
    const errs = (d.errors || []).length;
    _setStatus(
      res,
      `${d.repos} repos, ${d.pipelines} pipelines, ${d.workers} workers${errs ? ` — ${errs} error(s)` : ''}`,
      'ok'
    );
    window.loadView();
  } catch (e) {
    _setStatus(res, `Sync failed: ${e.message}`, 'err');
  }
}
