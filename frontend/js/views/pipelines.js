// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, tabBar, timeAgo, txtColor } from '../api.js';

let _searchQ = '';

function statusBadge(status) {
  const colors = {
    success: 'green', failure: 'red', error: 'red',
    running: 'accent', pending: 'orange', killed: 'red',
    blocked: 'orange', skipped: 'text-dim', declined: 'text-dim',
  };
  const color = colors[status] || 'text-dim';
  const running = status === 'running';
  return `<span ${running ? 'class="pipeline-running"' : ''} class="${txtColor(color)} text-bold">${esc(status || '—')}</span>${running ? '<span class="pipeline-bar"></span>' : ''}`;
}

function fmtDuration(secs) {
  if (!secs || secs <= 0) return '—';
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return s > 0 ? `${m}m${s}s` : `${m}m`;
}

function eventIcon(event) {
  const icons = {
    push: 'P', pull_request: 'PR', tag: 'T', cron: 'C', manual: 'M',
  };
  return `<span title="${esc(event || '')}" class="pl-event-icon">${icons[event] || '?'}</span>`;
}

export async function renderPipelines(el) {
  const tab = window.pipelinesTab || 'pipelines';

  let html = tabBar(
    [['pipelines', 'Pipelines'], ['workers', 'Workers'], ['servers', 'Servers']],
    tab, 'pipelines'
  );

  if (tab === 'servers') {
    el.innerHTML = html + await _renderServers();
    return;
  }
  if (tab === 'workers') {
    el.innerHTML = html + await _renderWorkers();
    return;
  }

  const d = await api('/cicd/stats');

  // Stats cards
  const rate = d.success_rate_30d !== null && d.success_rate_30d !== undefined ? d.success_rate_30d : null;
  const rateColor = rate !== null ? (rate >= 90 ? 'green' : rate >= 70 ? 'orange' : 'red') : 'text-dim';
  const avgDur = d.avg_duration_30d ? fmtDuration(d.avg_duration_30d) : '—';

  html += `<div class="flex gap-sm flex-wrap items-center mb-12">
    <input type="text" placeholder="Search pipeline, repo, server…" value="${esc(_searchQ)}"
           data-change="pipelinesSearch" class="f-filter w-200">
  </div>`;
  html += `<div class="flex items-center gap-lg mb-12">
    <button data-action="syncCicd" class="btn btn-primary pad-5-14">Sync Now</button>
    <span id="sync-result" class="text-sm text-dim"></span>
  </div>`;
  html += `<div class="stats-grid mb-16">
    <div class="stat-card"><div class="label">Repos</div><div class="value">${d.total_repos || 0}</div></div>
    <div class="stat-card"><div class="label">Runs (30d)</div><div class="value">${d.total_runs_30d || 0}</div></div>
    <div class="stat-card"><div class="label">Success</div><div class="value green">${d.success_30d || 0}</div></div>
    <div class="stat-card"><div class="label">Failures</div><div class="value red">${d.failure_30d || 0}</div></div>
    <div class="stat-card"><div class="label">Success rate</div><div class="value ${rateColor}">${rate !== null ? rate + '%' : '—'}</div></div>
    <div class="stat-card"><div class="label">Avg duration</div><div class="value">${avgDur}</div></div>
  </div>`;

  // Repos overview table
  html += `<h3 class="section-h">Repositories</h3>`;
  html += `<div class="table-wrap"><table>
    <tr><th>Repo</th><th>Language</th><th>Last pipeline</th><th>Status</th><th>Event</th><th>Branch</th><th>When</th><th>Duration</th><th>30d runs</th><th>Success rate</th></tr>`;

  const allRepos = d.latest_per_repo || [];
  const q = _searchQ.trim().toLowerCase();
  const repos = q
    ? allRepos.filter(r =>
        (r.repo_name || '').toLowerCase().includes(q) ||
        (r.branch || '').toLowerCase().includes(q) ||
        (r.last_status || '').toLowerCase().includes(q) ||
        (r.language || '').toLowerCase().includes(q) ||
        (r.server_name || '').toLowerCase().includes(q)
      )
    : allRepos;
  if (!repos.length) {
    html += '<tr><td colspan="10" class="empty">No CI/CD data — <a href="#settings" class="text-accent">configure Woodpecker in Settings</a> then click Sync Now</td></tr>';
  }
  for (const r of repos) {
    const rateVal = r.success_rate !== null && r.success_rate !== undefined ? r.success_rate : null;
    const rc = rateVal !== null ? (rateVal >= 90 ? 'green' : rateVal >= 70 ? 'orange' : 'red') : 'text-dim';
    const repoUrl = r.repo_url ? `<a href="${esc(r.repo_url)}" target="_blank" class="text-default">${esc(r.repo_name)} ↗</a>` : esc(r.repo_name);
    const pipeLink = r.link ? `<a href="${esc(r.link)}" target="_blank" class="no-underline">${statusBadge(r.status)} ↗</a>` : statusBadge(r.status);

    html += `<tr>
      <td>${repoUrl}${r.repo_private ? ' <span class="text-dim text-xs">private</span>' : ''}</td>
      <td class="text-sm">${esc(r.repo_language || '—')}</td>
      <td class="text-sm text-dim">#${r.pipeline_number || '—'}</td>
      <td>${pipeLink}</td>
      <td>${eventIcon(r.event)}</td>
      <td class="text-sm">${esc(r.branch || '—')}</td>
      <td>${r.started_at ? timeAgo(r.started_at) : '—'}</td>
      <td>${fmtDuration(r.duration_secs)}</td>
      <td>${r.total_runs || '—'}</td>
      <td>${rateVal !== null ? `<span class="${txtColor(rc)}">${rateVal}%</span>` : '—'}</td>
    </tr>`;
  }
  html += '</table></div>';

  // Recent pipelines
  const p = await api('/cicd/pipelines?size=20');
  html += `<h3 class="section-h-lg">Recent pipelines</h3>`;
  html += `<div class="table-wrap"><table>
    <tr><th>Repo</th><th>#</th><th>Status</th><th>Event</th><th>Branch</th><th>Commit</th><th>Author</th><th>Duration</th><th>When</th></tr>`;

  if (!p.items.length) {
    html += '<tr><td colspan="9" class="empty">No pipeline runs</td></tr>';
  }
  for (const run of p.items) {
    const sha = (run.commit_sha || '').slice(0, 8);
    const msg = esc((run.commit_message || '').split('\n')[0].slice(0, 60));
    const link = run.link ? `<a href="${esc(run.link)}" target="_blank" class="no-underline">${statusBadge(run.status)} ↗</a>` : statusBadge(run.status);

    html += `<tr>
      <td class="text-sm">${esc(run.repo_name)}</td>
      <td class="text-sm text-dim">#${run.pipeline_number}</td>
      <td>${link}</td>
      <td>${eventIcon(run.event)}</td>
      <td class="text-sm">${esc(run.branch || '—')}</td>
      <td class="text-sm" title="${msg}"><code>${sha || '—'}</code> ${msg}</td>
      <td class="text-sm">${esc(run.author || '—')}</td>
      <td>${fmtDuration(run.duration_secs)}</td>
      <td>${run.started_at ? timeAgo(run.started_at) : '—'}</td>
    </tr>`;
  }
  html += '</table></div>';

  el.innerHTML = html;
}


// Workers tab

async function _renderWorkers() {
  let d;
  try {
    d = await api('/cicd/workers');
  } catch {
    return '<div class="empty">No workers data — run sync_woodpecker.py or click Sync</div>';
  }
  const items = d.items || [];

  const stColor = s => ({connected: 'green', idle: 'accent', busy: 'orange', offline: 'red'}[s] || 'text-dim');

  let html = `<div class="mb-12">
    <button data-action="syncWorkers" class="btn btn-primary pad-5-14">Sync Workers from Woodpecker</button>
  </div>`;

  if (!items.length) {
    return html + '<div class="empty">No workers registered</div>';
  }

  html += `<div class="table-wrap"><table>
    <tr><th>Name</th><th>Hostname</th><th>Platform</th><th>Labels</th><th>Capacity</th><th>Status</th><th>Last Contact</th><th>Node</th><th>Running</th></tr>`;

  for (const w of items) {
    const labels = w.labels || {};
    const labelTags = Object.entries(labels)
      .map(([k, v]) => `<span class="pl-var-pill">${esc(k)}=${esc(v)}</span>`)
      .join('') || '<span class="text-dim text-xs">none</span>';
    const nodeLink = w.node_hostname
      ? `<span class="clickable" data-action="showNode" data-id="${w.node_id}">${esc(w.node_hostname)}</span>`
      : '<span class="text-dim">—</span>';

    html += `<tr>
      <td class="text-bold">${esc(w.name)}</td>
      <td>${esc(w.hostname || '—')}</td>
      <td class="text-sm text-dim">${esc(w.platform || '—')}</td>
      <td>${labelTags}</td>
      <td class="text-center">${w.capacity || 1}</td>
      <td><span class="${txtColor(stColor(w.status))} text-bold">${esc(w.status || 'unknown')}</span></td>
      <td>${w.last_contact ? timeAgo(w.last_contact) : '—'}</td>
      <td>${nodeLink}</td>
      <td class="text-center">${w.running_pipelines || 0}</td>
    </tr>`;
  }
  html += '</table></div>';
  return html;
}

export async function syncWorkers() {
  try {
    const r = await fetch(API + '/cicd/workers/sync', { method: 'POST' });
    const d = await r.json();
    if (d.error || d.detail) {
      alert(d.detail || d.error);
    }
  } catch (e) {
    alert('Sync failed: ' + e.message);
  }
  loadView();
}


// Servers tab

async function _renderServers() {
  const d = await api('/cicd/servers');
  const items = d.items || [];

  const stColor = s => ({connected: 'green', error: 'red', offline: 'text-dim'}[s] || 'text-dim');

  let html = `<div class="detail-section">
    <h3>Add CI/CD Server</h3>
    <div class="detail-grid gap-row-col w-500">
      <span class="k">Name</span>
      <input id="srv-name" placeholder="altair-woodpecker" class="form-input">
      <span class="k">Type</span>
      <select id="srv-type" class="form-input">
        <option value="woodpecker">Woodpecker</option>
        <option value="gitea">Gitea</option>
        <option value="gitlab">GitLab</option>
        <option value="forgejo">Forgejo</option>
      </select>
      <span class="k">URL</span>
      <input id="srv-url" placeholder="https://ci.example.com" class="form-input">
      <span class="k">Token</span>
      <input id="srv-token" type="password" class="form-input">
    </div>
    <button data-action="addCicdServer" class="btn btn-primary mt-12 pad-5-14">Add Server</button>
  </div>`;

  if (items.length) {
    html += `<div class="table-wrap"><table>
      <tr><th>Name</th><th>Type</th><th>URL</th><th>Status</th><th>Last check</th><th>Actions</th></tr>`;
    for (const s of items) {
      html += `<tr>
        <td>${esc(s.name)}</td>
        <td><span class="text-accent">${esc(s.server_type)}</span></td>
        <td class="text-sm"><a href="${esc(s.url)}" target="_blank" class="text-default">${esc(s.url)} ↗</a></td>
        <td><span class="${txtColor(stColor(s.status))} text-bold">${esc(s.status)}</span></td>
        <td>${s.last_check ? timeAgo(s.last_check) : '—'}</td>
        <td>
          <button data-action="testCicdServer" data-id="${s.id}" class="btn btn-primary">Test</button>
          <button data-action="deleteCicdServer" data-id="${s.id}" class="btn btn-danger">Delete</button>
        </td>
      </tr>`;
    }
    html += '</table></div>';
  } else {
    html += '<div class="empty">No CI/CD servers configured</div>';
  }

  return html;
}

export async function addCicdServer() {
  const name = document.getElementById('srv-name').value.trim();
  const url = document.getElementById('srv-url').value.trim();
  const server_type = document.getElementById('srv-type').value;
  const token = document.getElementById('srv-token').value;
  if (!name || !url) return alert('Name and URL required');
  await fetch(API + '/cicd/servers', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name, url, server_type, token}),
  });
  loadView();
}

export async function testCicdServer(id) {
  const r = await fetch(API + `/cicd/servers/${id}/test`, {method: 'POST'});
  const d = await r.json();
  alert(`${d.status}: ${d.detail || ''}`);
  loadView();
}

export async function deleteCicdServer(id) {
  if (!confirm('Delete this server?')) return;
  await fetch(API + `/cicd/servers/${id}`, {method: 'DELETE'});
  loadView();
}

export function pipelinesSearch(v) {
  _searchQ = v || '';
  window.refreshView();
}
