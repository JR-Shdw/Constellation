// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, paginator, tabBar, timeAgo, txtColor } from '../api.js';

let _searchQ = '';

function statusBadge(s) {
  const c = { success:'green', failure:'red', running:'accent', timeout:'orange', skipped:'text-dim' }[s] || 'text-dim';
  const anim = s === 'running' ? ' class="pipeline-running"' : '';
  return `<span${anim} class="${txtColor(c)} text-bold">${esc(s || '—')}</span>`;
}

function typeBadge(t) {
  const map = { woodpecker_pipeline: ['accent', 'Woodpecker'], gitlab_pipeline: ['orange', 'GitLab'], http_request: ['green', 'HTTP'] };
  const [c, label] = map[t] || ['text-dim', t];
  return `<span class="${txtColor(c)} text-sm text-bold">${label}</span>`;
}

function toggleBadge(enabled, id) {
  if (enabled) {
    return `<span data-toggle="${id}" data-action="toggleSchedulerJob" data-id="${id}" class="sched-toggle-on">ON</span>`;
  }
  return `<span data-toggle="${id}" data-action="toggleSchedulerJob" data-id="${id}" class="inline-block pad-2-10 rounded-pill bg-hover text-dim text-xs text-bolder cursor-pointer border no-select">OFF</span>`;
}

function humanCron(expr) {
  if (!expr) return '—';
  const p = expr.split(/\s+/);
  if (p.length !== 5) return expr;
  const [min, hr, dom, mon, dow] = p;
  const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];

  if (min === '0' && hr.startsWith('*/') && dom === '*' && mon === '*' && dow === '*') {
    return `Every ${hr.slice(2)}h`;
  }
  if (dom === '*' && mon === '*' && dow === '*' && !hr.includes('/') && !min.includes('/')) {
    return `Daily ${hr.padStart(2,'0')}:${min.padStart(2,'0')}`;
  }
  if (dom === '*' && mon === '*' && !dow.includes('*') && !hr.includes('/')) {
    const d = days[parseInt(dow)] || dow;
    return `${d} ${hr.padStart(2,'0')}:${min.padStart(2,'0')}`;
  }
  return expr;
}

function fmtDuration(secs) {
  if (!secs || secs <= 0) return '—';
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return s > 0 ? `${m}m${s}s` : `${m}m`;
}

function timeLeft(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  const now = new Date();
  const secs = Math.floor((d - now) / 1000);
  if (secs <= 0) return 'now';
  if (secs < 60) return `in ${secs}s`;
  if (secs < 3600) return `in ${Math.floor(secs/60)}m`;
  if (secs < 86400) return `in ${Math.floor(secs/3600)}h`;
  return `in ${Math.floor(secs/86400)}d`;
}


// Main render

export async function renderScheduler(el) {
  const tab = window.schedulerTab || 'jobs';

  let html = tabBar(
    [['jobs', 'Jobs'], ['history', 'History']],
    tab, 'scheduler'
  );

  if (tab === 'history') {
    el.innerHTML = html + await _renderHistory();
    return;
  }

  // Jobs tab
  const [stats, data] = await Promise.all([
    api('/scheduler/stats'),
    api('/scheduler/jobs'),
  ]);
  const allItems = data.items || [];
  const q = _searchQ.trim().toLowerCase();
  const items = q
    ? allItems.filter(j =>
        (j.name || '').toLowerCase().includes(q) ||
        (j.description || '').toLowerCase().includes(q) ||
        (j.job_type || '').toLowerCase().includes(q) ||
        (j.cron_expr || '').toLowerCase().includes(q)
      )
    : allItems;

  // Stats cards
  const rate24 = stats.runs_24h > 0 ? Math.round(100 * stats.success_24h / stats.runs_24h) : '—';
  const rateColor = rate24 >= 90 ? 'green' : rate24 >= 70 ? 'orange' : 'red';

  html += `<div class="stats-grid mb-16">
    <div class="stat-card"><div class="label">Total jobs</div><div class="value">${stats.total_jobs}</div></div>
    <div class="stat-card"><div class="label">Enabled</div><div class="value green">${stats.enabled_jobs}</div></div>
    <div class="stat-card"><div class="label">Running</div><div class="value accent">${stats.running_jobs}</div></div>
    <div class="stat-card"><div class="label">Runs 24h</div><div class="value">${stats.runs_24h}</div></div>
    <div class="stat-card"><div class="label">Fails 24h</div><div class="value ${stats.failure_24h > 0 ? 'red' : ''}">${stats.failure_24h}</div></div>
    <div class="stat-card"><div class="label">Rate 24h</div><div class="value ${rateColor}">${rate24}%</div></div>
  </div>`;

  if (stats.next_job_name) {
    html += `<div class="text-dim text-sm mb-12">Next: <strong>${esc(stats.next_job_name)}</strong> ${stats.next_job_at ? timeLeft(stats.next_job_at) : ''}</div>`;
  }

  // Search bar (per-view, in-memory; the full job list is small and unpaginated)
  html += `<div class="flex gap-sm flex-wrap items-center mb-12">
    <input type="text" placeholder="Search job, type, cron…" value="${esc(_searchQ)}"
           data-change="schedulerSearch" class="f-filter w-200">
  </div>`;

  // Add job button
  html += `<div class="mb-12">
    <button data-action="showAddJobForm" class="btn btn-primary btn-md">Add Job</button>
  </div>`;

  // Add job form (hidden by default)
  html += `<div id="add-job-form" class="hidden mb-16 detail-section">
    <h3>New Job</h3>
    <div class="detail-grid sched-grid-600">
      <span class="k">Name</span>
      <input id="job-name" placeholder="my-job" class="f-input">
      <span class="k">Description</span>
      <input id="job-desc" placeholder="What this job does" class="f-input">
      <span class="k">Type</span>
      <select id="job-type" class="f-input">
        <option value="http_request">HTTP Request</option>
        <option value="woodpecker_pipeline">Woodpecker Pipeline</option>
        <option value="gitlab_pipeline">GitLab Pipeline</option>
      </select>
      <span class="k">Cron</span>
      <input id="job-cron" placeholder="0 3 * * *" class="f-input">
      <span class="k">Config (JSON)</span>
      <textarea id="job-config" rows="4" class="f-input text-mono text-sm">{"method": "GET", "url": "/api/v1/health", "expected_status": [200]}</textarea>
      <span class="k">Timeout (s)</span>
      <input id="job-timeout" type="number" value="300" class="f-input w-100">
      <span class="k">Retries</span>
      <input id="job-retries" type="number" value="0" class="f-input w-100">
      <span class="k">Allow overlap</span>
      <input id="job-overlap" type="checkbox">
    </div>
    <button data-action="submitSchedulerJob" class="btn btn-primary btn-md mt-12">Create Job</button>
  </div>`;

  // Jobs table
  html += `<div class="table-wrap"><table>
    <thead><tr><th>Name</th><th>Type</th><th>Schedule</th><th>Last Run</th><th>Status</th><th>Next Run</th><th>30d</th><th>Enabled</th><th>Actions</th></tr></thead><tbody>`;

  if (!items.length) {
    html += '<tr><td colspan="9" class="empty">No jobs configured</td></tr>';
  }

  for (const j of items) {
    const rate30 = j.total_runs_30d > 0
      ? Math.round(100 * j.success_count_30d / j.total_runs_30d)
      : null;
    const rc = rate30 >= 90 ? 'green' : rate30 >= 70 ? 'orange' : 'red';
    const stats30 = rate30 !== null
      ? `<span class="${txtColor(rc)}">${rate30}%</span> <span class="text-dim text-xs">(${j.total_runs_30d})</span>`
      : '—';

    html += `<tr>
      <td class="text-bold">${esc(j.name)}${j.description ? `<br><span class="text-dim text-xs">${esc(j.description)}</span>` : ''}</td>
      <td>${typeBadge(j.job_type)}</td>
      <td><span title="${esc(j.cron_expr)}" class="text-sm">${humanCron(j.cron_expr)}</span></td>
      <td>${j.last_run_at ? timeAgo(j.last_run_at) : '—'}</td>
      <td>${j.is_running ? statusBadge('running') : statusBadge(j.last_status)}</td>
      <td class="text-sm">${j.next_run_at ? timeLeft(j.next_run_at) : '—'}</td>
      <td class="text-sm">${stats30}</td>
      <td>${toggleBadge(j.enabled, j.id)}</td>
      <td class="nowrap">
        <button data-action="triggerJob" data-id="${j.id}" class="btn btn-primary" ${j.is_running ? 'disabled' : ''}>Run</button>
        <button data-action="editSchedulerJob" data-id="${j.id}" class="btn btn-primary">Edit</button>
        <button data-action="deleteSchedulerJob" data-id="${j.id}" class="btn btn-danger">Del</button>
      </td>
    </tr>`;
    // Hidden edit row
    const cfgStr = esc(JSON.stringify(j.config || {}, null, 2));
    html += `<tr id="edit-row-${j.id}" class="hidden"><td colspan="9" class="p-12 bg-hover">
      <div class="detail-grid sched-grid-700">
        <span class="k">Name</span>
        <input id="edit-name-${j.id}" value="${esc(j.name)}" class="f-input">
        <span class="k">Description</span>
        <input id="edit-desc-${j.id}" value="${esc(j.description || '')}" class="f-input">
        <span class="k">Type</span>
        <select id="edit-type-${j.id}" class="f-input">
          <option value="http_request" ${j.job_type==='http_request'?'selected':''}>HTTP Request</option>
          <option value="woodpecker_pipeline" ${j.job_type==='woodpecker_pipeline'?'selected':''}>Woodpecker Pipeline</option>
          <option value="gitlab_pipeline" ${j.job_type==='gitlab_pipeline'?'selected':''}>GitLab Pipeline</option>
        </select>
        <span class="k">Cron</span>
        <input id="edit-cron-${j.id}" value="${esc(j.cron_expr)}" class="f-input">
        <span class="k">Config (JSON)</span>
        <textarea id="edit-config-${j.id}" rows="4" class="f-input text-mono text-sm">${cfgStr}</textarea>
        <span class="k">Timeout (s)</span>
        <input id="edit-timeout-${j.id}" type="number" value="${j.timeout_secs || 300}" class="f-input w-100">
        <span class="k">Retries</span>
        <input id="edit-retries-${j.id}" type="number" value="${j.max_retries || 0}" class="f-input w-100">
        <span class="k">Allow overlap</span>
        <input id="edit-overlap-${j.id}" type="checkbox" ${j.allow_overlap ? 'checked' : ''}>
      </div>
      <div class="mt-10">
        <button data-action="saveSchedulerJob" data-id="${j.id}" class="btn btn-primary btn-md">Save</button>
        <button data-action="editSchedulerJob" data-id="${j.id}" class="btn-cancel-ghost">Cancel</button>
      </div>
    </td></tr>`;
  }
  html += '</tbody></table></div>';

  el.innerHTML = html;
}


// History tab

async function _renderHistory() {
  const page = window.currentPage || 1;
  const d = await api(`/scheduler/runs?page=${page}&per_page=50`);
  const items = d.items || [];

  let html = `<div class="table-wrap"><table>
    <thead><tr><th>Time</th><th>Job</th><th>Status</th><th>Duration</th><th>Attempt</th><th>Pipeline</th><th>Error</th></tr></thead><tbody>`;

  if (!items.length) {
    html += '<tr><td colspan="7" class="empty">No runs yet</td></tr>';
  }

  for (const r of items) {
    const pipeLink = r.pipeline_link
      ? `<a href="${esc(r.pipeline_link)}" target="_blank" class="text-accent">#${r.pipeline_number}</a>`
      : '—';
    const err = r.error_msg
      ? `<span title="${esc(r.error_msg)}" class="text-red text-xs">${esc(r.error_msg.slice(0, 60))}</span>`
      : '';

    html += `<tr>
      <td class="text-sm">${r.started_at ? timeAgo(r.started_at) : '—'}</td>
      <td class="text-bold text-sm">${esc(r.job_name)}</td>
      <td>${statusBadge(r.status)}</td>
      <td>${fmtDuration(r.duration_secs)}</td>
      <td class="text-center text-sm">${r.attempt}</td>
      <td>${pipeLink}</td>
      <td>${err}</td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  html += paginator(d.total, page, 50);
  return html;
}


// Actions

export function showAddJobForm() {
  const form = document.getElementById('add-job-form');
  form.style.display = form.style.display === 'none' ? 'block' : 'none';
}

export async function submitSchedulerJob() {
  const name = document.getElementById('job-name').value.trim();
  const cron_expr = document.getElementById('job-cron').value.trim();
  const job_type = document.getElementById('job-type').value;
  if (!name || !cron_expr) return alert('Name and cron expression required');

  let config;
  try {
    config = JSON.parse(document.getElementById('job-config').value);
  } catch {
    return alert('Invalid JSON in config');
  }

  await fetch(API + '/scheduler/jobs', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      name,
      description: document.getElementById('job-desc').value.trim() || null,
      job_type,
      cron_expr,
      config,
      timeout_secs: parseInt(document.getElementById('job-timeout').value) || 300,
      max_retries: parseInt(document.getElementById('job-retries').value) || 0,
      allow_overlap: document.getElementById('job-overlap').checked,
    }),
  });
  window.refreshView();
}

export async function triggerJob(id) {
  const btn = document.querySelector(`button[data-action="triggerJob"][data-id="${id}"]`);
  if (btn) { btn.textContent = '…'; btn.disabled = true; }
  const r = await fetch(API + `/scheduler/jobs/${id}/trigger`, { method: 'POST' });
  const d = await r.json();
  if (d.error) alert(d.error);
  window.refreshView();
}

export async function toggleSchedulerJob(id) {
  // Optimistic toggle — update DOM immediately, then sync with API
  const badge = document.querySelector(`[data-toggle="${id}"]`);
  if (badge) {
    const wasOn = badge.textContent.trim() === 'ON';
    badge.textContent = wasOn ? 'OFF' : 'ON';
    badge.style.background = wasOn ? 'var(--bg-hover)' : 'var(--green)';
    badge.style.color = wasOn ? 'var(--text-dim)' : '#fff';
    badge.style.border = wasOn ? '1px solid var(--border)' : 'none';
  }
  const r = await fetch(API + `/scheduler/jobs/${id}/toggle`, { method: 'POST' });
  const d = await r.json();
  if (d.error) {
    window.refreshView(); // revert on error
  }
}

export function editSchedulerJob(id) {
  const row = document.getElementById('edit-row-' + id);
  if (row) row.style.display = row.style.display === 'none' ? '' : 'none';
}

export async function saveSchedulerJob(id) {
  const name = document.getElementById('edit-name-' + id).value.trim();
  const cron_expr = document.getElementById('edit-cron-' + id).value.trim();
  if (!name || !cron_expr) return alert('Name and cron required');

  let config;
  try {
    config = JSON.parse(document.getElementById('edit-config-' + id).value);
  } catch {
    return alert('Invalid JSON in config');
  }

  const body = {
    name,
    description: document.getElementById('edit-desc-' + id).value.trim() || null,
    job_type: document.getElementById('edit-type-' + id).value,
    cron_expr,
    config,
    timeout_secs: parseInt(document.getElementById('edit-timeout-' + id).value) || 300,
    max_retries: parseInt(document.getElementById('edit-retries-' + id).value) || 0,
    allow_overlap: document.getElementById('edit-overlap-' + id).checked,
  };

  const r = await fetch(API + `/scheduler/jobs/${id}`, {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });
  const d = await r.json();
  if (d.error) return alert(d.error);
  window.refreshView();
}

export async function deleteSchedulerJob(id) {
  if (!confirm('Delete this job?')) return;
  await fetch(API + `/scheduler/jobs/${id}`, { method: 'DELETE' });
  window.refreshView();
}

export function schedulerSearch(v) {
  _searchQ = v || '';
  window.refreshView();
}
