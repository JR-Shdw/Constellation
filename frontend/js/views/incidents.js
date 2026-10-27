// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, paginator, timeAgo, txtColor } from '../api.js';

const STATUSES = ['new', 'triaged', 'in_progress', 'resolved', 'closed'];
const PRIORITIES = ['P1', 'P2', 'P3', 'P4'];
const CLOSE_REASONS = ['fixed', 'mitigated', 'false_positive', 'duplicate', 'wont_fix', 'accepted_risk'];

function priorityPill(p) {
  const cls = (p || '').toLowerCase() || 'unknown';
  return `<span class="priority-pill ${cls}">${esc(p || '—')}</span>`;
}

function statusBadge(s) {
  const map = { new: 'accent', triaged: 'orange', in_progress: 'yellow', resolved: 'green', closed: 'text-dim' };
  const c = map[s] || 'text-dim';
  return `<span class="${txtColor(c)} text-sm text-bold">${esc(s || '—')}</span>`;
}

function durationSec(secs) {
  if (secs == null) return '—';
  if (secs < 60) return `${Math.round(secs)}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  if (secs < 86400) return `${(secs / 3600).toFixed(1)}h`;
  return `${(secs / 86400).toFixed(1)}d`;
}


export async function renderIncidents(el) {
  const params = new URLSearchParams();
  const filterStatus = window.incStatus || '';
  const filterPriority = window.incPriority || '';
  const filterQ = window.incQuery || '';
  if (filterStatus) params.set('status', filterStatus);
  if (filterPriority) params.set('priority', filterPriority);
  if (filterQ) params.set('q', filterQ);
  params.set('page', window.currentPage || 1);
  params.set('per_page', 50);

  const [stats, data] = await Promise.all([
    api('/incidents/stats'),
    api('/incidents?' + params.toString()),
  ]);
  const items = data.items || [];

  // Stats cards
  const total = Object.values(stats.by_status || {}).reduce((a, b) => a + b, 0);
  let html = `<div class="stats-grid mb-16">
    <div class="stat-card"><div class="label">Total</div><div class="value">${total}</div></div>
    <div class="stat-card"><div class="label">Open</div><div class="value ${stats.total_open > 0 ? 'orange' : ''}">${stats.total_open}</div></div>
    <div class="stat-card"><div class="label">P1</div><div class="value red">${(stats.by_priority || {}).P1 || 0}</div></div>
    <div class="stat-card"><div class="label">P2</div><div class="value orange">${(stats.by_priority || {}).P2 || 0}</div></div>
    <div class="stat-card"><div class="label">MTTA p50</div><div class="value">${durationSec(stats.mtta_p50_seconds)}</div></div>
    <div class="stat-card"><div class="label">MTTR p50</div><div class="value">${durationSec(stats.mttr_p50_seconds)}</div></div>
  </div>`;

  // Filters
  html += `<div class="flex gap-8 mb-12 flex-wrap items-center">
    <input id="inc-q" placeholder="Search title/description..." value="${esc(filterQ)}" class="f-input inc-search">
    <select id="inc-status" class="f-input">
      <option value="">All statuses</option>
      ${STATUSES.map(s => `<option value="${s}"${s === filterStatus ? ' selected' : ''}>${s}</option>`).join('')}
    </select>
    <select id="inc-priority" class="f-input">
      <option value="">All priorities</option>
      ${PRIORITIES.map(p => `<option value="${p}"${p === filterPriority ? ' selected' : ''}>${p}</option>`).join('')}
    </select>
    <button data-action="_applyIncFilters" class="btn btn-primary">Filter</button>
    <button data-action="_showIncForm" class="btn btn-primary">New incident</button>
  </div>`;

  // New incident form (hidden)
  html += `<div id="inc-add-form" class="hidden mb-16 detail-section">
    <h3>New incident</h3>
    <div class="detail-grid inc-grid-720">
      <span class="k">Title</span>
      <input id="inc-f-title" placeholder="Short summary" class="f-input">
      <span class="k">Description</span>
      <textarea id="inc-f-desc" rows="3" class="f-input"></textarea>
      <span class="k">CVE</span>
      <input id="inc-f-cve" placeholder="CVE-2024-..." class="f-input">
      <span class="k">Asset</span>
      <input id="inc-f-asset" placeholder="hostname/container" class="f-input">
      <span class="k">Package</span>
      <input id="inc-f-pkg" placeholder="package/image" class="f-input">
      <span class="k">Severity</span>
      <select id="inc-f-sev" class="f-input">
        <option value="">—</option>
        <option value="critical">critical</option>
        <option value="high">high</option>
        <option value="medium">medium</option>
        <option value="low">low</option>
      </select>
      <span class="k">Environment</span>
      <select id="inc-f-env" class="f-input">
        <option value="">—</option>
        <option value="production">production</option>
        <option value="staging">staging</option>
        <option value="development">development</option>
        <option value="lab">lab</option>
      </select>
      <span class="k">Exposure</span>
      <select id="inc-f-expo" class="f-input">
        <option value="">—</option>
        <option value="internet">internet</option>
        <option value="private_network">private_network</option>
        <option value="docker_internal">docker_internal</option>
        <option value="localhost">localhost</option>
      </select>
      <span class="k">CVSS</span>
      <input id="inc-f-cvss" type="number" step="0.1" min="0" max="10" class="f-input">
      <span class="k">In KEV</span>
      <input id="inc-f-kev" type="checkbox">
    </div>
    <div class="mt-10">
      <button data-action="submitIncident" class="btn btn-primary">Create</button>
    </div>
  </div>`;

  // Table
  if (!items.length) {
    html += `<div class="empty">No incidents match your filters.</div>`;
  } else {
    html += `<table class="data-table"><thead><tr>
      <th>UID</th><th>Title</th><th>Status</th><th>Priority</th>
      <th>Asset</th><th>CVE</th><th>Assignee</th><th>Created</th>
    </tr></thead><tbody>`;
    for (const it of items) {
      html += `<tr data-action="showIncident" data-id="${it.id}" class="cursor-pointer">
        <td class="text-mono text-sm">${esc(it.uid)}</td>
        <td>${esc(it.title || '')}</td>
        <td>${statusBadge(it.status)}</td>
        <td>${priorityPill(it.priority)}</td>
        <td>${esc(it.affected_asset || '—')}</td>
        <td class="text-mono text-sm">${esc(it.cve_id || '—')}</td>
        <td>${esc(it.assignee || '—')}</td>
        <td>${timeAgo(it.created_at)}</td>
      </tr>`;
    }
    html += `</tbody></table>`;
    html += paginator(data.total, data.page, data.per_page);
  }

  // Detail panel slot
  html += `<div id="inc-panel"></div>`;

  el.innerHTML = html;
}


export async function showIncident(id) {
  const data = await api('/incidents/' + id);
  const inc = data.incident;
  const events = data.events || [];
  const tickets = data.tickets || [];
  const panel = document.getElementById('inc-panel');
  if (!panel) return;

  let html = `<div class="detail-section mt-16">
    <h3>${esc(inc.uid)} — ${esc(inc.title)}</h3>
    <div class="detail-grid inc-grid-900">
      <span class="k">Status</span>
      <select id="ip-status" class="f-input">
        ${STATUSES.map(s => `<option value="${s}"${s === inc.status ? ' selected' : ''}>${s}</option>`).join('')}
      </select>
      <span class="k">Priority</span>
      <select id="ip-priority" class="f-input">
        ${PRIORITIES.map(p => `<option value="${p}"${p === inc.priority ? ' selected' : ''}>${p}</option>`).join('')}
      </select>
      <span class="k">Assignee</span>
      <input id="ip-assignee" value="${esc(inc.assignee || '')}" class="f-input">
      <span class="k">Description</span>
      <textarea id="ip-desc" rows="3" class="f-input">${esc(inc.description || '')}</textarea>
      <span class="k">Close reason</span>
      <select id="ip-close" class="f-input">
        <option value="">—</option>
        ${CLOSE_REASONS.map(r => `<option value="${r}"${r === inc.close_reason ? ' selected' : ''}>${r}</option>`).join('')}
      </select>
      <span class="k">Rule matched</span>
      <span class="text-dim">${esc(inc.rule_matched || '—')}</span>
      <span class="k">CVE / Asset / Package</span>
      <span class="text-mono text-sm">${esc(inc.cve_id || '—')} / ${esc(inc.affected_asset || '—')} / ${esc(inc.affected_package || '—')}</span>
      <span class="k">Created / Triaged / Resolved / Closed</span>
      <span class="text-sm text-dim">${timeAgo(inc.created_at)} / ${inc.triaged_at ? timeAgo(inc.triaged_at) : '—'} / ${inc.resolved_at ? timeAgo(inc.resolved_at) : '—'} / ${inc.closed_at ? timeAgo(inc.closed_at) : '—'}</span>
    </div>
    <div class="mt-10">
      <button data-action="updateIncident" data-id="${inc.id}" class="btn btn-primary">Save</button>
    </div>
  </div>`;

  // External tickets
  if (tickets.length) {
    html += `<div class="detail-section mt-16"><h3>External tickets</h3>
      <table class="data-table"><thead><tr>
        <th>Platform</th><th>Integration</th><th>Ticket</th><th>External status</th><th>Synced</th>
      </tr></thead><tbody>
      ${tickets.map(t => `<tr>
        <td>${esc(t.platform || '')}</td>
        <td>${esc(t.integration_name || '')}</td>
        <td>${t.external_url ? `<a href="${esc(t.external_url)}" target="_blank" rel="noopener">${esc(t.external_id)}</a>` : esc(t.external_id)}</td>
        <td class="text-sm">${esc(t.external_status || '—')}</td>
        <td class="text-sm text-dim">${t.last_synced_at ? timeAgo(t.last_synced_at) : '—'}</td>
      </tr>`).join('')}
      </tbody></table></div>`;
  }

  // Timeline
  html += `<div class="detail-section mt-16"><h3>Timeline</h3>`;
  if (!events.length) {
    html += `<div class="empty">No events yet.</div>`;
  } else {
    html += `<ul class="inc-events-list">`;
    for (const ev of events) {
      const who = esc(ev.actor || 'system');
      let line = `<strong>${esc(ev.event_type)}</strong> by ${who}`;
      if (ev.from_value || ev.to_value) {
        line += ` — ${esc(ev.from_value || '∅')} → ${esc(ev.to_value || '∅')}`;
      }
      if (ev.detail && ev.detail.body) {
        line += `<br><span class="text-dim">${esc(ev.detail.body)}</span>`;
      }
      html += `<li class="inc-event-item">
        <span class="text-dim text-sm">${timeAgo(ev.created_at)}</span> — ${line}
      </li>`;
    }
    html += `</ul>`;
  }
  html += `<div class="mt-10">
    <input id="ip-comment" placeholder="Add a comment..." class="f-input inc-comment-input">
    <button data-action="commentIncident" data-id="${inc.id}" class="btn btn-primary">Comment</button>
  </div></div>`;

  panel.innerHTML = html;
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}


export async function submitIncident() {
  const payload = {
    title: document.getElementById('inc-f-title').value.trim(),
    description: document.getElementById('inc-f-desc').value.trim() || null,
    cve_id: document.getElementById('inc-f-cve').value.trim() || null,
    affected_asset: document.getElementById('inc-f-asset').value.trim() || null,
    affected_package: document.getElementById('inc-f-pkg').value.trim() || null,
    severity: document.getElementById('inc-f-sev').value || null,
    environment: document.getElementById('inc-f-env').value || null,
    exposure: document.getElementById('inc-f-expo').value || null,
    cvss: parseFloat(document.getElementById('inc-f-cvss').value) || null,
    in_kev: document.getElementById('inc-f-kev').checked,
  };
  if (!payload.title) return alert('Title required');
  const r = await fetch(API + '/incidents', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!r.ok) return alert('Error: ' + r.status);
  window.refreshView();
}


export async function updateIncident(id) {
  const payload = {
    status: document.getElementById('ip-status').value,
    priority: document.getElementById('ip-priority').value,
    assignee: document.getElementById('ip-assignee').value.trim() || null,
    description: document.getElementById('ip-desc').value,
    close_reason: document.getElementById('ip-close').value || null,
  };
  const r = await fetch(API + '/incidents/' + id, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!r.ok) {
    const d = await r.json().catch(() => ({}));
    return alert('Error: ' + (d.detail || r.status));
  }
  window.refreshView();
}


export async function commentIncident(id) {
  const body = document.getElementById('ip-comment').value.trim();
  if (!body) return;
  await fetch(API + `/incidents/${id}/comment`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ body }),
  });
  showIncident(id);
}


// Filter helpers (wired via _actions)

export function _showIncForm() {
  const f = document.getElementById('inc-add-form');
  if (f) f.style.display = f.style.display === 'none' ? 'block' : 'none';
}

export function _applyIncFilters() {
  window.incQuery = document.getElementById('inc-q').value.trim();
  window.incStatus = document.getElementById('inc-status').value;
  window.incPriority = document.getElementById('inc-priority').value;
  window.currentPage = 1;
  window.refreshView();
}
