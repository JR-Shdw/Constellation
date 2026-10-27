// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, tabBar, timeAgo, txtColor } from '../api.js';

const _TYPES = [
  'package_upgrade', 'container_build', 'container_deploy',
  'ansible_playbook', 'image_pull',
];

function statusBadge(s) {
  const c = {
    draft: 'text-dim', pending: 'orange', approved: 'blue',
    running: 'accent', success: 'green', failure: 'red',
    cancelled: 'text-dim',
  }[s] || 'text-dim';
  return `<span class="${txtColor(c)} text-bold">${esc(s)}</span>`;
}

function actionBtns(d) {
  const btns = [];
  if (d.status === 'draft') {
    btns.push(`<button class="btn btn-bg" data-action="submitDeployment" data-id="${d.id}">Submit</button>`);
  }
  if (d.status === 'pending') {
    btns.push(`<button class="btn btn-success" data-action="approveDeployment" data-id="${d.id}">Approve</button>`);
    btns.push(`<button class="btn btn-danger" data-action="rejectDeployment" data-id="${d.id}">Reject</button>`);
  }
  if (d.status === 'approved') {
    btns.push(`<button class="btn btn-primary" data-action="executeDeployment" data-id="${d.id}">Execute</button>`);
  }
  return btns.join(' ');
}

function renderTable(items) {
  let html = `<div class="table-wrap"><table>
    <thead><tr><th>Title</th><th>Type</th><th>Status</th><th>Worker</th><th>Repo</th><th>Branch</th><th>Pipeline</th><th>Created</th><th>Actions</th></tr></thead><tbody>`;
  if (!items.length) {
    html += '<tr><td colspan="9" class="empty">No deployments</td></tr>';
  }
  for (const d of items) {
    const plink = d.pipeline_link
      ? `<a href="${esc(d.pipeline_link)}" target="_blank" class="text-default">#${d.pipeline_number}</a>`
      : (d.pipeline_number ? '#' + d.pipeline_number : '—');
    html += `<tr>
      <td>${esc(d.title)}</td>
      <td class="text-sm">${esc(d.deploy_type)}</td>
      <td>${statusBadge(d.status)}</td>
      <td class="text-sm">${esc(d.worker_hostname || d.worker_name || '—')}</td>
      <td class="text-sm">${esc(d.repo_name || '—')}</td>
      <td class="text-sm">${esc(d.branch || '—')}</td>
      <td class="text-sm">${plink}</td>
      <td>${timeAgo(d.created_at)}</td>
      <td>${actionBtns(d)}</td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  return html;
}

export async function renderDeployments(el) {
  const tab = window.deployTab || 'active';

  let html = tabBar(
    [['active', 'Active'], ['create', 'Create'], ['history', 'History']],
    tab, 'deploy'
  );

  if (tab === 'active') {
    const stats = await api('/deployments/stats');
    html += `<div class="stats-grid mb-16">
      <div class="stat-card"><div class="label">Total</div><div class="value">${stats.total || 0}</div></div>
      <div class="stat-card"><div class="label">Active</div><div class="value">${stats.active || 0}</div></div>
      <div class="stat-card"><div class="label">Running</div><div class="value text-accent">${stats.running || 0}</div></div>
      <div class="stat-card"><div class="label">Success</div><div class="value green">${stats.success || 0}</div></div>
      <div class="stat-card"><div class="label">Failed</div><div class="value red">${stats.failed || 0}</div></div>
    </div>`;

    const d = await api('/deployments?size=50');
    const active_items = (d.items || []).filter(
      i => ['draft', 'pending', 'approved', 'running'].includes(i.status)
    );
    html += renderTable(active_items);
  }

  if (tab === 'create') {
    // Load workers, repos, managers for dropdowns
    let workers = [], repos = [], managers = [];
    try { workers = (await api('/cicd/workers')).items || []; } catch {}
    try { repos = (await api('/cicd/repos')).items || []; } catch {}
    try { managers = (await api('/managers')).items || []; } catch {}

    const workerOpts = workers.map(w =>
      `<option value="${esc(w.hostname)}">${esc(w.name)} (${esc(w.hostname)})</option>`
    ).join('');
    const repoOpts = repos.filter(r => r.has_pipeline).map(r =>
      `<option value="${esc(r.repo_name)}">${esc(r.repo_name)}</option>`
    ).join('');
    const mgrOpts = managers.map(m =>
      `<option value="${esc(m.id)}">${esc(m.name)} (${esc(m.manager_type)})</option>`
    ).join('');
    const typeOpts = _TYPES.map(t =>
      `<option value="${t}">${t}</option>`
    ).join('');

    html += `<div class="card-form-600">
      <h3 class="mb-12 text-base text-dim">New deployment</h3>
      <div class="grid gap-sm">
        <input id="dep-title" class="form-input" placeholder="Title">
        <select id="dep-type" class="form-input">${typeOpts}</select>
        <select id="dep-worker" class="form-input"><option value="">— Worker —</option>${workerOpts}</select>
        <select id="dep-repo" class="form-input"><option value="">— Repo (CI/CD) —</option>${repoOpts}</select>
        <input id="dep-branch" class="form-input" placeholder="Branch (default: main)" value="main">
        <select id="dep-manager" class="form-input"><option value="">— Manager (optional) —</option>${mgrOpts}</select>
        <button class="btn btn-primary p-8" data-action="createDeployment">Create draft</button>
      </div>
    </div>`;
  }

  if (tab === 'history') {
    const d = await api('/deployments?size=100');
    html += renderTable(d.items || []);
  }

  el.innerHTML = html;
}

export async function createDeployment() {
  const title = document.getElementById('dep-title').value;
  const deploy_type = document.getElementById('dep-type').value;
  const worker = document.getElementById('dep-worker').value;
  const repo = document.getElementById('dep-repo').value;
  const branch = document.getElementById('dep-branch').value;
  const manager = document.getElementById('dep-manager').value;

  if (!title) return alert('Title required');

  await fetch(API + '/deployments', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      title, deploy_type,
      worker_hostname: worker || null,
      repo_name: repo || null,
      branch: branch || 'main',
      manager_id: manager || null,
      config: {},
    }),
  });
  window.deployTab = 'active';
  window.refreshView();
}

export async function submitDeployment(id) {
  await fetch(API + `/deployments/${id}/submit`, {method: 'POST'});
  window.refreshView();
}

export async function approveDeployment(id) {
  await fetch(API + `/deployments/${id}/approve`, {method: 'POST'});
  window.refreshView();
}

export async function rejectDeployment(id) {
  if (!confirm('Reject this deployment?')) return;
  await fetch(API + `/deployments/${id}/reject`, {method: 'POST'});
  window.refreshView();
}

export async function executeDeployment(id) {
  // Run preflight first
  const pf = await fetch(API + `/deployments/${id}/preflight`, {method: 'POST'});
  const pfData = await pf.json();
  if (!pfData.preflight_ok) {
    const issues = (pfData.checks || [])
      .filter(c => !c.ok)
      .map(c => c.detail)
      .join('\n');
    if (!confirm(`Preflight issues:\n${issues}\n\nProceed anyway?`)) return;
  }
  await fetch(API + `/deployments/${id}/execute`, {method: 'POST'});
  window.refreshView();
}
