// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, paginator, tabBar, timeAgo, txtColor } from '../api.js';
import { renderIncidents } from './incidents.js';

if (window.automationTab === undefined) window.automationTab = 'rules';

let _searchQ = '';

export async function renderAutomation(el) {
  let html = tabBar(
    [['overview', 'How it works'], ['rules', 'Rules'], ['incidents', 'Incidents'], ['priority-rules', 'Priority Rules'], ['log', 'Log']],
    window.automationTab, 'automation'
  );

  if (automationTab === 'overview') {
    el.innerHTML = html + _renderOverview();
    return;
  }

  if (automationTab === 'incidents') {
    const wrap = document.createElement('div');
    await renderIncidents(wrap);
    el.innerHTML = html + wrap.innerHTML;
    return;
  }

  if (automationTab === 'priority-rules') {
    el.innerHTML = html + await _renderPriorityRules();
    return;
  }

  if (automationTab === 'rules') {
    const d = await api('/automation/policies');
    const q = _searchQ.trim().toLowerCase();
    const items = q
      ? (d.items || []).filter(p =>
          (p.name || '').toLowerCase().includes(q) ||
          (p.trigger_type || '').toLowerCase().includes(q) ||
          (p.action || '').toLowerCase().includes(q) ||
          (p.match_hostname || '').toLowerCase().includes(q) ||
          (p.match_image || '').toLowerCase().includes(q)
        )
      : (d.items || []);
    html += `<div class="flex gap-sm flex-wrap items-center mb-12">
      <input type="text" placeholder="Search policy, trigger, action…" value="${esc(_searchQ)}"
             data-change="automationSearch" class="f-filter w-200">
    </div>`;
    html += `<button data-action="showAddPolicyForm" class="btn btn-primary btn-md mb-12">+ Add Policy</button>`;
    html += `<div id="policy-form" class="detail-panel">
      <div class="grid-auto-180 gap-sm mb-10">
        <input id="pf-name" placeholder="Policy name" class="f-input">
        <select id="pf-trigger" class="f-input">
          <option value="cve_detected">cve_detected</option>
          <option value="update_available">update_available</option>
          <option value="backup_overdue">backup_overdue</option>
          <option value="scan_stale">scan_stale</option>
          <option value="misconf_detected">misconf_detected</option>
          <option value="exposure_change">exposure_change</option>
        </select>
        <select id="pf-action" class="f-input">
          <option value="notify">notify</option>
          <option value="email">email</option>
          <option value="create_incident">create_incident</option>
          <option value="manual_validation">manual_validation</option>
          <option value="ignore">ignore</option>
          <option value="rescan">rescan</option>
          <option value="auto_update">auto_update</option>
        </select>
        <input id="pf-priority" type="number" value="0" placeholder="Priority" class="f-input">
        <input id="pf-hostname" placeholder="match_hostname (% wildcard)" class="f-input">
        <input id="pf-image" placeholder="match_image" class="f-input">
        <input id="pf-package" placeholder="match_package" class="f-input">
        <input id="pf-severity" placeholder="severity (critical,high)" class="f-input">
        <input id="pf-env" placeholder="environment (production)" class="f-input">
        <select id="pf-exposure" multiple size="4" class="f-input" title="match_exposure (Ctrl+click for multiple)">
          <option value="internet">internet</option>
          <option value="private_network">private_network</option>
          <option value="docker_internal">docker_internal</option>
          <option value="localhost">localhost</option>
        </select>
        <input id="pf-email-to" placeholder="email: to (comma-separated)" class="f-input">
        <input id="pf-email-subject" placeholder="email: subject (opt, {trigger} {hostname})" class="f-input">
      </div>
      <div class="flex gap-sm">
        <button data-action="submitPolicy" class="btn btn-success-primary">Save</button>
        <button data-action="hideEl" data-target="policy-form" class="btn btn-neutral">Cancel</button>
      </div>
    </div>`;
    html += `<div class="table-wrap"><table>
      <thead><tr><th>Pri</th><th>Name</th><th>Trigger</th><th>Action</th><th>Hostname</th><th>Image</th><th>Severity</th><th>Env</th><th>Exposure</th><th>On</th><th></th></tr></thead><tbody>`;
    if (!items.length) html += '<tr><td colspan="11" class="empty">No policies</td></tr>';
    for (const p of items) {
      const actColor = p.action==='notify'?'accent':p.action==='ignore'?'text-dim':p.action==='auto_update'?'green':'orange';
      html += `<tr${p.enabled ? '' : ' class="opacity-50"'}>
        <td class="text-bold">${p.priority}</td>
        <td>${esc(p.name)}</td>
        <td class="text-sm">${esc(p.trigger_type)}</td>
        <td class="text-sm ${txtColor(actColor)}">${esc(p.action)}</td>
        <td class="text-sm">${esc(p.match_hostname || '*')}</td>
        <td class="text-sm">${esc(p.match_image || '*')}</td>
        <td class="text-sm">${esc((p.match_severity || []).join(',') || '*')}</td>
        <td class="text-sm">${esc((p.match_environment || []).join(',') || '*')}</td>
        <td class="text-sm">${esc((p.match_exposure || []).join(',') || '*')}</td>
        <td><input type="checkbox" ${p.enabled?'checked':''} data-change="togglePolicy" data-id="${p.id}" class="f-accent-green"></td>
        <td><button data-action="deletePolicy" data-id="${p.id}" class="btn btn-ghost-red">✕</button></td>
      </tr>`;
    }
    html += '</tbody></table></div>';
  } else {
    const d = await api(`/automation/log?page=${currentPage}&per_page=50`);
    html += `<div class="table-wrap"><table>
      <thead><tr><th>Time</th><th>Policy</th><th>Trigger</th><th>Action</th><th>Node</th><th>CVE/Image</th><th>Status</th><th></th></tr></thead><tbody>`;
    if (!d.items.length) html += '<tr><td colspan="8" class="empty">No log entries</td></tr>';
    for (const l of d.items) {
      const stColor = {pending:'orange',completed:'green',approved:'green',failed:'red',skipped:'text-dim',ignored:'text-dim'}[l.status] || 'text-dim';
      html += `<tr>
        <td class="text-xs">${timeAgo(l.created_at)}</td>
        <td class="text-sm">${esc(l.policy_name || '—')}</td>
        <td class="text-sm">${esc(l.trigger_type)}</td>
        <td class="text-sm">${esc(l.action)}</td>
        <td class="text-sm">${esc(l.hostname || '—')}</td>
        <td class="text-sm">${esc(l.cve_id || l.image || '—')}</td>
        <td><span class="${txtColor(stColor)}">${esc(l.status)}</span></td>
        <td>${l.status === 'pending' ? `<button data-action="approveLog" data-id="${l.id}" class="btn btn-surface-alt">✓</button><button data-action="skipLog" data-id="${l.id}" class="btn btn-ghost-red">✕</button>` : ''}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';
    html += paginator(d.total, d.page, d.per_page);
  }
  el.innerHTML = html;
}

export function showAddPolicyForm() { document.getElementById('policy-form').style.display = 'block'; }

export async function submitPolicy() {
  const sev = document.getElementById('pf-severity').value.trim();
  const env = document.getElementById('pf-env').value.trim();
  const expSel = document.getElementById('pf-exposure');
  const exp = expSel ? Array.from(expSel.selectedOptions).map(o => o.value) : [];
  const action = document.getElementById('pf-action').value;
  const payload = {
    name: document.getElementById('pf-name').value,
    trigger_type: document.getElementById('pf-trigger').value,
    action,
    priority: parseInt(document.getElementById('pf-priority').value) || 0,
    match_hostname: document.getElementById('pf-hostname').value || null,
    match_image: document.getElementById('pf-image').value || null,
    match_package: document.getElementById('pf-package').value || null,
    match_severity: sev ? sev.split(',').map(s=>s.trim()) : null,
    match_environment: env ? env.split(',').map(s=>s.trim()) : null,
    match_exposure: exp.length ? exp : null,
  };
  if (action === 'email') {
    const to = (document.getElementById('pf-email-to').value || '').trim();
    const subject = (document.getElementById('pf-email-subject').value || '').trim();
    const config = {};
    if (to) config.to = to.split(',').map(s => s.trim()).filter(Boolean);
    if (subject) config.subject = subject;
    if (Object.keys(config).length) payload.config = config;
  }
  await fetch(API + '/automation/policies', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload),
  });
  window.refreshView();
}

export async function togglePolicy(id, enabled) {
  await fetch(`${API}/automation/policies/${id}`, {
    method: 'PUT', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({enabled}),
  });
}

export async function deletePolicy(id) {
  await fetch(`${API}/automation/policies/${id}`, {method: 'DELETE'});
  window.refreshView();
}

export async function approveLog(id) {
  await fetch(`${API}/automation/log/${id}/approve`, {method: 'POST'});
  window.refreshView();
}

export async function skipLog(id) {
  await fetch(`${API}/automation/log/${id}/skip`, {method: 'POST'});
  window.refreshView();
}

// How it works (overview / reference)

function _renderOverview() {
  const stage = (title, sub) => `
    <div class="flow-stage">
      <div class="flow-stage-title">${title}</div>
      <div class="text-md text-default">${sub}</div>
    </div>`;
  const arrow = `<div class="flow-arrow">→</div>`;

  const triggers = [
    ['cve_detected', 'POST /cves/report', 'Trivy / Wazuh scan result'],
    ['update_available', 'POST /nodes/report', 'Package update available'],
    ['image_update_available', 'POST /repositories/{id}/check', 'New image tag detected'],
    ['misconf_detected', 'POST /misconfigurations/report', 'Trivy misconf critical/high'],
    ['backup_overdue', 'POST /backup/report', 'Restic status error/warning/failed'],
    ['pipeline_failure', 'POST /cicd/pipelines/report', 'Woodpecker / GitLab CI failure'],
    ['worker_offline', 'POST /cicd/workers/report', 'Runner marked offline'],
    ['deploy_requested', 'POST /deployments/{id}/submit', 'Deployment moves draft→pending'],
    ['exposure_change', 'POST /nodes/report', 'Container exposure class changed'],
    ['scan_stale', 'GET /scan/status', 'Node not scanned in 7+ days'],
  ];

  const filters = [
    ['match_hostname', 'LIKE, % wildcard', '<code>altair</code>, <code>%backup%</code>'],
    ['match_container', 'LIKE', '<code>traefik</code>, <code>%postgres%</code>'],
    ['match_image', 'LIKE', '<code>nginx:%</code>, <code>%/cmdb-%</code>'],
    ['match_package', 'LIKE', '<code>openssl</code>, <code>linux-headers%</code>'],
    ['match_cve_id', 'LIKE', '<code>CVE-2024-%</code>'],
    ['match_severity', 'IN list', '<code>["critical","high"]</code>'],
    ['match_environment', 'IN list', '<code>["production"]</code>'],
    ['match_exposure', 'IN list', '<code>["internet","private_network"]</code>'],
  ];

  const actions = [
    ['notify', 'auto', 'Matrix + email + webhooks, room routed per trigger'],
    ['email', 'auto', 'Dedicated SMTP channel with <code>{severity} {cve_id} {hostname}</code> templating + fallback to <code>alert_email</code>'],
    ['create_incident', 'auto', 'Scored P1–P4 via SSVC ruleset, dedup on (cve, asset, package), feeds ITSM'],
    ['create_deployment', 'auto', 'Insert deployment in status=<code>pending</code> (human approves)'],
    ['pull_image', 'auto', 'Portainer pull on first connected manager'],
    ['manual_validation', 'manual', 'Log pending, human clicks approve/skip'],
    ['ignore', '—', 'Log as <code>ignored</code>, no side-effect (useful as noise filter)'],
  ];

  const routing = [
    ['cve_detected, update_available, image_update_available', 'matrix_room_cve'],
    ['pipeline_failure, worker_offline, deploy_requested, scheduler_failure', 'matrix_room_cicd'],
    ['backup_overdue', 'matrix_room_backup'],
    ['misconf_detected, node_offline, exposure_change, scan_stale, incident_created', 'matrix_room_security'],
  ];

  const rule = (rows) => `<table class="ref-table">
    <thead><tr>${rows[0].map(h => `<th>${h}</th>`).join('')}</tr></thead>
    <tbody>${rows.slice(1).map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody>
  </table>`;

  const section = (title, body) => `
    <div class="section-label">${title}</div>
    ${body}`;

  return `
    <div class="overview-wrap">
      <div class="overview-intro">
        Constellation's automation engine matches events from every ingestion endpoint
        against ordered policies (first-match-wins, <code>priority DESC</code>) and runs
        one action — notify, email, create incident, deploy, pull image, or ignore.
      </div>

      <div class="flow-row">
        ${stage('1. Event', 'Ingestion endpoint fires a trigger')}
        ${arrow}
        ${stage('2. Match', 'First policy whose filters all pass')}
        ${arrow}
        ${stage('3. Action', 'Execute if <code>auto_execute=true</code>')}
        ${arrow}
        ${stage('4. Deliver', 'Matrix room + email + webhooks routed per trigger')}
      </div>

      ${section('Triggers (10 wired events)',
        rule([['Trigger', 'Source', 'Emitted when'], ...triggers.map(r => [`<code>${r[0]}</code>`, `<code>${r[1]}</code>`, r[2]])]))}

      ${section('Filters (AND between filters, IN inside lists)',
        rule([['Field', 'Match', 'Example'], ...filters.map(r => [`<code>${r[0]}</code>`, r[1], r[2]])])
        + `<div class="text-dim text-sm mt-6">An empty filter matches every event — leave the ones you do not need blank.</div>`)}

      ${section('Actions',
        rule([['Action', 'Runs', 'Behavior'], ...actions.map(r => [`<code>${r[0]}</code>`, r[1], r[2]])]))}

      ${section('Matrix room routing (per trigger)',
        rule([['Triggers', 'Room setting'], ...routing.map(r => [`<code>${r[0]}</code>`, `<code>${r[1]}</code>`])])
        + `<div class="text-dim text-sm mt-6">Override per policy via <code>notify_room</code>. Webhooks are filtered by their <code>route_cve / route_cicd / route_backup / route_security</code> flags.</div>`)}

      ${section('Safety rails',
        `<ul class="safety-list">
          <li><b>Vault sealed</b> — auto-execution is blocked for every action that needs secrets. <code>notify</code>, <code>email</code> and <code>create_incident</code> keep running so operators still get alerted.</li>
          <li><b>auto_execute=false</b> — the engine still logs the match, but the action waits for manual approve in <code>Rules → Log</code>.</li>
          <li><b>First match wins</b> — use <code>priority</code> to put <code>ignore</code> rules above notify rules when you want a deny list.</li>
        </ul>`)}

      ${section('Example recipes',
        `<pre class="recipe-pre">// Email on-call for every critical CVE in production
{ "name":"cve-critical-prod", "trigger_type":"cve_detected", "action":"email",
  "match_severity":["critical"], "match_environment":["production"],
  "config":{"to":["oncall@example.org"],
            "subject":"[{severity}] {cve_id} on {hostname}"},
  "auto_execute":true, "priority":100 }

// Open an ITIL incident for every KEV-flagged vuln (SSVC scoring picks priority)
{ "name":"kev-to-incident", "trigger_type":"cve_detected", "action":"create_incident",
  "auto_execute":true, "priority":120 }

// Silence medium-severity noise in lab
{ "name":"ignore-medium-lab", "trigger_type":"cve_detected", "action":"ignore",
  "match_severity":["medium"], "match_environment":["lab"], "priority":200 }</pre>`)}
    </div>`;
}

// Priority Rules (SSVC)

async function _renderPriorityRules() {
  const d = await api('/priority-rules');
  const sets = d.items || [];
  const active = sets.find(s => s.is_active);
  const draft = active ? JSON.stringify(active.rules, null, 2) : '[]';

  let html = `<div class="priority-cols">
    <div class="priority-col-left">
      <h3 class="mb-10">Rule sets</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>Rules</th><th>Active</th><th></th></tr></thead><tbody>`;
  if (!sets.length) html += `<tr><td colspan="4" class="empty">No rule sets</td></tr>`;
  for (const s of sets) {
    html += `<tr>
      <td>${esc(s.name)}</td>
      <td class="text-sm text-dim">${(s.rules || []).length} rule(s)</td>
      <td>${s.is_active ? '<span class="text-green text-bold">ACTIVE</span>' : '—'}</td>
      <td>${s.is_active ? '' : `<button data-action="activatePriorityRules" data-id="${s.id}" class="btn btn-surface-alt">Activate</button>`}</td>
    </tr>`;
  }
  html += `</tbody></table></div>
    </div>
    <div class="priority-col-right">
      <h3 class="mb-10">New rule set</h3>
      <div class="flex flex-col gap-8">
        <input id="pr-name" placeholder="Name (e.g. CISA SSVC v2)" class="f-input">
        <input id="pr-desc" placeholder="Description (optional)" class="f-input">
        <textarea id="pr-rules" rows="16" class="f-input text-mono text-sm" placeholder='[{"priority":"P1","name":"kev-prod","any":[{"in_kev":true}],"environment":["production"]}]'>${esc(draft)}</textarea>
        <div class="text-xs text-dim">Fields per rule: <code>priority</code> (P1|P2|P3|P4), <code>name</code>, <code>in_kev</code>, <code>cvss_min</code>, <code>severity[]</code>, <code>environment[]</code>, <code>exposure[]</code>, <code>any:[]</code> (OR group). First match wins.</div>
        <div><button data-action="submitPriorityRules" class="btn btn-success-primary">Save + Activate</button></div>
      </div>
    </div>
  </div>`;
  return html;
}

export async function submitPriorityRules() {
  const name = document.getElementById('pr-name').value.trim();
  const description = document.getElementById('pr-desc').value.trim() || null;
  const raw = document.getElementById('pr-rules').value;
  if (!name) return alert('Name required');
  let rules;
  try { rules = JSON.parse(raw); }
  catch (e) { return alert('Invalid JSON: ' + e.message); }
  const r = await fetch(API + '/priority-rules', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name, description, rules}),
  });
  if (!r.ok) {
    const d = await r.json().catch(() => ({}));
    return alert('Error: ' + (d.detail || r.status));
  }
  const created = await r.json();
  await fetch(`${API}/priority-rules/${created.id}/activate`, {method: 'POST'});
  window.refreshView();
}

export async function activatePriorityRules(id) {
  const r = await fetch(`${API}/priority-rules/${id}/activate`, {method: 'POST'});
  if (!r.ok) return alert('Activate failed: ' + r.status);
  window.refreshView();
}

export function automationSearch(v) {
  _searchQ = v || '';
  window.refreshView();
}
