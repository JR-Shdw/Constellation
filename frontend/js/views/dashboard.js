// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, esc, tabBar } from '../api.js';
import { PixelArray } from '../lib/pixelarray.js';

export async function renderDashboard(el) {
  const tab = window.dashboardTab || 'summary';
  const [s, comp, incStats] = await Promise.all([
    api('/stats'),
    api('/compliance'),
    api('/incidents/stats').catch(() => null),
  ]);
  const cveOn = s.feature_cve_enabled !== false;
  const bkOn = s.feature_backup_enabled !== false;

  const tabs = tabBar(
    [['summary', 'Summary'], ['health', 'Health Map']],
    tab, 'dashboard'
  );

  if (tab === 'health') {
    let hmHtml = tabs;
    const nodes = (comp && comp.items) || [];
    if (!nodes.length) {
      el.innerHTML = hmHtml + '<div class="empty">No node compliance data yet</div>';
      return;
    }
    hmHtml += '<div class="heatmap-grid">';
    const isSmall = window.innerWidth < 768;
    const cw = isSmall ? 48 : 100;
    const ch = isSmall ? 28 : 48;
    const maxChars = isSmall ? 6 : 10;
    for (const n of nodes) {
      const cid = 'hm' + (n.node_id || '').slice(0, 8);
      const short = (n.hostname || '').split('.')[0];
      const label = esc(short.length > maxChars ? short.slice(0, maxChars - 1) + '…' : short);
      hmHtml += `<div class="heatmap-cell" data-action="showNode" data-id="${n.node_id}" title="${esc(n.hostname)}\nCVE crit: ${n.cve_critical_open || 0}\nMisconf crit: ${n.misconf_critical || 0}">
        <canvas id="${cid}" width="${cw}" height="${ch}"></canvas>
        <div class="hm-label">${label}</div>
      </div>`;
    }
    hmHtml += '</div>';
    el.innerHTML = hmHtml;
    _drawHealthMap(nodes);
    return;
  }

  // Build exclusion label only for what's actually excluded
  const exParts = [];
  if (s.cve_count_exclude_low) exParts.push('low');
  if (s.cve_count_exclude_medium) exParts.push('med');
  const exLabel = exParts.length
    ? `<div class="text-xs text-orange mt-4">excl. ${exParts.join(' + ')}</div>`
    : '';

  el.innerHTML = tabs + `
    <div class="stats">
      <div class="stat-card">
        <div class="label">Nodes</div>
        <div class="value accent">${esc(s.nodes_active)} / ${esc(s.nodes_total)}</div>
      </div>
      <div class="stat-card">
        <div class="label">Packages</div>
        <div class="value">${esc(s.packages_total.toLocaleString())}</div>
      </div>
      <div class="stat-card">
        <div class="label">Containers</div>
        <div class="value accent">${esc(s.containers_total)}</div>
      </div>
      <div class="stat-card">
        <div class="label">CVEs Critical</div>
        ${cveOn ? `<div class="value red">${esc(s.cves_critical)}</div>
        <div class="text-xs text-dim mt-4">
          host&nbsp;<span class="text-red">${s.cves_host_critical}</span>
          &nbsp;·&nbsp;
          ctr&nbsp;<span class="text-red">${s.cves_container_critical}</span>
        </div>` : '<div class="value text-dim">—</div><div class="text-xs text-dim">module disabled</div>'}
      </div>
      ${cveOn ? `<div class="stat-card">
        <div class="label">CVEs High</div>
        <div class="value orange">${s.cves_high}</div>
        <div class="text-xs text-dim mt-4">
          host&nbsp;<span class="text-orange">${s.cves_host_high || 0}</span>
          &nbsp;·&nbsp;
          ctr&nbsp;<span class="text-orange">${s.cves_container_high || 0}</span>
        </div>
      </div>
      <div class="stat-card">
        <div class="label">CVEs Medium</div>
        <div class="value text-yellow">${s.cves_medium || 0}</div>
        <div class="text-xs text-dim mt-4">
          host&nbsp;<span class="text-yellow">${s.cves_host_medium || 0}</span>
          &nbsp;·&nbsp;
          ctr&nbsp;<span class="text-yellow">${s.cves_container_medium || 0}</span>
        </div>
        ${s.cve_count_exclude_medium ? '<div class="dash-excl-tag">excl. from total</div>' : ''}
      </div>
      <div class="stat-card">
        <div class="label">CVEs Host</div>
        <div class="value">${s.cves_host_total.toLocaleString()}</div>
        ${exLabel}
      </div>
      <div class="stat-card">
        <div class="label">CVEs Containers</div>
        <div class="value">${s.cves_container_total.toLocaleString()}</div>
        ${exLabel}
      </div>` : ''}
      ${bkOn ? `<div class="stat-card">
        <div class="label">Backups OK</div>
        <div class="value green">${s.backups_ok}</div>
      </div>
      <div class="stat-card">
        <div class="label">Backups Failed</div>
        <div class="value red">${s.backups_failed}</div>
      </div>
      <div class="stat-card">
        <div class="label">Backups Overdue</div>
        <div class="value orange">${s.backups_overdue}</div>
      </div>` : `<div class="stat-card">
        <div class="label">Backups</div>
        <div class="value text-dim">—</div>
        <div class="text-xs text-dim">module disabled</div>
      </div>`}
      <div class="stat-card">
        <div class="label">Trivy Scanned</div>
        <div class="value green">${s.trivy_host_scanned || 0}</div>
      </div>
      <div class="stat-card">
        <div class="label">Scans Stale</div>
        <div class="value ${(s.trivy_host_stale || 0) > 0 ? 'orange' : ''}">${s.trivy_host_stale || 0}</div>
      </div>
      <div class="stat-card">
        <div class="label">Images Tracked</div>
        <div class="value">${s.repos_total || 0}</div>
      </div>
      <div class="stat-card">
        <div class="label">Images Updates</div>
        <div class="value ${(s.repos_update_available || 0) > 0 ? 'orange' : ''}">${s.repos_update_available || 0}</div>
      </div>
      <div class="stat-card">
        <div class="label">Pending Actions</div>
        <div class="value ${(s.automation_pending || 0) > 0 ? 'orange' : ''}">${s.automation_pending || 0}</div>
      </div>
      ${incStats ? `<div class="stat-card clickable" data-action="_openIncidentsTab" title="Open incidents (click to view)">
        <div class="label">Open Incidents</div>
        <div class="value ${incStats.total_open > 0 ? 'orange' : ''}">${incStats.total_open || 0}</div>
        <div class="text-xs text-dim mt-4">
          P1&nbsp;<span class="text-red">${(incStats.by_priority || {}).P1 || 0}</span>
          &nbsp;·&nbsp;
          P2&nbsp;<span class="text-orange">${(incStats.by_priority || {}).P2 || 0}</span>
        </div>
      </div>` : ''}
      <div class="stat-card hidden" id="vault-card">
        <div class="label">Vault</div>
        <div class="value" id="vault-dash-value">—</div>
      </div>
    </div>
  `;

  // Vault status — single call, cached 5min by api() stale-while-revalidate
  try {
    const v = await api('/settings/vault/status');
    const card = document.getElementById('vault-card');
    const val = document.getElementById('vault-dash-value');
    if (card && val && v && v.configured) {
      card.style.display = '';
      if (v.sealed === false) {
        val.innerHTML = '<span class="text-green">unsealed</span>';
      } else if (v.sealed === true) {
        val.innerHTML = '<span class="text-orange">sealed</span>';
      } else {
        val.innerHTML = '<span class="text-red">unreach.</span>';
      }
    }
  } catch {}

}

function _drawHealthMap(nodes) {
  for (const n of nodes) {
    const cid = 'hm' + (n.node_id || '').slice(0, 8);
    const canvas = document.getElementById(cid);
    if (!canvas) continue;
    let r, g, b;
    if ((n.cve_critical_open || 0) > 0 || (n.misconf_critical || 0) > 0) { r = 224; g = 64; b = 80; }
    else if ((n.cve_open_total || 0) > 0 || (n.misconf_total || 0) > 0) { r = 232; g = 144; b = 64; }
    else { r = 64; g = 192; b = 96; }
    const w = canvas.width, h = canvas.height;
    const pa = new PixelArray(canvas, { pixelSize: 1 });
    pa.fill(r, g, b, 0.12);
    const dots = w >= 100 ? 24 : 10;
    for (let p = 0; p < dots; p++) {
      const dx = 1 + Math.floor(Math.random() * (w - 2));
      const dy = 1 + Math.floor(Math.random() * (h - 2));
      const v = Math.floor(Math.random() * 30) - 15;
      pa.dot(dx, dy,
        Math.max(0, Math.min(255, r + v)),
        Math.max(0, Math.min(255, g + v)),
        Math.max(0, Math.min(255, b + v)),
        0.3 + Math.random() * 0.5);
    }
  }
}
