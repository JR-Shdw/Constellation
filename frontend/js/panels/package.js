// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, esc, txtColor } from '../api.js';

export async function showPackageHosts(name) {
  const panel = document.getElementById('detail');
  const content = document.getElementById('detail-content');
  panel.classList.add('side-panel', 'open');
  content.innerHTML = '<div class="loading">Loading...</div>';
  try {
    const d = await api(`/packages/hosts?name=${encodeURIComponent(name)}`);
    const items = d.items || [];
    const totalCves = items.reduce((s, r) => s + (r.cve_count || 0), 0);
    const hasUpgrade = items.some(r => r.available_ver && r.available_ver !== r.version);
    const hasKev = items.some(r => r.exploited);

    let html = `<h2>Package: ${esc(name)}</h2>`;

    // Summary badges
    html += '<div class="flex gap-8 mb-12 flex-wrap">';
    if (totalCves > 0) {
      const worst = items.reduce((w, r) => {
        const order = {critical:0,high:1,medium:2,low:3,unknown:4};
        return (order[r.max_severity] ?? 4) < (order[w] ?? 4) ? r.max_severity : w;
      }, 'unknown');
      const sevColor = {critical:'red',high:'orange',medium:'yellow',low:'green'}[worst] || 'text-dim';
      html += `<span class="badge ${txtColor(sevColor)} text-bold">${totalCves} CVE${totalCves > 1 ? 's' : ''}</span>`;
    } else {
      html += '<span class="badge text-green">No CVEs</span>';
    }
    if (hasUpgrade) html += '<span class="badge text-orange text-bold">UPD available</span>';
    if (hasKev) html += '<span class="badge text-red text-bolder">KEV</span>';
    html += '</div>';

    html += `<div class="detail-section"><h3>Installed on ${items.length} host(s)</h3>
      <div class="table-wrap"><table>
      <tr><th>Hostname</th><th>OS</th><th>Arch</th><th>Version</th><th>Upgrade</th><th>Mgr</th><th>CVEs</th><th>Fix</th><th>KEV</th></tr>`;
    for (const r of items) {
      const upgBadge = r.available_ver && r.available_ver !== r.version
        ? `<span class="text-orange text-bold">${esc(r.available_ver)}</span>`
        : '<span class="text-dim">\u2014</span>';
      const cveColor = (r.cve_count || 0) > 0 ? {critical:'red',high:'orange',medium:'yellow'}[r.max_severity] || 'text-dim' : 'text-dim';
      const fixBadge = r.has_fix
        ? '<span class="text-green text-bold">yes</span>'
        : (r.cve_count > 0 ? '<span class="text-dim">no</span>' : '\u2014');
      const kevBadge = r.exploited
        ? '<span class="text-red text-bolder">KEV</span>' : '';
      const osLabel = [r.os, r.os_version].filter(Boolean).join(' ');
      html += `<tr>
        <td class="clickable" data-action="showNode" data-id="${r.node_id}">${esc(r.hostname)}</td>
        <td class="text-sm">${esc(osLabel)}</td>
        <td class="text-sm">${esc(r.arch || r.node_arch || '')}</td>
        <td class="text-mono text-sm">${esc(r.version)}</td>
        <td>${upgBadge}</td>
        <td class="text-xs text-dim">${esc(r.manager || '')}</td>
        <td class="${txtColor(cveColor)} ${(r.cve_count||0) > 0 ? 'text-bold' : 'text-normal'}">${r.cve_count || 0}${r.max_severity && r.cve_count > 0 ? ' <span class="text-xs">(' + r.max_severity + ')</span>' : ''}</td>
        <td>${fixBadge}</td>
        <td>${kevBadge}</td>
      </tr>`;
    }
    html += '</table></div></div>';

    // CVE list if any
    const allCves = items.flatMap(r => (r.cve_ids || []).map(c => ({
      cve_id: c, hostname: r.hostname, max_severity: r.max_severity,
      max_cvss: r.max_cvss, has_fix: r.has_fix, exploited: r.exploited,
    })));
    // Deduplicate by cve_id
    const seen = new Set();
    const uniqueCves = allCves.filter(c => { if (seen.has(c.cve_id)) return false; seen.add(c.cve_id); return true; });
    if (uniqueCves.length) {
      html += `<div class="detail-section mt-16"><h3>CVEs (${uniqueCves.length})</h3>
        <div class="table-wrap"><table><tr><th>CVE</th><th>Severity</th><th>Fix</th><th>KEV</th></tr>`;
      for (const c of uniqueCves.slice(0, 30)) {
        const sevColor = {critical:'red',high:'orange',medium:'yellow',low:'green'}[c.max_severity] || 'text-dim';
        html += `<tr>
          <td class="clickable" data-action="showCVEDetail" data-id="${esc(c.cve_id)}">${esc(c.cve_id)}</td>
          <td><span class="badge ${txtColor(sevColor)}">${c.max_severity || 'unknown'}</span></td>
          <td>${c.has_fix ? '<span class="text-green">yes</span>' : '<span class="text-dim">no</span>'}</td>
          <td>${c.exploited ? '<span class="text-red text-bolder">KEV</span>' : ''}</td>
        </tr>`;
      }
      if (uniqueCves.length > 30) html += `<tr><td colspan="4" class="text-dim text-sm">+${uniqueCves.length - 30} more</td></tr>`;
      html += '</table></div></div>';
    }

    content.innerHTML = html;
  } catch(e) { content.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`; }
}
