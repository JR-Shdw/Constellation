// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, API, esc, exposureTags, timeAgo, txtColor } from '../api.js';

export async function deleteGhostImage(imageId, fullName) {
  if (!confirm(
    `Delete ${fullName} and mark all its CVEs as resolved?\n\n` +
    `Use this when the image + its containers have been removed ` +
    `from the host but CVEs still linger (scanner only reports on ` +
    `running images).`
  )) return;
  const r = await fetch(`${API}/container-images/${imageId}`, { method: 'DELETE' });
  if (!r.ok) {
    const d = await r.json().catch(() => ({}));
    alert(`Failed: ${d.detail || r.statusText}`);
    return;
  }
  const data = await r.json();
  alert(
    `Removed ${data.image}\n` +
    `• ${data.cves_resolved} CVE(s) resolved\n` +
    `• ${data.secrets_resolved} secret(s) resolved`
  );
  // Re-render the panel on the same image name to reflect the change.
  const name = fullName.split(':')[0];
  await showImageHosts(name);
}

export async function showImageHosts(image) {
  const panel = document.getElementById('detail');
  const content = document.getElementById('detail-content');
  panel.classList.add('side-panel', 'open');
  content.innerHTML = '<div class="loading">Loading...</div>';
  try {
    const d = await api(`/containers/hosts?image=${encodeURIComponent(image)}`);
    let html = `<h2>Image: ${esc(image)}</h2>`;

    // Image variants (tags). Ghost rows = no running container; expose
    // the manual cleanup so ops can drop them without waiting 7 days.
    if (d.images && d.images.length) {
      html += `<div class="detail-section"><h3>Variants (${d.images.length})</h3>
        <div class="table-wrap"><table><tr><th>Tag</th><th>Containers</th><th>Last scan</th><th></th></tr>`;
      for (const v of d.images) {
        const isGhost = v.container_count === 0;
        const action = isGhost
          ? `<button class="btn-sm btn-danger" data-action="deleteGhostImage"
                     data-id="${v.id}" data-value="${esc(image)}:${esc(v.tag)}">Delete + resolve CVEs</button>`
          : '<span class="text-dim text-sm">in use</span>';
        html += `<tr>
          <td class="text-mono text-sm">${esc(v.tag)}</td>
          <td class="${isGhost ? 'text-orange' : ''}">${v.container_count}</td>
          <td class="text-xs text-dim">${v.last_updated ? timeAgo(v.last_updated) : '—'}</td>
          <td>${action}</td></tr>`;
      }
      html += '</table></div></div>';
    }

    // Hosts table
    html += `<div class="detail-section"><h3>Running on ${d.items.length} node(s)</h3>
      <div class="table-wrap"><table><tr><th>Node</th><th>Container</th><th>Tag</th><th>Exposure</th><th>Networks</th><th>Ports</th><th>Status</th></tr>`;
    for (const r of d.items) {
      const nets = (r.networks || []).join(', ') || '—';
      const ports = (r.port_bindings || []).map(p =>
        `${p.host_ip || '0.0.0.0'}:${p.host_port}→${p.container_port}`
      ).join(', ') || '—';
      html += `<tr>
        <td class="clickable" data-action="showNode" data-id="${r.node_id}">${esc(r.hostname)}</td>
        <td>${esc(r.name)}</td>
        <td>${esc(r.tag || 'latest')}</td>
        <td>${exposureTags(r)}</td>
        <td class="text-sm text-dim">${esc(nets)}</td>
        <td class="text-sm">${esc(ports)}</td>
        <td>${esc(r.status || '')}</td></tr>`;
    }
    html += '</table></div></div>';

    // Repositories
    if (d.repos && d.repos.length) {
      html += `<div class="detail-section"><h3>Repositories (${d.repos.length})</h3>
        <div class="table-wrap"><table><tr><th>Project</th><th>Tag</th><th>Latest</th><th>Update</th><th>Exposure</th><th>Checked</th></tr>`;
      for (const r of d.repos) {
        const updBadge = r.update_available
          ? `<span class="text-orange text-bold">↑ ${esc(r.latest_tag_available)}</span>`
          : (r.latest_tag_available ? '<span class="text-green">✓</span>' : '—');
        const listenColor = r.listen === 'internet' ? 'red' : r.listen === 'private_network' ? 'orange' : 'text-dim';
        html += `<tr>
          <td>${esc(r.project_name)}</td>
          <td class="text-mono text-sm">${esc(r.current_tag || '—')}</td>
          <td class="text-mono text-sm">${esc(r.latest_tag_available || '—')}</td>
          <td>${updBadge}</td>
          <td class="${txtColor(listenColor)}">${esc(r.listen || '—')}</td>
          <td class="text-xs text-dim">${r.last_checked ? timeAgo(r.last_checked) : '—'}</td>
        </tr>`;
      }
      html += '</table></div></div>';
    }

    // CVEs
    if (d.cves && d.cves.length) {
      html += `<div class="detail-section"><h3>CVEs (${d.cves.length}${d.cves.length >= 50 ? '+' : ''})</h3>
        <div class="table-wrap"><table><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Node</th></tr>`;
      for (const c of d.cves) {
        const kevTag = c.exploited ? ' <span class="text-red text-xxs text-bolder">KEV</span>' : '';
        html += `<tr>
          <td class="clickable" data-action="showCVEDetail" data-id="${esc(c.cve_id)}">${esc(c.cve_id)}${kevTag}</td>
          <td><span class="badge ${c.severity}">${esc(c.severity)}</span></td>
          <td>${c.cvss_score != null ? c.cvss_score : '—'}</td>
          <td class="text-sm">${esc(c.pkg_name)}</td>
          <td class="text-mono text-xs">${esc(c.installed_ver || '—')}</td>
          <td class="text-mono text-xs text-green">${esc(c.fixed_ver || '—')}</td>
          <td class="clickable text-sm" data-action="showNode" data-id="${c.node_id}">${esc(c.hostname)}</td>
        </tr>`;
      }
      html += '</table></div></div>';
    } else {
      html += '<div class="detail-section"><h3>CVEs</h3><div class="empty">No CVEs found for this image</div></div>';
    }

    content.innerHTML = html;
  } catch(e) { content.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`; }
}
