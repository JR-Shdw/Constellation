// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, esc } from '../api.js';

export async function showImpact(cveId) {
  const panel = document.getElementById('detail');
  const content = document.getElementById('detail-content');
  panel.classList.add('side-panel', 'open');
  content.innerHTML = '<div class="loading">Loading impact...</div>';
  try {
    const d = await api(`/opencve/impact?cve_id=${encodeURIComponent(cveId)}`);
    let html = `<h2>${esc(cveId)} — Impact</h2>`;
    if (!d.items.length) {
      html += '<div class="empty">No assets impacted in your infrastructure</div>';
    } else {
      html += `<div class="table-wrap"><table>
        <tr><th>Hostname</th><th>Package</th><th>Version</th><th>Type</th></tr>`;
      for (const i of d.items) {
        html += `<tr>
          <td>${esc(i.hostname)}</td>
          <td>${esc(i.target)}</td>
          <td>${esc(i.installed_ver || '')}</td>
          <td>${esc(i.target_type)}</td>
        </tr>`;
      }
      html += '</table></div>';
    }
    content.innerHTML = html;
  } catch(e) {
    content.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}
