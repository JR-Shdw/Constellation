// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, esc, typeBadges } from '../api.js';

export async function showOsNodes(os) {
  const panel = document.getElementById('detail');
  const content = document.getElementById('detail-content');
  panel.classList.add('side-panel', 'open');
  content.innerHTML = '<div class="loading">Loading...</div>';
  try {
    const d = await api(`/nodes?os=${encodeURIComponent(os)}&per_page=200`);
    let html = `<h2>OS: ${esc(os)}</h2>`;
    html += `<div class="detail-section"><h3>${d.items.length} node(s)</h3>
      <div class="table-wrap"><table><tr><th>Hostname</th><th>Type</th><th>Version</th><th>Kernel</th></tr>`;
    for (const n of d.items) {
      html += `<tr>
        <td class="clickable" data-action="showNode" data-id="${n.id}">${esc(n.hostname)}</td>
        <td>${typeBadges(n.type)}</td>
        <td>${esc(n.os_version || '')}</td>
        <td>${esc(n.kernel || '')}</td></tr>`;
    }
    html += '</table></div></div>';
    content.innerHTML = html;
  } catch(e) { content.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`; }
}
