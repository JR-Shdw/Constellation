// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, esc, paginator, timeAgo } from '../api.js';

if (window.opencveMatchedOnly === undefined) window.opencveMatchedOnly = true;

export async function renderOpenCVE(el) {
  const fs = getFilterSeverity();
  let url = `/opencve/alerts?page=${currentPage}&per_page=50&matched_only=${opencveMatchedOnly}`;
  if (fs) url += `&severity=${fs}`;
  const d = await api(url);

  let html = `<div class="mb-12 flex items-center gap-lg">
    <label class="flex items-center gap-sm cursor-pointer text-md text-dim">
      <input type="checkbox" ${opencveMatchedOnly ? 'checked' : ''}
        data-change="opencveMatchedOnly"
        class="f-accent-color">
      Infra only
    </label>
    <span class="text-sm text-dim">${d.matched_only ? 'Showing CVEs detected on your infrastructure' : 'Showing all OpenCVE alerts'}</span>
  </div>`;

  html += `<div class="table-wrap"><table>
    <tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Vendor</th><th>Product</th><th>Title</th>${opencveMatchedOnly ? '<th>Nodes</th>' : ''}<th>Impact</th><th>Date</th></tr>`;
  if (!d.items.length) html += `<tr><td colspan="${opencveMatchedOnly ? 9 : 8}" class="empty">${opencveMatchedOnly ? 'No OpenCVE alerts match your infrastructure' : 'No OpenCVE alerts'}</td></tr>`;
  for (const a of d.items) {
    html += `<tr>
      <td class="clickable" data-action="showCVEDetail" data-id="${a.cve_id}">${esc(a.cve_id)}</td>
      <td><span class="badge ${a.severity}">${esc(a.severity)}</span></td>
      <td>${a.cvss_v3 || '-'}</td>
      <td>${esc(a.vendor || '')}</td>
      <td>${esc(a.product || '')}</td>
      <td class="truncate-w-300">${esc(a.title || '')}</td>
      ${opencveMatchedOnly ? `<td class="text-accent">${a.affected_nodes || 0}</td>` : ''}
      <td><button data-action="showImpact" data-id="${a.cve_id}" class="chip-accent-btn">Impact</button></td>
      <td>${timeAgo(a.created_at)}</td>
    </tr>`;
  }
  html += '</table></div>';
  html += paginator(d.total, d.page, d.per_page);
  el.innerHTML = html;
}
