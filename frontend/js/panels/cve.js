// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, txtColor } from '../api.js';

export async function showCVEDetail(cveId) {
  const panel = document.getElementById('detail');
  const content = document.getElementById('detail-content');
  panel.classList.remove('side-panel');
  panel.classList.add('open');
  content.innerHTML = '<div class="loading">Loading...</div>';
  try {
    const d = await api(`/cves/${encodeURIComponent(cveId)}`);
    const sevClass = d.severity || 'unknown';
    const kev = d.opencve && d.opencve.kev;
    const cid = encodeURIComponent(cveId);
    const cveLinks = [
      {label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${cid}`},
      {label: 'CVE.org', url: `https://www.cve.org/CVERecord?id=${cid}`},
      {label: 'MITRE', url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cid}`},
      {label: 'RHEL', url: `https://access.redhat.com/security/cve/${cid}`},
      {label: 'Debian', url: `https://security-tracker.debian.org/tracker/${cid}`},
    ];
    if (d.opencve_url) cveLinks.push({label: 'OpenCVE', url: `${esc(d.opencve_url)}/cve/${esc(cid)}`});
    const ocveTitle = d.opencve_url ? `<a href="${esc(d.opencve_url)}/cve/${esc(cid)}" target="_blank" rel="noopener" class="text-accent no-underline">${esc(cveId)}</a>` : `<span class="text-accent">${esc(cveId)}</span>`;
    let html = `<h2 class="flex items-center gap-md flex-wrap">
      <span class="badge ${sevClass}">${esc(d.severity || '?')}</span>
      ${kev ? '<span class="kev-pill">⚠ CISA KEV</span>' : ''}
      ${ocveTitle}
    </h2>
    <div class="cve-links">
      ${cveLinks.map(l => `<a href="${l.url}" target="_blank" rel="noopener"
        class="text-sm text-dim border pad-2-8 rounded-sm no-underline">${l.label} ↗</a>`).join('')}
    </div>`;

    // Meta bar: CVSS + CWEs + vendors
    const metaBar = [];
    const allSources = [...(d.sources || [])];
    if (d.opencve) allSources.push('opencve');
    if (allSources.length)
      metaBar.push(`Source: ${allSources.map(s => `<strong>${esc(s)}</strong>`).join(', ')}`);
    if (d.cvss_score) metaBar.push(`CVSS&nbsp;<strong>${d.cvss_score}</strong>`);
    if (d.opencve) {
      if (d.opencve.cwe_ids && d.opencve.cwe_ids.length)
        metaBar.push(d.opencve.cwe_ids.map(c => `<span class="text-purple">${esc(c)}</span>`).join(' '));
      if (d.opencve.vendors && d.opencve.vendors.length)
        metaBar.push(`Vendors: ${d.opencve.vendors.slice(0,5).map(v => esc(v)).join(', ')}${d.opencve.vendors.length > 5 ? '…' : ''}`);
    }
    if (metaBar.length)
      html += `<div class="cve-meta">${metaBar.join('&ensp;·&ensp;')}</div>`;

    if (kev) {
      html += `<div class="kev-banner">
        This vulnerability is in the <strong>CISA Known Exploited Vulnerabilities</strong> catalog — active exploitation confirmed in the wild.
      </div>`;
    }

    if (d.description) {
      html += `<div class="detail-section"><p class="cve-desc">${esc(d.description)}</p></div>`;
    }

    if (d.hosts.length) {
      html += `<div class="detail-section"><h3>Affected nodes — packages (${d.hosts.length})</h3>
        <div class="table-wrap"><table>
          <tr><th>Node</th><th>OS</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Fix status</th><th>Score</th><th>Workflow</th></tr>`;
      for (const h of d.hosts) {
        const kBadge = h.exploited ? '<span class="text-9-red-bold" title="CISA KEV">⚠KEV</span> ' : '';
        const scoreColor = h.score >= 70 ? 'red' : h.score >= 40 ? 'orange' : 'text-dim';
        const fixC = h.fix_status === 'fixed_available' ? 'green' : h.fix_status === 'not_affected' ? 'accent' : h.fix_status === 'under_investigation' ? 'orange' : 'text-dim';
        html += `<tr>
          <td class="clickable" data-action="showNode" data-id="${h.node_id}">${kBadge}${esc(h.hostname)}</td>
          <td class="text-sm">${esc(h.os || '')}</td>
          <td>${esc(h.pkg_name)}</td>
          <td class="text-sm">${esc(h.installed_ver || '')}</td>
          <td class="text-sm text-green">${esc(h.fixed_ver || '—')}</td>
          <td class="text-xs ${txtColor(fixC)}">${esc((h.fix_status||'unfixed').replace(/_/g,' '))}</td>
          <td><span class="${txtColor(scoreColor)} text-bold text-md">${h.score}</span></td>
          <td>${_workflowSelect(cveId, h.node_id, h.workflow_status || h.status, h.justification)}</td>
        </tr>`;
      }
      html += '</table></div></div>';
    }

    if (d.containers.length) {
      html += `<div class="detail-section"><h3>Affected containers (${d.containers.length})</h3>
        <div class="table-wrap"><table>
          <tr><th>Node</th><th>Container</th><th>Image</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Fix status</th><th>Exposure</th><th>Score</th><th>Status</th></tr>`;
      for (const c of d.containers) {
        const kBadge = c.exploited ? '<span class="text-9-red-bold" title="CISA KEV">⚠KEV</span> ' : '';
        const scoreColor = c.score >= 70 ? 'red' : c.score >= 40 ? 'orange' : 'text-dim';
        const listenColor = c.listen === 'internet' ? 'red' : c.listen === 'private_network' ? 'orange' : 'text-dim';
        const fixC = c.fix_status === 'fixed_available' ? 'green' : c.fix_status === 'not_affected' ? 'accent' : c.fix_status === 'under_investigation' ? 'orange' : 'text-dim';
        const imgBase = (c.image || '').split(':')[0];
        const imgTag = c.container_tag || (c.image || '').split(':')[1] || 'latest';
        const ctrName = c.container_name || '—';
        html += `<tr>
          <td class="clickable" data-action="showNode" data-id="${c.node_id}">${kBadge}${esc(c.hostname)}</td>
          <td class="text-sm">${esc(ctrName)}</td>
          <td class="clickable text-mono text-xs" data-action="showImageHosts" data-id="${esc(imgBase)}">${esc(imgBase)}<span class="text-dim">:${esc(imgTag)}</span></td>
          <td>${esc(c.pkg_name)}${c.pkg_type ? `<span class="pill-type" title="Trivy PkgType">${esc(c.pkg_type)}</span>` : ''}</td>
          <td class="text-sm">${esc(c.installed_ver || '')}</td>
          <td class="text-sm text-green">${esc(c.fixed_ver || '—')}</td>
          <td class="text-xs ${txtColor(fixC)}">${esc((c.fix_status||'unfixed').replace(/_/g,' '))}</td>
          <td class="text-xs ${txtColor(listenColor)}">${esc(c.listen || 'docker_internal')}</td>
          <td><span class="${txtColor(scoreColor)} text-bold text-md">${c.score}</span></td>
          <td>${_statusSelect('container', c.finding_id, c.status)}</td>
        </tr>`;
      }
      html += '</table></div></div>';
    }

    // Toutes les CVEs par image (cross-référence container complet)
    if (d.image_cves && Object.keys(d.image_cves).length) {
      for (const [img, cves] of Object.entries(d.image_cves)) {
        const critCount = cves.filter(c => c.severity === 'critical').length;
        const highCount = cves.filter(c => c.severity === 'high').length;
        html += `<div class="detail-section">
          <h3 class="clickable text-mono text-md" data-action="showImageHosts" data-id="${esc(img.split(':')[0])}">${esc(img)}
            <span class="font-inherit text-sm text-normal text-dim ml-8">
              ${cves.length} CVEs
              ${critCount ? `— <span class="text-red">${critCount} critical</span>` : ''}
              ${highCount ? `— <span class="text-orange">${highCount} high</span>` : ''}
            </span>
          </h3>
          <div class="table-wrap scroll-300"><table>
            <tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Package</th><th>Installed</th><th>Fixed</th></tr>`;
        for (const cv of cves) {
          html += `<tr>
            <td class="clickable" data-action="showCVEDetail" data-id="${cv.cve_id}">${esc(cv.cve_id)}</td>
            <td><span class="badge ${cv.severity}">${esc(cv.severity)}</span></td>
            <td>${cv.cvss_score || '—'}</td>
            <td>${esc(cv.pkg_name)}${cv.pkg_type ? `<span class="pill-type" title="Trivy PkgType">${esc(cv.pkg_type)}</span>` : ''}</td>
            <td>${esc(cv.installed_ver || '')}</td>
            <td>${esc(cv.fixed_ver || '—')}</td>
          </tr>`;
        }
        html += '</table></div></div>';
      }
    }

    if (!d.hosts.length && !d.containers.length) {
      html += `<div class="empty">No affected assets found</div>`;
    }

    content.innerHTML = html;
  } catch(e) {
    content.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}

export function _statusSelect(type, findingId, current) {
  if (!findingId) return current || 'open';
  const opts = ['open','mitigated','ignored','resolved'];
  const colors = {open:'text-dim', mitigated:'orange', ignored:'text-dim', resolved:'green'};
  const c = current || 'open';
  return `<select data-change="patchFinding" data-type="${type}" data-id="${findingId}" data-field="status"
    class="form-select-inline-sm ${txtColor(colors[c]||'text-dim')}">
    ${opts.map(o=>`<option value="${o}" ${o===c?'selected':''}>${o}</option>`).join('')}
  </select>`;
}

export async function patchFinding(type, findingId, field, value) {
  await fetch(`${API}/findings/${type}/${findingId}`, {
    method: 'PATCH',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({[field]: value}),
  });
}

export function _workflowSelect(cveId, nodeId, current, justification) {
  const opts = ['open','acknowledged','in_progress','mitigated','resolved','false_positive','accepted_risk'];
  const colors = {open:'text-dim',acknowledged:'accent',in_progress:'orange',mitigated:'green',resolved:'green',false_positive:'purple',accepted_risk:'yellow'};
  const c = current || 'open';
  const uid = `wf_${nodeId.slice(0,8)}`;
  const needsJustif = c === 'accepted_risk' || c === 'false_positive';
  let html = `<select id="${uid}_sel" data-change="setCveWorkflow" data-cve="${cveId}" data-node="${nodeId}" data-justif="${uid}_j"
    class="form-select-inline ${txtColor(colors[c]||'text-dim')}">
    ${opts.map(o=>`<option value="${o}" ${o===c?'selected':''}>${o.replace(/_/g,' ')}</option>`).join('')}
  </select>`;
  html += `<textarea id="${uid}_j" placeholder="Justification..." rows="2"
    class="wf-justif${needsJustif ? '' : ' hidden'}"
    data-blur="setCveWorkflow" data-cve="${cveId}" data-node="${nodeId}" data-sel="${uid}_sel">${esc(justification || '')}</textarea>`;
  if (justification && !needsJustif) {
    html += `<div class="wf-justif-preview" title="${esc(justification)}">&#9432; ${esc(justification.length > 60 ? justification.slice(0,60) + '...' : justification)}</div>`;
  }
  return html;
}

export async function setCveWorkflow(cveId, nodeId, status, textareaEl) {
  const justification = textareaEl ? textareaEl.value.trim() : null;
  const needsJustif = status === 'accepted_risk' || status === 'false_positive';
  if (textareaEl) textareaEl.classList.toggle('hidden', !needsJustif);
  await fetch(`${API}/cves/${encodeURIComponent(cveId)}/workflow`, {
    method: 'PUT', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({node_id: nodeId, status, justification: justification || null}),
  });
}
