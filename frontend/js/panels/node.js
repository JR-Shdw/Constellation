// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, esc, formatBytes, timeAgo, typeBadges, txtColor } from '../api.js';

// Heartbeat mini-chart (SVG viewBox)
const _VW = 400, _VH = 60;

function _hbChart(data) {
  if (!data || !data.length) return '<div class="text-dim text-sm">No heartbeat data yet</div>';
  const step = _VW / Math.max(data.length - 1, 1);
  // Plot uptime ratio (0–100%) per bucket, not raw check counts
  const pct = data.map(d => {
    const total = (d.up || 0) + (d.down || 0);
    return total > 0 ? (d.up || 0) / total * 100 : null;
  });
  const y = (v) => _VH - (v / 100) * _VH * 0.85 - 1;

  // Skip buckets with no data (null) — connect surrounding points
  const upPts = pct.map((v, i) => `${(i * step).toFixed(1)},${y(v ?? 100).toFixed(1)}`);
  const upPath = `M0,${_VH} L${upPts.join(' L')} L${((data.length - 1) * step).toFixed(1)},${_VH} Z`;

  return `<svg viewBox="0 0 ${_VW} ${_VH}" preserveAspectRatio="xMidYMid meet" class="block w-full h-auto">
    <path d="${upPath}" fill="var(--green)" opacity="0.25"/>
    <polyline points="${upPts.join(' ')}" fill="none" stroke="var(--green)" stroke-width="1.5"/>
    ${data.map((d, i) => d.down > 0 ? `<circle cx="${(i * step).toFixed(1)}" cy="${y(pct[i] ?? 100).toFixed(1)}" r="2.5" fill="var(--red)" opacity="0.8"/>` : '').join('')}
  </svg>`;
}

function _fmtHz(hz) {
  if (!hz || typeof hz !== 'number') return '';
  if (hz >= 1e9) return `${(hz / 1e9).toFixed(2)} GHz`;
  if (hz >= 1e6) return `${(hz / 1e6).toFixed(0)} MHz`;
  return `${hz} Hz`;
}

function _fmtBytes(b) {
  if (!b || typeof b !== 'number') return '';
  if (b >= 1073741824) return `${Math.round(b / 1073741824)} GB`;
  if (b >= 1048576) return `${Math.round(b / 1048576)} MB`;
  return `${b} B`;
}

function _parseHardware(hw) {
  const r = { system: '', vendor: '', cpu: [], memory: '', memSlots: [], disks: [], volumes: [], network: [], swap: '' };
  if (!hw || typeof hw !== 'object') return null;

  // Flatten lshw -json tree into flat list
  const flat = [];
  const flatten = (node) => {
    if (node.class) flat.push(node);
    for (const child of (node.children || [])) flatten(child);
  };
  if (Array.isArray(hw)) { for (const item of hw) flatten(item); }
  else { flatten(hw); }
  if (!flat.length) return null;

  for (const item of flat) {
    const cls = (item.class || '').toLowerCase();
    const prod = item.product || '';
    const desc = item.description || '';

    // System
    if (cls === 'system' && prod && !r.system) {
      r.system = prod;
      if (item.vendor) r.vendor = item.vendor;
    }

    // CPU — each physical processor
    if (cls === 'processor' && prod && !prod.toLowerCase().includes('empty')) {
      const freq = item.capacity || item.size || 0;
      const cores = item.configuration?.cores || '';
      const threads = item.configuration?.threads || '';
      let label = prod;
      if (freq) label += ` @ ${_fmtHz(freq)}`;
      if (cores) label += ` (${cores}c/${threads || cores}t)`;
      r.cpu.push(label);
    }

    // Memory bank (top-level "memory" with description "System Memory")
    if (cls === 'memory' && desc.toLowerCase().includes('system memory') && item.size) {
      r.memory = _fmtBytes(item.size);
    }

    // Individual DIMM slots
    if (cls === 'memory' && desc.toLowerCase().includes('dimm') && item.size) {
      const slotDesc = item.slot || item.description || '';
      r.memSlots.push(`${slotDesc}: ${_fmtBytes(item.size)}${item.clock ? ' @ ' + _fmtHz(item.clock) : ''}`);
    }

    // Disks (physical drives)
    if (cls === 'disk' && (prod || desc)) {
      const sz = item.size ? ` (${_fmtBytes(item.size)})` : '';
      const logname = item.logicalname || '';
      const label = prod || desc;
      r.disks.push(`${logname ? logname + ' — ' : ''}${label}${sz}`);
    }

    // Storage controllers (NVMe, RAID) — extract disk info from children
    if (cls === 'storage' && (prod || desc)) {
      const label = prod || desc;
      const sz = item.size ? ` (${_fmtBytes(item.size)})` : '';
      const logname = item.logicalname || '';
      // Only add if it looks like a drive (has size or logicalname like /dev/nvme*)
      if (item.size || (logname && logname.includes('nvme'))) {
        r.disks.push(`${logname ? logname + ' — ' : ''}${label}${sz}`);
      }
    }

    // Volumes — mounted filesystems + swap
    if (cls === 'volume') {
      const mount = item.configuration?.mount || '';
      const fs = item.configuration?.filesystem || '';
      const sz = item.size || item.capacity || 0;
      const logname = item.logicalname || '';

      if (mount === 'swap' || desc.toLowerCase().includes('swap') || fs === 'swap') {
        r.swap = _fmtBytes(sz);
      } else if (mount && sz) {
        r.volumes.push(`${logname || '?'} → ${mount} (${_fmtBytes(sz)}, ${fs || '?'})`);
      }
    }

    // Network interfaces (physical only — lshw doesn't see wg/virtual)
    if (cls === 'network') {
      const name = item.logicalname || '';
      const label = prod || desc;
      const ip = item.configuration?.ip || '';
      const link = item.configuration?.link || '';
      const speed = item.capacity ? _fmtHz(item.capacity).replace('Hz', 'bit/s') : '';
      let entry = name ? `${name} — ` : '';
      entry += label;
      if (speed) entry += ` (${speed})`;
      if (ip) entry += ` — ${ip}`;
      if (link === 'no') entry += ' [DOWN]';
      r.network.push(entry);
    }
  }

  // Fallback: total memory from top-level if not found in System Memory
  if (!r.memory) {
    const memNode = flat.find(n => n.class === 'memory' && n.size && n.size >= 1073741824);
    if (memNode) r.memory = _fmtBytes(memNode.size);
  }

  return (r.system || r.cpu.length || r.memory) ? r : null;
}

export async function showNode(id) {
  const panel = document.getElementById('detail');
  const content = document.getElementById('detail-content');
  panel.classList.remove('side-panel');
  panel.classList.add('open');
  content.innerHTML = '<div class="loading">Loading...</div>';

  try {
    const [d, scansData, bkData, settings, hbData, driftData] = await Promise.all([
      api(`/nodes/${id}`),
      api('/scan/status').catch(() => ({items:[]})),
      api(`/backup/summary?node_id=${id}`).catch(() => ({items:[]})),
      api('/settings/alerts').catch(() => ({})),
      api(`/heartbeat/history?node_id=${id}&days=7`).catch(() => ({items:[]})),
      api(`/drift?node_id=${id}&per_page=20`).catch(() => ({items:[]})),
    ]);
    const n = d.node;

    // Count CVEs by severity from the detail data
    const allCves = d.cves || [];
    const countBySev = (sev) => allCves.filter(c => c.severity === sev).length;
    const exMed = settings.cve_count_exclude_medium === 'true';
    const exLow = settings.cve_count_exclude_low === 'true';

    let cveBadges = `<span class="badge critical text-xs">${countBySev('critical')} critical</span> `;
    cveBadges += `<span class="badge high text-xs">${countBySev('high')} high</span> `;
    if (!exMed) cveBadges += `<span class="text-yellow text-xs text-bold">${countBySev('medium')} medium</span> `;
    if (!exLow) cveBadges += `<span class="text-dim text-xs">${countBySev('low')} low</span>`;

    let html = `
      <div data-action="closeDetail" class="close-chevron" title="Close">▼</div>
      <h2>${esc(n.hostname)}</h2>`;
    html += `<div class="detail-section">
      <h3>Info</h3>
      <div class="detail-grid">
        <span class="k">Type</span><span>${typeBadges(n.type, 99)}</span>
        <span class="k">OS</span><span>${esc(n.os || '')} ${esc(n.os_version || '')}</span>
        <span class="k">Arch</span><span>${esc(n.arch || '')}</span>
        <span class="k">Kernel</span><span>${esc(n.kernel || '')}</span>
        <span class="k">Last scan</span><span>${timeAgo(n.last_seen)}</span>
        <span class="k">Packages</span><span>${n.package_count}</span>
        <span class="k">Containers</span><span>${n.container_count}</span>
        <span class="k">CVEs host</span><span>${n.cve_package_count || 0}</span>
        <span class="k">CVEs containers</span><span>${n.cve_container_count || 0}</span>
        <span class="k">CVEs</span><span>${cveBadges}</span>
      </div>
    </div>`;

    // Heartbeat graph + uptime %
    const hbItems = hbData.items || [];
    if (hbItems.length || n.heartbeat_status) {
      const totalUp = hbItems.reduce((a, d) => a + (d.up || 0), 0);
      const totalDown = hbItems.reduce((a, d) => a + (d.down || 0), 0);
      const total = totalUp + totalDown;
      const uptimePct = total > 0 ? ((totalUp / total) * 100).toFixed(1) : '—';
      const st = n.heartbeat_status || 'unknown';
      const stColor = st === 'up' ? 'green' : st === 'down' ? 'red' : 'text-dim';
      const dot = st === 'up' ? '●' : st === 'down' ? '●' : '○';
      const lastHb = n.last_heartbeat ? timeAgo(n.last_heartbeat) : '—';

      html += `<div class="detail-section">
        <h3 class="flex items-center gap-lg">
          Heartbeat
          <span class="${txtColor(stColor)} text-14">${dot}</span>
          <span class="text-12 text-normal ${txtColor(stColor)}">${st}</span>
          <span class="ml-auto text-md text-normal text-dim">last: ${lastHb}</span>
        </h3>
        <div class="hb-row">
          <div class="uptime-big ${txtColor(uptimePct === '100.0' ? 'green' : uptimePct === '—' ? 'text-dim' : 'orange')}">${uptimePct}${uptimePct !== '—' ? '%' : ''}</div>
          <div class="text-sm text-dim">uptime<br>7 days</div>
          <div class="flex-1-min-200">${_hbChart(hbItems)}</div>
        </div>
        <div class="flex gap-xl text-sm text-dim">
          <span><span class="legend-dot-sm green"></span>${totalUp} checks up</span>
          <span><span class="legend-dot-sm red"></span>${totalDown} checks down</span>
        </div>
      </div>`;
    }

    // Scan status (already fetched in parallel)
    try {
      const ss = scansData.items.find(s => s.node_id === id);
      if (ss) {
        html += `<div class="detail-section"><h3>Scan Status</h3>
          <div class="detail-grid">
            <span class="k">Trivy Host</span><span>${ss.last_trivy_host_scan ? timeAgo(ss.last_trivy_host_scan) : '<span class="text-red">never</span>'}</span>
            <span class="k">Trivy Images</span><span>${ss.last_trivy_image_scan ? timeAgo(ss.last_trivy_image_scan) : '<span class="text-dim">-</span>'}</span>
            <span class="k">Wazuh</span><span>${ss.last_wazuh_scan ? timeAgo(ss.last_wazuh_scan) : '<span class="text-dim">-</span>'}</span>
          </div>
        </div>`;
      }
    } catch(e) {}

    // Hardware summary — parse lshw JSON into a readable summary
    if (n.hw_info && typeof n.hw_info === 'object') {
      const hw = _parseHardware(n.hw_info);
      if (hw) {
        let hwHtml = '<div class="detail-grid">';
        if (hw.system) hwHtml += `<span class="k">System</span><span>${esc(hw.system)}${hw.vendor ? ' — ' + esc(hw.vendor) : ''}</span>`;
        if (hw.cpu.length) hwHtml += `<span class="k">CPU</span><span>${hw.cpu.map(c => esc(c)).join('<br>')}</span>`;
        if (hw.memory) {
          let memStr = hw.memory;
          if (hw.memSlots.length) memStr += `<br><span class="text-xs text-dim">${hw.memSlots.map(s => esc(s)).join('<br>')}</span>`;
          hwHtml += `<span class="k">Memory</span><span>${memStr}</span>`;
        }
        if (hw.swap) hwHtml += `<span class="k">Swap</span><span>${esc(hw.swap)}</span>`;
        if (hw.disks.length) hwHtml += `<span class="k">Disks</span><span>${hw.disks.map(d => esc(d)).join('<br>')}</span>`;
        if (hw.volumes.length) hwHtml += `<span class="k">Mounts</span><span>${hw.volumes.map(d => esc(d)).join('<br>')}</span>`;
        if (hw.network.length) {
          // Add WireGuard IPs from node data (lshw only sees physical interfaces)
          const wgIps = [];
          if (n.ip_address && n.ip_address.startsWith('10.5')) wgIps.push(`wg — ${n.ip_address}`);
          if (n.check_address && n.check_address !== n.ip_address && n.check_address.startsWith('10.5')) wgIps.push(`wg — ${n.check_address}`);
          const allNets = [...hw.network, ...wgIps.map(w => w + ' (WireGuard)')];
          hwHtml += `<span class="k">Network</span><span>${allNets.map(d => esc(d)).join('<br>')}</span>`;
        }
        hwHtml += '</div>';
        html += `<div class="detail-section"><h3>Hardware</h3>${hwHtml}</div>`;
      }
    }

    // Drift section
    const driftItems = driftData.items || [];
    if (driftItems.length) {
      html += `<div class="detail-section"><h3>Drift Detection (${driftItems.length})</h3>
        <div class="table-wrap"><table>
          <tr><th>Type</th><th>Resource</th><th>Severity</th><th>Expected</th><th>Actual</th><th>Status</th></tr>`;
      for (const dr of driftItems) {
        const sevC = dr.severity === 'critical' ? 'red' : dr.severity === 'high' ? 'orange' : 'text-dim';
        html += `<tr>
          <td class="text-xs">${esc(dr.drift_type)}</td>
          <td class="text-mono text-xs">${esc(dr.resource_name)}</td>
          <td><span class="badge ${dr.severity}">${esc(dr.severity)}</span></td>
          <td class="drift-cell text-green" title="${esc(dr.expected || '')}">${esc(dr.expected || '—')}</td>
          <td class="drift-cell text-red" title="${esc(dr.actual || '')}">${esc(dr.actual || '—')}</td>
          <td class="text-xs ${txtColor(dr.status === 'resolved' ? 'green' : dr.status === 'open' ? 'text-dim' : 'accent')}">${esc(dr.status)}</td>
        </tr>`;
      }
      html += '</table></div></div>';
    }

    if (d.containers.length) {
      html += `<div class="detail-section"><h3>Containers (${d.containers.length})</h3>
        <div class="table-wrap"><table><tr><th>Name</th><th>Image</th><th>Status</th></tr>`;
      for (const c of d.containers) {
        const img = `${c.image}:${c.tag || 'latest'}`;
        html += `<tr>
          <td>${esc(c.name)}</td>
          <td class="clickable" data-action="showImageHosts" data-id="${esc(c.image)}">${esc(img)}</td>
          <td>${esc(c.status || '')}</td></tr>`;
      }
      html += '</table></div></div>';
    }

    // Filter CVEs by settings exclusions
    const exclSev = new Set();
    if (exMed) exclSev.add('medium');
    if (exLow) exclSev.add('low');
    const visibleCves = exclSev.size ? allCves.filter(c => !exclSev.has(c.severity)) : allCves;

    const sevOrder = {critical:0, high:1, medium:2, low:3, unknown:4};
    const sortCves = arr => arr.sort((a, b) =>
      (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4)
      || (b.cvss_score || 0) - (a.cvss_score || 0));
    const hostCves = sortCves(visibleCves.filter(c => c.target_type === 'package'));
    const ctrCves  = sortCves(visibleCves.filter(c => c.target_type !== 'package'));
    const isNoise = c => c.severity === 'low' || c.fix_status === 'will_not_fix' || c.fix_status === 'not_affected';
    const hostNoise = hostCves.filter(isNoise).length;
    const ctrNoise  = ctrCves.filter(isNoise).length;
    const totalNoise = hostNoise + ctrNoise;

    // Helper: noise indicator (backported, disputed, will_not_fix)
    const noiseInfo = (c) => {
      const wnf = c.fix_status === 'will_not_fix';
      const na = c.fix_status === 'not_affected';
      const bp = (c.severity === 'low' && c.cvss_score >= 7) || (c.severity === 'medium' && c.cvss_score >= 9);
      const is = wnf || na || bp;
      const label = wnf ? 'won\'t fix' : na ? 'not affected' : bp ? 'backport' : '';
      return {
        is,
        tag: is ? ` <span title="${wnf ? 'Distro will not fix this CVE' : na ? 'Package not affected per distro' : 'Distro severity differs from NVD CVSS'}" class="text-dim text-xs cursor-help">${label}</span>` : '',
      };
    };

    // Toggle noise CVEs (low, will_not_fix, not_affected)
    if (totalNoise > 0) {
      html += `<div class="noise-toggle-row">
        <label class="flex items-center gap-sm cursor-pointer text-md text-dim">
          <input type="checkbox" id="hide-noise-cves" data-change="toggleCveNoise" checked>
          Hide noise (${totalNoise} hidden — low, won't fix, not affected)
        </label>
      </div>`;
    }

    if (hostCves.length) {
      const hCrit = hostCves.filter(c => c.severity === 'critical').length;
      html += `<div class="detail-section">
        <h3>CVEs — OS packages (${hostCves.length})
          ${hCrit ? `<span class="badge critical ml-8 text-xs">${hCrit} critical</span>` : ''}
          ${hostNoise ? `<span class="cve-noise-count ml-8 text-xs text-dim">${hostNoise} noise hidden</span>` : ''}
        </h3>
        <div class="table-wrap"><table>
          <tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Package</th></tr>`;
      for (const c of hostCves.slice(0, 50)) {
        const ni = noiseInfo(c);
        const hide = isNoise(c);
        html += `<tr class="${[hide ? 'cve-noise' : '', hide ? 'hidden' : '', ni.is && !hide ? 'opacity-60' : ''].filter(Boolean).join(' ')}">
          <td class="clickable" data-action="showCVEDetail" data-id="${c.cve_id}">${esc(c.cve_id)}</td>
          <td><span class="badge ${c.severity}">${esc(c.severity)}</span>${ni.tag}</td>
          <td>${c.cvss_score || '—'}</td>
          <td>${esc(c.target)}</td>
        </tr>`;
      }
      if (hostCves.length > 50) html += `<tr><td colspan="4" class="empty">... and ${hostCves.length - 50} more</td></tr>`;
      html += '</table></div></div>';
    }

    if (ctrCves.length) {
      const cCrit = ctrCves.filter(c => c.severity === 'critical').length;
      const byImage = {};
      for (const c of ctrCves) {
        const key = c.target || 'unknown';
        if (!byImage[key]) byImage[key] = [];
        byImage[key].push(c);
      }
      html += `<div class="detail-section">
        <h3>CVEs — Containers (${ctrCves.length})
          ${cCrit ? `<span class="badge critical ml-8 text-xs">${cCrit} critical</span>` : ''}
          ${ctrNoise ? `<span class="cve-noise-count ml-8 text-xs text-dim">${ctrNoise} noise hidden</span>` : ''}
        </h3>`;
      for (const [img, cvs] of Object.entries(byImage).slice(0, 10)) {
        const imgNoise = cvs.filter(isNoise).length;
        html += `<div class="mb-8">
          <div class="ctr-img-head">${esc(img)} (${cvs.length}${imgNoise ? `, ${imgNoise} noise` : ''})</div>
          <div class="table-wrap"><table>
            <tr><th>CVE</th><th>Severity</th><th>CVSS</th></tr>`;
        for (const c of cvs.slice(0, 20)) {
          const ni = noiseInfo(c);
          const hide = isNoise(c);
          html += `<tr class="${[hide ? 'cve-noise' : '', hide ? 'hidden' : '', ni.is && !hide ? 'opacity-60' : ''].filter(Boolean).join(' ')}">
            <td class="clickable" data-action="showCVEDetail" data-id="${c.cve_id}">${esc(c.cve_id)}</td>
            <td><span class="badge ${c.severity}">${esc(c.severity)}</span>${ni.tag}</td>
            <td>${c.cvss_score || '—'}</td>
          </tr>`;
        }
        if (cvs.length > 20) html += `<tr><td colspan="3" class="empty">... and ${cvs.length - 20} more</td></tr>`;
        html += '</table></div></div>';
      }
      if (Object.keys(byImage).length > 10) {
        html += `<div class="empty">... and ${Object.keys(byImage).length - 10} more images</div>`;
      }
      html += '</div>';
    }

    if (d.packages.length) {
      html += `<div class="detail-section"><h3>Packages (${d.packages.length})</h3>
        <div class="table-wrap scroll-300"><table><tr><th>Name</th><th>Version</th></tr>`;
      for (const p of d.packages.slice(0, 100)) {
        html += `<tr>
          <td class="clickable" data-action="showPackageHosts" data-id="${esc(p.name)}">${esc(p.name)}</td>
          <td>${esc(p.version)}</td></tr>`;
      }
      if (d.packages.length > 100) html += `<tr><td colspan="2" class="empty">... and ${d.packages.length - 100} more</td></tr>`;
      html += '</table></div></div>';
    }

    // Backup section
    try {
      const bk = bkData;
      if (bk.items && bk.items.length) {
        html += `<div class="detail-section"><h3>Backups (${bk.items.length} repo${bk.items.length > 1 ? 's' : ''})</h3>
          <div class="table-wrap"><table>
            <tr><th>Repo</th><th>Status</th><th>Last run</th><th>Duration</th><th>Added</th><th>Files new</th><th>30d runs</th><th>Success rate</th></tr>`;
        for (const b of bk.items) {
          const stColor = b.status === 'success' ? 'green' : b.status === 'failure' ? 'red' : 'text-dim';
          const overdueTag = b.overdue ? ' <span class="text-red text-xs text-bolder">OVERDUE</span>' : '';
          const dur = b.duration_secs ? `${Math.floor(b.duration_secs / 60)}m${b.duration_secs % 60}s` : '—';
          const added = b.size_added ? formatBytes(b.size_added) : '—';
          const rate = b.success_rate != null ? `${Math.round(b.success_rate)}%` : '—';
          const rateColor = b.success_rate >= 90 ? 'green' : b.success_rate >= 70 ? 'orange' : 'red';
          html += `<tr>
            <td>${esc(b.repo_name)}${overdueTag}</td>
            <td><span class="${txtColor(stColor)}">${esc(b.status || '—')}</span></td>
            <td>${b.last_run ? timeAgo(b.last_run) : '—'}</td>
            <td>${dur}</td>
            <td>${added}</td>
            <td>${b.files_new != null ? b.files_new : '—'}</td>
            <td>${b.total_runs || '—'}</td>
            <td><span class="${txtColor(rateColor)}">${rate}</span></td>
          </tr>`;
        }
        html += '</table></div></div>';
      }
    } catch(e) {}

    content.innerHTML = html;
  } catch(e) {
    content.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}
