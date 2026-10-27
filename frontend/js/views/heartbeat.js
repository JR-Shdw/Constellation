// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { api, esc, _h, tabBar, timeAgo, txtColor } from '../api.js';

// SVG chart helpers (responsive via viewBox)
// All charts use a fixed internal coordinate system (vW×vH)
// but render at 100% container width via viewBox + preserveAspectRatio.

const VW = 500, VH = 140, PAD_L = 40, PAD_B = 20, CHART_W = VW - PAD_L - 4, CHART_H = VH - PAD_B - 4;

function svgWrap(inner) {
  return `<svg viewBox="0 0 ${VW} ${VH}" preserveAspectRatio="xMidYMid meet" class="block w-full h-auto">${inner}</svg>`;
}

function _fmtDate(d) {
  if (!d) return '';
  const s = String(d);
  // "2026-04-05" → "Apr 05" or "04/05"
  const m = s.match(/(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return s.slice(0, 10);
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  return `${months[parseInt(m[2], 10) - 1]} ${parseInt(m[3], 10)}`;
}

function _axisLabels(data, maxVal, dayKey, suffix) {
  let labels = '';
  const tickCount = Math.min(data.length, 6);
  const step = CHART_W / Math.max(data.length - 1, 1);
  const sfx = suffix || '';

  // Y-axis — 3 ticks (0, mid, max)
  const yTicks = [0, Math.round(maxVal / 2), maxVal];
  for (const v of yTicks) {
    const y = (CHART_H - (v / Math.max(maxVal, 1)) * CHART_H * 0.85 - 2) + 2;
    labels += `<text x="${PAD_L - 4}" y="${y + 3}" fill="var(--text-dim)" font-size="8" text-anchor="end" font-family="inherit">${v}${sfx}</text>`;
    labels += `<line x1="${PAD_L}" y1="${y}" x2="${VW - 4}" y2="${y}" stroke="var(--border)" stroke-width="0.5" opacity="0.3"/>`;
  }

  // X-axis — evenly spaced date labels
  if (data.length > 1) {
    const spacing = Math.max(1, Math.floor((data.length - 1) / (tickCount - 1)));
    for (let i = 0; i < data.length; i += spacing) {
      const x = PAD_L + i * step;
      const label = _fmtDate(data[i][dayKey || 'day']);
      labels += `<text x="${x}" y="${VH - 2}" fill="var(--text-dim)" font-size="8" text-anchor="middle" font-family="inherit">${label}</text>`;
    }
    // Always show last label
    const lastI = data.length - 1;
    if (lastI % spacing !== 0) {
      const x = PAD_L + lastI * step;
      labels += `<text x="${x}" y="${VH - 2}" fill="var(--text-dim)" font-size="8" text-anchor="middle" font-family="inherit">${_fmtDate(data[lastI][dayKey || 'day'])}</text>`;
    }
  }
  return labels;
}

function areaChart(data, keyUp, keyDown, suffix) {
  if (!data || !data.length) return '<div class="empty">No data yet</div>';
  const maxVal = Math.max(...data.map(d => (d[keyUp] || 0) + (d[keyDown] || 0)), 1);
  const step = CHART_W / Math.max(data.length - 1, 1);
  const yScale = (v) => 2 + CHART_H - (v / maxVal) * CHART_H * 0.85;
  const bottom = 2 + CHART_H;

  const upPts = data.map((d, i) => `${(PAD_L + i * step).toFixed(1)},${yScale(d[keyUp] || 0).toFixed(1)}`);
  const upPath = `M${PAD_L},${bottom} L${upPts.join(' L')} L${(PAD_L + (data.length - 1) * step).toFixed(1)},${bottom} Z`;

  const downPts = data.map((d, i) => {
    const total = (d[keyUp] || 0) + (d[keyDown] || 0);
    return `${(PAD_L + i * step).toFixed(1)},${yScale(total).toFixed(1)}`;
  });
  const downPath = `M${upPts[0].split(',')[0]},${upPts[0].split(',')[1]} L${downPts.join(' L')} L${upPts[upPts.length - 1].split(',')[0]},${upPts[upPts.length - 1].split(',')[1]} Z`;

  return svgWrap(`
    ${_axisLabels(data, maxVal, 'day', suffix)}
    <path d="${upPath}" fill="var(--green)" opacity="0.3"/>
    <polyline points="${upPts.join(' ')}" fill="none" stroke="var(--green)" stroke-width="1.5"/>
    <path d="${downPath}" fill="var(--red)" opacity="0.25"/>
    <polyline points="${downPts.join(' ')}" fill="none" stroke="var(--red)" stroke-width="1.5"/>
  `);
}

function barChart(data, keyOk, keyFail, suffix) {
  if (!data || !data.length) return '<div class="empty">No data yet</div>';
  const maxVal = Math.max(...data.map(d => (d[keyOk] || 0) + (d[keyFail] || 0)), 1);
  const bw = Math.max(CHART_W / data.length - 2, 3);
  const bottom = 2 + CHART_H;
  let bars = '';
  for (let i = 0; i < data.length; i++) {
    const x = PAD_L + i * (bw + 2);
    const ok = (data[i][keyOk] || 0);
    const fail = (data[i][keyFail] || 0);
    const oh = (ok / maxVal) * CHART_H * 0.85;
    const fh = (fail / maxVal) * CHART_H * 0.85;
    if (oh > 0) bars += `<rect x="${x}" y="${(bottom - oh - fh).toFixed(1)}" width="${bw}" height="${oh.toFixed(1)}" fill="var(--green)" opacity="0.7" rx="1"><title>${data[i].day || ''}: ${ok}${suffix || ''} ok</title></rect>`;
    if (fh > 0) bars += `<rect x="${x}" y="${(bottom - fh).toFixed(1)}" width="${bw}" height="${fh.toFixed(1)}" fill="var(--red)" opacity="0.8" rx="1"><title>${data[i].day || ''}: ${fail}${suffix || ''} fail</title></rect>`;
  }
  return svgWrap(`${_axisLabels(data, maxVal, 'day', suffix)}${bars}`);
}

function lineChart(data, keys, colors) {
  if (!data || !data.length) return '<div class="empty">No data yet</div>';
  const maxVal = Math.max(...keys.flatMap(k => data.map(d => d[k] || 0)), 1);
  const step = CHART_W / Math.max(data.length - 1, 1);
  let lines = '';
  for (let ki = 0; ki < keys.length; ki++) {
    const pts = data.map((d, i) => {
      const y = 2 + CHART_H - ((d[keys[ki]] || 0) / maxVal) * CHART_H * 0.85;
      return `${(PAD_L + i * step).toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    lines += `<polyline points="${pts}" fill="none" stroke="${colors[ki]}" stroke-width="1.5" stroke-linejoin="round"/>`;
  }
  return svgWrap(`${_axisLabels(data, maxVal, 'day')}${lines}`);
}

function legend(items) {
  return `<div class="flex gap-xl mt-6 text-sm text-dim">
    ${items.map(([color, label]) => `<span><span class="legend-dot ${color}"></span>${label}</span>`).join('')}
  </div>`;
}

// Summary helpers

function sumKey(data, key) {
  return (data || []).reduce((a, d) => a + (d[key] || 0), 0);
}

// 24h mini sparklines for the Summary tab — smaller than the Graph tab
// charts, no axes, single colour each. Whole card is clickable → Graph.
function _miniSpark(points, color, fillOpacity) {
  if (!points || !points.length) {
    return '<div class="text-xs text-dim">No data yet</div>';
  }
  const W = 240, H = 50, PAD = 4;
  const max = Math.max(...points, 1);
  const step = (W - 2 * PAD) / Math.max(points.length - 1, 1);
  const yScale = v => H - PAD - ((v / max) * (H - 2 * PAD));
  const pts = points.map((v, i) => `${(PAD + i * step).toFixed(1)},${yScale(v).toFixed(1)}`);
  const linePath = `M${pts.join(' L')}`;
  const areaPath = `${linePath} L${(PAD + (points.length - 1) * step).toFixed(1)},${H - PAD} L${PAD},${H - PAD} Z`;
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" class="block w-full h-auto">
    <path d="${areaPath}" fill="${color}" opacity="${fillOpacity}"/>
    <path d="${linePath}" fill="none" stroke="${color}" stroke-width="1.5"/>
  </svg>`;
}

function _miniBars(values, color) {
  if (!values || !values.length) {
    return '<div class="text-xs text-dim">No data yet</div>';
  }
  const W = 240, H = 50, PAD = 4;
  const max = Math.max(...values, 1);
  const slot = (W - 2 * PAD) / values.length;
  const barW = Math.max(1.5, slot - 1);
  let bars = '';
  for (let i = 0; i < values.length; i++) {
    const v = values[i];
    if (v <= 0) continue;
    const h = Math.max(1, ((v / max) * (H - 2 * PAD)));
    const x = PAD + i * slot;
    bars += `<rect x="${x.toFixed(1)}" y="${(H - PAD - h).toFixed(1)}" width="${barW.toFixed(1)}" height="${h.toFixed(1)}" fill="${color}"/>`;
  }
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" class="block w-full h-auto">${bars}</svg>`;
}

function _miniCards24h(buckets) {
  // Per-hour aggregates from /heartbeat/trends?hours=24.
  // Uptime % per hour : up / (up+down). Latency : avg_latency_ms.
  // Incidents : down_events count per hour.
  const uptimePct = buckets.map(b => {
    const total = (b.up || 0) + (b.down || 0);
    return total > 0 ? Math.round((b.up / total) * 100) : 100;
  });
  const latency = buckets.map(b => Number(b.avg_latency_ms) || 0);
  const events = buckets.map(b => b.down_events || 0);

  const totalUp = buckets.reduce((s, b) => s + (b.up || 0), 0);
  const totalDown = buckets.reduce((s, b) => s + (b.down || 0), 0);
  const uptimeRate = totalUp + totalDown > 0
    ? Math.round((totalUp / (totalUp + totalDown)) * 100)
    : 100;
  const lastLatency = [...latency].reverse().find(v => v > 0) || 0;
  const totalEvents = events.reduce((s, v) => s + v, 0);
  const goToGraph = 'data-action="setTab" data-tab="graph" data-group="heartbeat"';

  return `<div class="grid-card-240 mb-24">
    <div class="stat-card cursor-pointer" ${goToGraph} title="Open Graph tab">
      <div class="label">Uptime · 24h</div>
      <div class="value ${uptimeRate >= 99 ? 'green' : 'orange'} text-base">${uptimeRate}%</div>
      <div class="mt-4">${_miniSpark(uptimePct, 'var(--green)', 0.3)}</div>
    </div>
    <div class="stat-card cursor-pointer" ${goToGraph} title="Open Graph tab">
      <div class="label">Latency · 24h</div>
      <div class="value text-base">${lastLatency ? lastLatency.toFixed(0) + ' ms' : '—'}</div>
      <div class="mt-4">${_miniSpark(latency, 'var(--accent)', 0.25)}</div>
    </div>
    <div class="stat-card cursor-pointer" ${goToGraph} title="Open Graph tab">
      <div class="label">Down events · 24h</div>
      <div class="value ${totalEvents > 0 ? 'red' : ''} text-base">${totalEvents}</div>
      <div class="mt-4">${_miniBars(events, 'var(--red)')}</div>
    </div>
  </div>`;
}

function summaryRow(items) {
  return `<div class="flex gap-xl mt-8 text-md flex-wrap">
    ${items.map(([val, label, color]) => `<span class="${txtColor(color || 'text-dim')}">${label} <strong class="text-base">${val.toLocaleString()}</strong></span>`).join('<span class="sep-dot">·</span>')}
  </div>`;
}

// Main render

let _trendDays = 30;
let _hbSortCol = null;
let _hbSortAsc = true;

export async function renderHeartbeat(el) {
  _hbEl = el;
  const tab = window.heartbeatTab || 'summary';

  // Fetch status + trends in parallel. The 24h hourly trend is only used
  // by the Summary tab's mini cards, so we skip it on Graph/Status.
  let hbUrl = '/heartbeat/status';
  if (_hbSortCol) hbUrl += `?sort_by=${_hbSortCol}&sort_dir=${_hbSortAsc ? 'asc' : 'desc'}`;
  const [statusData, trends, trends24h] = await Promise.all([
    api(hbUrl),
    api(`/stats/trends?days=${_trendDays}`),
    tab === 'summary'
      ? api('/heartbeat/trends?hours=24').catch(() => ({ items: [] }))
      : Promise.resolve({ items: [] }),
  ]);

  const items = statusData.items || [];
  const upCount = items.filter(n => n.heartbeat_status === 'up').length;
  const downCount = items.filter(n => n.heartbeat_status === 'down').length;
  const unknownCount = items.filter(n => !n.heartbeat_status || n.heartbeat_status === 'unknown').length;

  let html = tabBar(
    [['summary', 'Summary'], ['graph', 'Graph'], ['status', 'Status']],
    tab, 'heartbeat'
  );

  // Summary tab — 4 stat cards + 3 clickable mini sparklines (24h)
  if (tab === 'summary') {
    html += `<div class="stats mb-16">
      <div class="stat-card">
        <div class="label">Nodes Up</div>
        <div class="value green">${upCount}</div>
      </div>
      <div class="stat-card">
        <div class="label">Nodes Down</div>
        <div class="value ${downCount > 0 ? 'red' : ''}">${downCount}</div>
      </div>
      <div class="stat-card">
        <div class="label">Unknown</div>
        <div class="value text-dim">${unknownCount}</div>
      </div>
      <div class="stat-card">
        <div class="label">Uptime Rate</div>
        <div class="value ${upCount === items.length ? 'green' : 'orange'}">${items.length ? Math.round(upCount / items.length * 100) : 0}%</div>
      </div>
    </div>`;

    html += _miniCards24h(trends24h.items || []);
    el.innerHTML = html;
    return;
  }

  // Compute totals for summaries
  const hb = trends.heartbeat || [];
  const totalUp = sumKey(hb, 'up');
  const totalDown = sumKey(hb, 'down');
  const uptimeRate30 = totalUp + totalDown > 0 ? ((totalUp / (totalUp + totalDown)) * 100).toFixed(1) : '—';

  const cv = trends.cves || [];
  const cvStock = trends.cve_stock || {};
  const totalDetected = sumKey(cv, 'detected');
  const totalResolved = sumKey(cv, 'resolved');
  const totalDetectedHost = sumKey(cv, 'detected_host');
  const totalDetectedCtr = sumKey(cv, 'detected_container');
  const totalResolvedHost = sumKey(cv, 'resolved_host');
  const totalResolvedCtr = sumKey(cv, 'resolved_container');

  // Build cumulative series for CVE charts (total, host, container)
  let cumCrit = 0, cumResolved = 0;
  let cumHostCrit = 0, cumHost = 0, cumHostResolved = 0;
  let cumCtrCrit = 0, cumCtr = 0, cumCtrResolved = 0;
  const cvCumul = cv.map(d => {
    cumCrit += (d.detected_critical || 0);
    cumResolved += (d.resolved || 0);
    cumHostCrit += (d.detected_host_critical || 0);
    cumHost += (d.detected_host || 0);
    cumHostResolved += (d.resolved_host || 0);
    cumCtrCrit += (d.detected_container_critical || 0);
    cumCtr += (d.detected_container || 0);
    cumCtrResolved += (d.resolved_container || 0);
    return {
      ...d,
      cum_critical: cumCrit, cum_resolved: cumResolved,
      cum_host: cumHost, cum_host_critical: cumHostCrit, cum_host_resolved: cumHostResolved,
      cum_container: cumCtr, cum_container_critical: cumCtrCrit, cum_container_resolved: cumCtrResolved,
    };
  });

  const bk = trends.backups || [];
  const totalBkOk = sumKey(bk, 'ok');
  const totalBkFail = sumKey(bk, 'failed');
  const bkRate = totalBkOk + totalBkFail > 0 ? ((totalBkOk / (totalBkOk + totalBkFail)) * 100).toFixed(1) : '—';

  const au = trends.automation || [];
  const totalExec = sumKey(au, 'executed');
  const totalErr = sumKey(au, 'errors');

  // Graph tab — period selector + charts
  if (tab === 'graph') {
  const periods = [[1, '1d'], [7, '7d'], [30, '30d'], [180, '6m'], [365, '1y']];
  const periodBtns = periods.map(([d, l]) =>
    `<button data-action="_setTrendDays" data-id="${d}" class="btn-toggle${_trendDays === d ? ' active' : ''}">${l}</button>`
  ).join('');
  html += `<div class="flex gap-sm mb-12 items-center">
    <span class="text-sm text-dim">Period:</span>${periodBtns}
  </div>`;

  html += '<div class="grid-card-380">';

  const pLabel = _trendDays >= 365 ? '1y' : _trendDays >= 180 ? '6m' : `${_trendDays}d`;

  // Uptime trend — convert to percentages per day
  const hbPct = hb.map(d => {
    const total = (d.up || 0) + (d.down || 0);
    return { day: d.day, up: total > 0 ? Math.round((d.up || 0) / total * 100) : 0, down: total > 0 ? Math.round((d.down || 0) / total * 100) : 0 };
  });
  html += `<div class="stat-card p-16">
    <div class="label mb-8">Uptime — ${pLabel}</div>
    ${areaChart(hbPct, 'up', 'down', '%')}
    ${legend([['green', 'Up %'], ['red', 'Down %']])}
    ${summaryRow([
      [totalUp, 'checks up', 'green'],
      [totalDown, 'checks down', 'red'],
      [uptimeRate30 + '%', 'availability', totalDown > 0 ? 'orange' : 'green'],
    ])}
  </div>`;

  // CVE Total — cumulative critical + resolved
  const mitigRate = cumCrit > 0 ? ((cumResolved / cumCrit) * 100).toFixed(1) : '—';
  html += `<div class="stat-card p-16">
    <div class="label mb-8">CVE Total — ${pLabel}</div>
    ${lineChart(cvCumul, ['cum_critical', 'cum_resolved'], ['var(--red)', 'var(--green)'])}
    ${legend([['red', 'Critical (cumul)'], ['green', 'Resolved (cumul)']])}
    ${summaryRow([
      [cvStock.open_critical || 0, 'open critical', 'red'],
      [cvStock.open_high || 0, 'open high', 'orange'],
      [cvStock.open_total || 0, 'open total', 'accent'],
      [totalResolved, `resolved (${pLabel})`, 'green'],
      [mitigRate + '%', 'mitigation rate', cumResolved > 0 ? 'green' : 'text-dim'],
    ])}
  </div>`;

  // CVE Host — cumulative detected + critical + resolved
  html += `<div class="stat-card p-16">
    <div class="label mb-8">CVE Host — ${pLabel}</div>
    ${lineChart(cvCumul, ['cum_host', 'cum_host_critical', 'cum_host_resolved'], ['var(--orange)', 'var(--red)', 'var(--green)'])}
    ${legend([['orange', 'Detected (cumul)'], ['red', 'Critical (cumul)'], ['green', 'Resolved (cumul)']])}
    ${summaryRow([
      [cvStock.open_host || 0, 'open total', 'accent'],
      [cvStock.open_host_critical || 0, 'open critical', 'red'],
      [cvStock.open_host_high || 0, 'open high', 'orange'],
      [totalResolvedHost, `resolved (${pLabel})`, 'green'],
    ])}
  </div>`;

  // CVE Container — cumulative detected + critical + resolved
  html += `<div class="stat-card p-16">
    <div class="label mb-8">CVE Container — ${pLabel}</div>
    ${lineChart(cvCumul, ['cum_container', 'cum_container_critical', 'cum_container_resolved'], ['var(--orange)', 'var(--red)', 'var(--green)'])}
    ${legend([['orange', 'Detected (cumul)'], ['red', 'Critical (cumul)'], ['green', 'Resolved (cumul)']])}
    ${summaryRow([
      [cvStock.open_container || 0, 'open total', 'accent'],
      [cvStock.open_container_critical || 0, 'open critical', 'red'],
      [cvStock.open_container_high || 0, 'open high', 'orange'],
      [totalResolvedCtr, `resolved (${pLabel})`, 'green'],
    ])}
  </div>`;

  // Backup trend — convert to percentages per day
  const bkPct = bk.map(d => {
    const total = (d.ok || 0) + (d.failed || 0);
    return { day: d.day, ok: total > 0 ? Math.round((d.ok || 0) / total * 100) : 0, failed: total > 0 ? Math.round((d.failed || 0) / total * 100) : 0 };
  });
  html += `<div class="stat-card p-16">
    <div class="label mb-8">Backups — ${pLabel}</div>
    ${barChart(bkPct, 'ok', 'failed', '%')}
    ${legend([['green', 'Success %'], ['red', 'Failed %']])}
    ${summaryRow([
      [totalBkOk, 'success', 'green'],
      [totalBkFail, 'failed', totalBkFail > 0 ? 'red' : 'text-dim'],
      [bkRate + '%', 'success rate', totalBkFail > 0 ? 'orange' : 'green'],
    ])}
  </div>`;

  // Automation trend (30d)
  html += `<div class="stat-card p-16">
    <div class="label mb-8">Automation — ${pLabel}</div>
    ${barChart(au, 'executed', 'errors')}
    ${legend([['green', 'Executed'], ['red', 'Errors']])}
    ${summaryRow([
      [totalExec, 'executed', 'green'],
      [totalErr, 'errors', totalErr > 0 ? 'red' : 'text-dim'],
      [totalExec + totalErr, 'total actions', 'accent'],
    ])}
  </div>`;

  html += '</div>';
  el.innerHTML = html;
  return;
  } // end graph tab

  // Status tab — node status table
  const hbArrow = c => _hbSortCol === c ? (_hbSortAsc ? ' ▲' : ' ▼') : ' ▲▼';
  const hbTh = (label, col) => `<th class="clickable" data-action="sortHeartbeat" data-id="${col}">${label}${hbArrow(col)}</th>`;

  html += `<h3 class="section-h m-0">Node Status</h3>`;
  if (!items.length) {
    html += '<div class="empty">No heartbeat data — run a check first</div>';
  } else {
    html += `<div class="table-wrap"><table>
      <thead><tr>${hbTh('Status', 'status')}${hbTh('Hostname', 'hostname')}<th>Address</th>${hbTh('Last Heartbeat', 'last_heartbeat')}${hbTh('Last Down', 'last_down')}</tr></thead><tbody>`;
    for (const n of items) {
      const st = n.heartbeat_status || 'unknown';
      const color = st === 'up' ? 'green' : st === 'down' ? 'red' : 'text-dim';
      const dot = st === 'up' ? '●' : st === 'down' ? '●' : '○';
      const ago = n.last_heartbeat ? timeAgo(n.last_heartbeat) : '—';
      const addr = n.check_address || n.ip_address || '';
      const addrEsc = esc(addr);
      const lastDown = n.last_down_at ? timeAgo(n.last_down_at) : '—';
      const lastDownColor = n.last_down_at ? 'red' : 'text-dim';
      html += `<tr>
        <td><span class="${txtColor(color)} text-14">${dot}</span> <span class="text-11 ${txtColor(color)}">${st}</span></td>
        <td class="clickable" data-action="showNode" data-id="${n.id}">${esc(n.hostname)}</td>
        <td class="clickable text-sm text-accent cursor-pointer" data-action="editCheckAddress" data-id="${n.id}" data-addr="${addrEsc}" title="Click to edit — ping target">${esc(addr || '— click to set')}</td>
        <td class="text-sm text-dim">${ago}</td>
        <td class="text-11 ${txtColor(lastDownColor)}">${lastDown}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';
  }

  // Manual check button
  html += `<div class="mt-16">
    <button data-action="runHeartbeatCheck" class="btn btn-primary btn-md">Run Heartbeat Check</button>
    <span id="hb-check-result" class="ml-12 text-md text-dim"></span>
  </div>`;

  el.innerHTML = html;

}

let _hbEl = null;
export function _setTrendDays(d) {
  _trendDays = d;
  if (_hbEl) renderHeartbeat(_hbEl);
}

export function sortHeartbeat(col) {
  if (_hbSortCol === col) _hbSortAsc = !_hbSortAsc;
  else { _hbSortCol = col; _hbSortAsc = col === 'hostname'; }
  window.refreshView();
}

export async function editCheckAddress(nodeId, current) {
  const val = prompt('Check address (IP or hostname for ping):', current);
  if (val === null) return;
  await fetch(`/api/v1/heartbeat/nodes/${nodeId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ check_address: val || null }),
  });
  window.loadView();
}

export async function runHeartbeatCheck() {
  const span = document.getElementById('hb-check-result');
  if (span) span.textContent = 'Checking...';
  try {
    const res = await fetch('/api/v1/heartbeat/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const d = await res.json();
    const newlyDown = d.newly_down?.length
      ? ` — newly down: ${d.newly_down.map(h => esc(h)).join(', ')}`
      : '';
    if (span) span.innerHTML = `Checked <strong>${esc(d.checked)}</strong> nodes — <span class="text-green">${esc(d.up)} up</span>, <span class="text-red">${esc(d.down)} down</span>${_h(newlyDown)}`;
    // Refresh view after check
    setTimeout(() => window.loadView(), 1500);
  } catch (e) {
    if (span) span.textContent = `Error: ${e.message}`;
  }
}
