// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, esc, tabBar, timeAgo, txtColor } from '../api.js';

function statusBadge(s) {
  const c = {connected: 'green', error: 'red', offline: 'text-dim'}[s] || 'text-dim';
  return `<span class="${txtColor(c)} text-bold">${esc(s)}</span>`;
}

function formatSize(bytes) {
  if (!bytes) return '0 B';
  const u = ['B', 'KiB', 'MiB', 'GiB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + u[i];
}

export async function renderManagers(el) {
  const tab = window.managerTab || 'list';

  let html = tabBar(
    [['list', 'Managers'], ['add', 'Add']],
    tab, 'manager'
  );

  if (tab === 'list') {
    const d = await api('/managers');
    const items = d.items || [];

    const connected = items.filter(m => m.status === 'connected').length;
    const errored = items.filter(m => m.status === 'error').length;
    const offline = items.filter(m => m.status === 'offline').length;

    html += `<div class="stats-grid mb-16">
      <div class="stat-card"><div class="label">Total</div><div class="value">${items.length}</div></div>
      <div class="stat-card"><div class="label">Connected</div><div class="value green">${connected}</div></div>
      <div class="stat-card"><div class="label">Error</div><div class="value red">${errored}</div></div>
      <div class="stat-card"><div class="label">Offline</div><div class="value text-dim">${offline}</div></div>
    </div>`;

    html += `<div class="table-wrap"><table>
      <thead><tr><th>Name</th><th>Type</th><th>URL</th><th>Endpoint</th><th>Status</th><th>Last check</th><th>Actions</th></tr></thead><tbody>`;
    if (!items.length) {
      html += '<tr><td colspan="7" class="empty">No managers — add a Portainer instance</td></tr>';
    }
    for (const m of items) {
      html += `<tr>
        <td>${esc(m.name)}</td>
        <td class="text-sm">${esc(m.manager_type)}</td>
        <td class="text-sm">${esc(m.url)}</td>
        <td class="text-center">${m.endpoint_id || 1}</td>
        <td>${statusBadge(m.status)}</td>
        <td>${m.last_check ? timeAgo(m.last_check) : 'never'}</td>
        <td>
          <button class="btn btn-bg" data-action="testManager" data-id="${m.id}">Test</button>
          <button class="btn btn-bg" data-action="showManagerImages" data-id="${m.id}">Images</button>
          <button class="btn btn-danger" data-action="deleteManager" data-id="${m.id}">Del</button>
        </td>
      </tr>`;
    }
    html += '</tbody></table></div>';

    // Images panel (populated by showManagerImages)
    html += '<div id="manager-images"></div>';
  }

  if (tab === 'add') {
    html += `<div class="card-form-500">
      <h3 class="mb-12 text-base text-dim">Register manager</h3>
      <div class="grid gap-sm">
        <input id="mgr-name" class="form-input" placeholder="Name">
        <select id="mgr-type" class="form-input">
          <option value="portainer">Portainer</option>
          <option value="docker">Docker</option>
        </select>
        <input id="mgr-url" class="form-input" placeholder="URL (https://portainer.example.com)">
        <input id="mgr-token" class="form-input" placeholder="API token" type="password">
        <input id="mgr-endpoint" class="form-input" placeholder="Endpoint ID (default: 1)" value="1">
        <label class="text-sm text-dim">
          <input type="checkbox" id="mgr-tls-skip"> Skip TLS verify
        </label>
        <button class="btn btn-primary p-8" data-action="addManager">Add manager</button>
      </div>
    </div>`;
  }

  el.innerHTML = html;
}

export async function addManager() {
  const name = document.getElementById('mgr-name').value;
  const manager_type = document.getElementById('mgr-type').value;
  const url = document.getElementById('mgr-url').value;
  const token = document.getElementById('mgr-token').value;
  const endpoint_id = parseInt(document.getElementById('mgr-endpoint').value) || 1;
  const tls_skip_verify = document.getElementById('mgr-tls-skip').checked;

  if (!name || !url) return alert('Name and URL required');

  await fetch(API + '/managers', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      name, manager_type, url, token, endpoint_id, tls_skip_verify,
    }),
  });
  window.managerTab = 'list';
  window.refreshView();
}

export async function testManager(id) {
  try {
    const r = await fetch(API + `/managers/${id}/test`, {method: 'POST'});
    if (r.ok) {
      alert('Connection OK');
    } else {
      const d = await r.json();
      alert('Connection failed: ' + (d.detail || r.statusText));
    }
  } catch (e) {
    alert('Error: ' + e.message);
  }
  window.refreshView();
}

export async function deleteManager(id) {
  if (!confirm('Delete this manager?')) return;
  await fetch(API + `/managers/${id}`, {method: 'DELETE'});
  window.refreshView();
}

export async function pullImage(id) {
  const image = prompt('Image name (e.g. nginx)');
  if (!image) return;
  const tag = prompt('Tag (default: latest)', 'latest') || 'latest';
  try {
    const r = await fetch(API + `/managers/${id}/pull`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({image, tag}),
    });
    if (r.ok) {
      alert(`Pulled ${image}:${tag}`);
      showManagerImages(id);
    } else {
      const d = await r.json();
      alert('Pull failed: ' + (d.detail || r.statusText));
    }
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

export async function showManagerImages(id) {
  const panel = document.getElementById('manager-images');
  if (!panel) return;
  panel.innerHTML = '<div class="loading">Loading images...</div>';
  try {
    const d = await api(`/managers/${id}/images`);
    const items = d.items || [];
    let html = `<h3 class="section-h-lg">Images on manager</h3>`;
    html += `<button class="btn btn-primary mb-8" data-action="pullImage" data-id="${id}">Pull image</button>`;
    html += `<div class="table-wrap"><table>
      <tr><th>ID</th><th>Tags</th><th>Size</th></tr>`;
    if (!items.length) {
      html += '<tr><td colspan="3" class="empty">No images</td></tr>';
    }
    for (const img of items) {
      const tags = (img.tags || []).map(t => esc(t)).join(', ') || '<none>';
      html += `<tr>
        <td class="text-xs font-mono">${esc(img.id)}</td>
        <td class="text-sm">${tags}</td>
        <td class="text-sm">${formatSize(img.size)}</td>
      </tr>`;
    }
    html += '</table></div>';
    panel.innerHTML = html;
  } catch (e) {
    panel.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}
