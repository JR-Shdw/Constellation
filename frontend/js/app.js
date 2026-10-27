// DO NOT REMOVE: SPDX header + copyright are part of the Apache-2.0 license terms.
// Stripping or rewriting these notices on redistribution is a license violation.
// Project: Constellation · Author: shdw <contact@resurgamus.com> · License: Apache-2.0
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
// CMDB Router + Init
import { api, esc } from './api.js';
import { renderDashboard } from './views/dashboard.js';
import { renderHeartbeat, runHeartbeatCheck, editCheckAddress, sortHeartbeat, _setTrendDays } from './views/heartbeat.js';
import { renderNodes, sortNodes, _exportNodes, nodesSearch } from './views/nodes.js';
import { renderPackages, sortPackages, toggleUpgradeFilter } from './views/packages.js';
import { renderContainers, sortContainers, containersSearch } from './views/containers.js';
import { renderExposure, editExposure, saveExposure, toggleFlag, _expSort, expFilterExp } from './views/exposure.js';
import { renderCVEs, cleanupPreview, cleanupExec, cleanupExecSelected, cleanupAutoResolve, cleanupPurgeOrphans, cleanupPurgeOrphansConfirm, cleanupPurgeOrphansCancel, cleanupRescan, _clToggleAll, _clUpdateCount, toggleTriage, setCveGroup, sortCves, _exportCves, _intelSort } from './views/cves.js';
import { renderRepositories, showAddPkgRepoForm, submitPkgRepo, editPkgRepo, togglePkgRepo, deletePkgRepo, runCheckUpdates, repositoriesSearch } from './views/repositories.js';
import { renderCrepositories, showAddRepoForm, submitAddRepo, patchRepo, checkOneRepo, deleteRepo, checkAllRepos, editRepoField, repoSort, repoSearch, repoFilterExposure, repoFilterRegistry } from './views/crepositories.js';
import { renderUpdates, _updSort, _updFilter, updatesSearch } from './views/updates.js';
import { renderSecrets, patchSecret, sortSecrets, filterSecretsStatus, filterSecretsSev, filterSecretsSearch } from './views/secrets.js';
import { renderBackups, backupSort, backupToggle, backupToggleAll, backupDeleteSelected, backupAssignNode, backupShowNodePicker, _exportBackup, backupsSearch } from './views/backups.js';
import { renderMisconf, patchMisconf, sortMisconf, filterMisconfStatus } from './views/misconf.js';
import { renderCompliance, sortCompliance, filterComplianceEnv, filterComplianceHost, _exportCompliance } from './views/compliance.js';
import { renderAutomation, showAddPolicyForm, submitPolicy, togglePolicy, deletePolicy, approveLog, skipLog, submitPriorityRules, activatePriorityRules, automationSearch } from './views/automation.js';
import { showIncident, submitIncident, updateIncident, commentIncident, _showIncForm, _applyIncFilters } from './views/incidents.js';
import { renderScheduler, showAddJobForm, submitSchedulerJob, triggerJob, toggleSchedulerJob, deleteSchedulerJob, editSchedulerJob, saveSchedulerJob, schedulerSearch } from './views/scheduler.js';
import { renderSettings, setThreshold, saveSettings, showAddWebhookForm, submitWebhook, testWebhook, deleteWebhook, toggleFeature, resyncWazuh, resyncOpencve, resetCve, saveSsoGroups, addSsoRow, removeSsoRow, checkVault, discoverVault, bootstrapVault, itsmCreate, itsmTest, itsmDelete, cveFeedAdd, cveFeedFetch, cveFeedToggle, cveFeedDelete, cveFeedAutoFetchSet, cveFeedAutoFetchClear } from './views/settings.js';
import { renderPipelines, addCicdServer, testCicdServer, deleteCicdServer, syncWorkers, pipelinesSearch } from './views/pipelines.js';
import { renderTokens, createToken, revokeToken, activateToken, regenerateToken, deleteToken, revokeAllNodeTokens, deleteExpiredTokens, tokensSearch } from './views/tokens.js';
import { renderHistory, _historyTab, viewArchive, downloadArchive, deleteArchive, compactAudit, exportAuditJson, exportAuditCsv, historySearch } from './views/history.js';
import { renderVersioning, syncCicd } from './views/versioning.js';
import { renderDeployments, createDeployment, submitDeployment, approveDeployment, rejectDeployment, executeDeployment } from './views/deployments.js';
import { renderDelivery } from './views/delivery.js';
import { renderManagers, addManager, testManager, deleteManager, pullImage, showManagerImages } from './views/managers.js';
import { showNode } from './panels/node.js';
import { showCVEDetail, patchFinding, setCveWorkflow } from './panels/cve.js';
import { showPackageHosts } from './panels/package.js';
import { showImageHosts, deleteGhostImage } from './panels/image.js';
import { showOsNodes } from './panels/os.js';
import { showImpact } from './panels/impact.js';
import { initStarfield, initLoadingAnim, updateSparks } from './starfield.js';

// State (on window for view access)
window.currentView = 'dashboard';
window.currentPage = 1;
let searchTimeout = null;

// Action handlers (click delegation)
const _actions = {
  // Panels
  showNode, showCVEDetail, showImageHosts, showPackageHosts, showOsNodes, showImpact,
  deleteGhostImage,
  // Nodes
  sortNodes, _exportNodes,
  // Heartbeat
  sortHeartbeat, runHeartbeatCheck, editCheckAddress, _setTrendDays,
  // Packages
  sortPackages, toggleUpgradeFilter,
  // Containers
  sortContainers,
  // Exposure
  editExposure, saveExposure, toggleFlag, _expSort,
  // CVEs
  sortCves, setCveGroup, toggleTriage, _exportCves, _intelSort,
  cleanupPreview, cleanupExec, cleanupExecSelected, cleanupAutoResolve, cleanupPurgeOrphans, cleanupPurgeOrphansConfirm, cleanupPurgeOrphansCancel, cleanupRescan,
  // Package repositories
  showAddPkgRepoForm, submitPkgRepo, editPkgRepo, togglePkgRepo, deletePkgRepo, runCheckUpdates,
  // Container repositories
  showAddRepoForm, submitAddRepo, checkOneRepo, deleteRepo, checkAllRepos, editRepoField, repoSort,
  // Updates
  _updSort, _updFilter,
  // Secrets
  sortSecrets,
  // Misconf
  sortMisconf,
  // Compliance
  sortCompliance, _exportCompliance,
  // Backups
  backupSort, backupDeleteSelected, backupShowNodePicker, _exportBackup,
  // Automation
  showAddPolicyForm, submitPolicy, deletePolicy, approveLog, skipLog,
  submitPriorityRules, activatePriorityRules,
  // Incidents
  showIncident, submitIncident, updateIncident, commentIncident,
  _showIncForm, _applyIncFilters, _openIncidentsTab,
  // Settings
  setThreshold, saveSettings, showAddWebhookForm, submitWebhook, testWebhook, deleteWebhook,
  toggleFeature, resyncWazuh, resyncOpencve, resetCve, saveSsoGroups, addSsoRow, removeSsoRow, checkVault, discoverVault, bootstrapVault,
  itsmCreate, itsmTest, itsmDelete,
  cveFeedAdd, cveFeedFetch, cveFeedToggle, cveFeedDelete,
  cveFeedAutoFetchSet, cveFeedAutoFetchClear,
  // Pipelines
  addCicdServer, testCicdServer, deleteCicdServer, syncWorkers, syncCicd,
  // Tokens
  createToken, revokeToken, activateToken, regenerateToken, deleteToken,
  revokeAllNodeTokens, deleteExpiredTokens,
  // Deployments
  createDeployment, submitDeployment, approveDeployment, rejectDeployment, executeDeployment,
  // Managers
  addManager, testManager, deleteManager, pullImage, showManagerImages,
  // Scheduler
  showAddJobForm, submitSchedulerJob, triggerJob, toggleSchedulerJob,
  deleteSchedulerJob, editSchedulerJob, saveSchedulerJob,
  // History / Audit
  _historyTab, viewArchive, downloadArchive, deleteArchive,
  compactAudit, exportAuditJson, exportAuditCsv,
};

// Change handlers (select/checkbox/input delegation)
const _changes = {
  // Exposure
  expFilterExp,
  // CVEs
  setCveWorkflow,
  clToggleAll: (value) => _clToggleAll(value),
  clUpdateCount: () => _clUpdateCount(),
  opencveMatchedOnly: (value) => { window.opencveMatchedOnly = value; window.currentPage = 1; window.refreshView(); },
  // Automation
  togglePolicy: (id) => togglePolicy(id),
  // Secrets
  patchSecret, filterSecretsStatus, filterSecretsSev, filterSecretsSearch,
  // Misconf
  patchMisconf, filterMisconfStatus,
  // Compliance
  filterComplianceEnv, filterComplianceHost,
  // Container repositories
  patchRepo: (id, field, value) => patchRepo(id, field, value),
  patchRepoChecked: (id, field, value) => patchRepo(id, field, value),
  repoSearch, repoFilterExposure, repoFilterRegistry,
  // Per-view search bars (barre 2 — spécifique par vue, en plus de #filter-node)
  containersSearch, updatesSearch, nodesSearch, historySearch,
  backupsSearch, tokensSearch, schedulerSearch,
  automationSearch, repositoriesSearch, pipelinesSearch,
  // Backups
  backupToggle, backupToggleAll,
  backupAssignNode: (id, value) => backupAssignNode(id, value),
  // Findings panel
  patchFinding,
  // Node panel
  toggleCveNoise: (value) => {
    document.querySelectorAll('.cve-noise').forEach(r => { r.style.display = value ? 'none' : ''; });
    document.querySelectorAll('.cve-noise-count').forEach(s => { s.style.display = value ? '' : 'none'; });
  },
  // Settings: live label next to the resolved-CVE retention slider
  retentionCveDaysLabel: (value) => {
    const lbl = document.getElementById('s-retention-cve-days-display');
    if (lbl) lbl.textContent = value;
  },
  // Nodes
  setNodeEnv: async (id, value) => {
    await fetch(`/api/v1/nodes/${id}/environment`, {
      method: 'PUT', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({environment: value}),
    });
  },
};

// Tab group → window variable mapping
const _tabGroups = {
  settings: 'settingsTab', automation: 'automationTab', deploy: 'deployTab',
  cve: '_cveTab', pipelines: 'pipelinesTab', tokens: 'tokensTab',
  manager: 'managerTab', scheduler: 'schedulerTab', delivery: 'deliveryTab',
  heartbeat: 'heartbeatTab', dashboard: 'dashboardTab',
};

// Click delegation
document.body.addEventListener('click', (e) => {
  const el = e.target.closest('[data-action]');
  if (!el) return;
  if ('stop' in el.dataset) e.stopPropagation();

  const action = el.dataset.action;

  // Built-in actions
  if (action === 'setTab') {
    const group = el.dataset.group;
    const tab = el.dataset.tab;
    const key = _tabGroups[group];
    if (key) { window[key] = tab; loadView(); }
    return;
  }
  if (action === 'goPage') {
    window.currentPage = parseInt(el.dataset.page);
    window.refreshView();
    return;
  }
  if (action === 'hideEl') {
    const target = document.getElementById(el.dataset.target);
    if (target) target.style.display = 'none';
    return;
  }
  if (action === 'closeDetail') { closeDetail(); return; }
  if (action === 'toggleFullscreen') { toggleFullscreen(); return; }
  if (action === 'toggleSidebar') { toggleSidebar(); return; }
  if (action === 'toggleMobileMenu') { toggleMobileMenu(); return; }
  if (action === 'toggleMobileNavMode') { toggleMobileNavMode(); return; }
  if (action === 'toggleNavGroup') { toggleNavGroup(el.dataset.group); return; }

  const handler = _actions[action];
  if (!handler) return;

  const { id, value, field, flag } = el.dataset;

  // Dispatch based on available data attributes; `e` is forwarded last
  // so handlers that need modifiers (e.g. shift+click) can read e.shiftKey.
  if (flag !== undefined) return handler(id, flag, value === 'true', el, e);
  if (field !== undefined) return handler(id, field, value, el, e);
  if (value !== undefined) return handler(id, value, e);
  if (id !== undefined) return handler(id, e);
  return handler(e);
});

// Change + Input delegation
function _handleChange(e) {
  const el = e.target.closest('[data-change]');
  if (!el) return;

  const isText = el.tagName === 'INPUT' && el.type !== 'checkbox';
  // Text inputs: handle on 'input' for live update, skip 'change'
  if (isText && e.type === 'change') return;
  if (!isText && e.type === 'input') return;

  const action = el.dataset.change;
  const handler = _changes[action];
  if (!handler) return;

  const value = el.type === 'checkbox' ? el.checked : el.value;
  const { id, field, cve, node } = el.dataset;

  // Special: setCveWorkflow from select (cve panel)
  if (cve !== undefined) handler(cve, node, value, el);
  // Field-based: patchRepo, patchMisconf, patchSecret, patchFinding
  else if (field !== undefined) handler(id, field, value);
  // ID-based: backupToggle, backupAssignNode
  else if (id !== undefined) handler(id, value);
  // Value-only: filter functions
  else handler(value);

  // Update select color to match selected option
  if (el.tagName === 'SELECT') {
    const opt = el.options[el.selectedIndex];
    if (opt && opt.style.color) el.style.color = opt.style.color;
  }
}
document.body.addEventListener('change', _handleChange);
document.body.addEventListener('input', _handleChange);

// Blur delegation (textarea onblur)
document.body.addEventListener('blur', (e) => {
  const el = e.target.closest('[data-blur]');
  if (!el) return;
  const action = el.dataset.blur;
  if (action === 'setCveWorkflow') {
    const selEl = document.getElementById(el.dataset.sel);
    const status = selEl ? selEl.value : '';
    setCveWorkflow(el.dataset.cve, el.dataset.node, status, el);
  }
}, true); // capture phase for blur

// Sidebar
function toggleSidebar() {
  const sb = document.getElementById('sidebar');
  const main = document.querySelector('.main');
  sb.classList.toggle('collapsed');
  main.style.marginLeft = sb.classList.contains('collapsed') ? '48px' : '175px';
  localStorage.setItem('sidebar-collapsed', sb.classList.contains('collapsed'));
}

if (localStorage.getItem('sidebar-collapsed') === 'true') {
  document.getElementById('sidebar').classList.add('collapsed');
  document.querySelector('.main').style.marginLeft = '48px';
}

// Mobile menu
function toggleMobileMenu() {
  const sb = document.getElementById('sidebar');
  sb.classList.toggle('mobile-open');
}

function closeMobileMenu() {
  document.getElementById('sidebar').classList.remove('mobile-open');
}

// Backdrop click closes menu
document.getElementById('sidebar-backdrop').addEventListener('click', closeMobileMenu);

// Close menu on nav click (mobile — only in dropdown mode)
document.querySelectorAll('.sidebar nav a').forEach(a => {
  a.addEventListener('click', () => {
    if (window.innerWidth <= 768 && document.body.dataset.mobileNav !== 'icons') closeMobileMenu();
  });
});

// Mobile nav mode: icons bar vs dropdown overlay
function toggleMobileNavMode() {
  const mode = document.body.dataset.mobileNav === 'icons' ? 'dropdown' : 'icons';
  document.body.dataset.mobileNav = mode;
  localStorage.setItem('mobile-nav-mode', mode);
  closeMobileMenu();
}

function initMobileNavMode() {
  const saved = localStorage.getItem('mobile-nav-mode') || 'dropdown';
  document.body.dataset.mobileNav = saved;
}

// Swipe to close detail panel
(function initSwipe() {
  const panel = document.getElementById('detail');
  let startX = 0, startY = 0, tracking = false;

  panel.addEventListener('touchstart', (e) => {
    startX = e.touches[0].clientX;
    startY = e.touches[0].clientY;
    tracking = true;
  }, { passive: true });

  panel.addEventListener('touchend', (e) => {
    if (!tracking) return;
    tracking = false;
    const dx = e.changedTouches[0].clientX - startX;
    const dy = Math.abs(e.changedTouches[0].clientY - startY);
    // Swipe right > 80px and mostly horizontal → close
    if (dx > 80 && dy < 60) closeDetail();
  }, { passive: true });
})();

// Filters
function getFilterType() { return document.getElementById('filter-type').value; }
function getFilterSeverity() { return document.getElementById('filter-severity').value; }
function getFilterNode() { return document.getElementById('filter-node').value; }
function getFilterPackage() { return document.getElementById('filter-package').value; }
function getFilterTable() { return document.getElementById('filter-table').value; }
function showFilters(show) {
  document.getElementById('filters').style.display = show ? 'flex' : 'none';
}

// Expose filter getters for views
window.getFilterType = getFilterType;
window.getFilterSeverity = getFilterSeverity;
window.getFilterNode = getFilterNode;
window.getFilterPackage = getFilterPackage;
window.getFilterTable = getFilterTable;

function getFilterHostname() { return document.getElementById('filter-node').value.trim(); }
window.getFilterHostname = getFilterHostname;

// Sidebar accordion groups
const _navGroupParent = {
  packages: 'packages', updates: 'packages', repositories: 'packages',
  containers: 'containers', crepositories: 'containers',
};

function _closeNavPopovers() {
  document.querySelectorAll('.nav-group.popover-open').forEach(n => n.classList.remove('popover-open'));
}

function _navGroupOpen(group) {
  return localStorage.getItem(`nav-group-open-${group}`) === 'true';
}

function _setNavGroupOpen(group, open) {
  const node = document.getElementById(`nav-group-${group}`);
  if (node) node.classList.toggle('open', open);
  localStorage.setItem(`nav-group-open-${group}`, open ? 'true' : 'false');
}

function toggleNavGroup(group) {
  // Mobile icons mode: each group toggles independently as an inline accordion.
  if (document.body.dataset.mobileNav === 'icons' && window.matchMedia('(max-width: 768px)').matches) {
    const node = document.getElementById(`nav-group-${group}`);
    if (node) node.classList.toggle('popover-open');
    return;
  }
  _setNavGroupOpen(group, !_navGroupOpen(group));
}

function initNavGroups() {
  document.querySelectorAll('.nav-group').forEach(g => {
    const group = g.id.replace(/^nav-group-/, '');
    g.classList.toggle('open', _navGroupOpen(group));
  });
}

function _markActiveGroup(view) {
  const parent = _navGroupParent[view];
  document.querySelectorAll('.nav-group-header').forEach(h => {
    h.classList.toggle('has-active', h.dataset.group === parent);
  });
  // Auto-open the parent group when a child view is active
  if (parent) _setNavGroupOpen(parent, true);
}

// Navigation
function navigate(view) {
  window.currentView = view;
  window.currentPage = 1;
  document.querySelectorAll('.sidebar nav a').forEach(a => {
    a.classList.toggle('active', a.dataset.view === view);
  });
  _markActiveGroup(view);
  window.location.hash = view;
  loadView();
}
window.navigate = navigate;

document.querySelectorAll('.sidebar nav a').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    navigate(a.dataset.view);
  });
});

// Search
async function doSearch(q) {
  const el = document.getElementById('content');
  el.innerHTML = '<div class="loading">Searching...</div>';
  try {
    const d = await api(`/search?q=${encodeURIComponent(q)}`);
    let html = '';
    if (d.nodes.length) {
      html += '<h3 class="section-h">Nodes</h3>';
      html += '<div class="table-wrap"><table><tr><th>Hostname</th><th>Type</th><th>OS</th></tr>';
      for (const n of d.nodes) {
        html += `<tr><td class="clickable" data-action="showNode" data-id="${n.id}">${n.hostname}</td><td>${n.type}</td><td>${n.os || ''}</td></tr>`;
      }
      html += '</table></div>';
    }
    if (d.packages.length) {
      html += '<h3 class="section-h">Packages</h3>';
      html += '<div class="table-wrap"><table><tr><th>Package</th><th>Version</th><th>Node</th></tr>';
      for (const p of d.packages) {
        html += `<tr><td>${p.name}</td><td>${p.version}</td><td class="clickable" data-action="showNode" data-id="${p.node_id}">${p.hostname}</td></tr>`;
      }
      html += '</table></div>';
    }
    if (d.containers.length) {
      html += '<h3 class="section-h">Containers</h3>';
      html += '<div class="table-wrap"><table><tr><th>Name</th><th>Image</th><th>Node</th></tr>';
      for (const c of d.containers) {
        html += `<tr><td>${c.name}</td><td>${c.image}</td><td class="clickable" data-action="showNode" data-id="${c.node_id}">${c.hostname}</td></tr>`;
      }
      html += '</table></div>';
    }
    if (d.cves.length) {
      html += '<h3 class="section-h">CVEs</h3>';
      html += '<div class="table-wrap"><table><tr><th>CVE</th><th>Severity</th><th>Target</th><th>Node</th></tr>';
      for (const v of d.cves) {
        html += `<tr><td class="clickable" data-action="showCVEDetail" data-id="${v.cve_id}">${v.cve_id}</td><td><span class="badge ${v.severity}">${v.severity}</span></td><td>${v.target}</td><td class="clickable" data-action="showNode" data-id="${v.node_id}">${v.hostname}</td></tr>`;
      }
      html += '</table></div>';
    }
    if (!html) html = '<div class="empty">No results</div>';
    el.innerHTML = html;
  } catch(e) {
    el.innerHTML = `<div class="empty">Search error: ${esc(e.message)}</div>`;
  }
}

document.getElementById('search').addEventListener('input', e => {
  clearTimeout(searchTimeout);
  const q = e.target.value.trim();
  if (['packages', 'containers', 'cves'].includes(window.currentView)) {
    searchTimeout = setTimeout(() => { window.currentPage = 1; loadView(); }, 300);
    return;
  }
  if (q.length < 2) { loadView(); return; }
  searchTimeout = setTimeout(() => doSearch(q), 300);
});

document.getElementById('search').addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    e.preventDefault();
    const q = e.target.value.trim();
    if (q.length >= 2) doSearch(q);
  }
});

document.getElementById('search-version').addEventListener('input', () => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => { window.currentPage = 1; loadView(); }, 300);
});

// Filter change handlers
['filter-type', 'filter-severity', 'filter-target-type', 'filter-source',
 'filter-kev', 'filter-workflow', 'filter-sort'].forEach(id => {
  document.getElementById(id).addEventListener('change', () => { window.currentPage = 1; loadView(); });
});
// Host search: debounced input
document.getElementById('filter-node').addEventListener('input', () => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => { window.currentPage = 1; loadView(); }, 300);
});
// Package filter: shared between packages + updates views
document.getElementById('filter-package').addEventListener('input', () => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => { window.currentPage = 1; loadView(); }, 300);
});
// Table filter: per-view, client-side, reset between views (see loadView)
document.getElementById('filter-table').addEventListener('input', () => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => { loadView(); }, 200);
});

// Detail panel controls
function closeDetail() {
  const panel = document.getElementById('detail');
  panel.classList.remove('open', 'side-panel', 'fullscreen');
}

function toggleFullscreen() {
  const panel = document.getElementById('detail');
  panel.classList.toggle('fullscreen');
}

document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDetail(); });

// Load View (router)
async function loadView() {
  const el = document.getElementById('content');
  initLoadingAnim(el);

  const needsFilters = ['nodes', 'cves', 'packages', 'containers', 'backups', 'misconf', 'updates', 'exposure', 'secrets', 'history', 'tokens'].includes(window.currentView);
  showFilters(needsFilters);

  const cveOnly = window.currentView === 'cves';
  document.getElementById('filter-target-type').style.display = cveOnly ? '' : 'none';
  document.getElementById('filter-source').style.display = cveOnly ? '' : 'none';
  document.getElementById('filter-kev').style.display = cveOnly ? '' : 'none';
  document.getElementById('filter-workflow').style.display = cveOnly ? '' : 'none';
  document.getElementById('filter-sort').style.display = cveOnly ? '' : 'none';
  const nodeFilter = ['nodes', 'cves', 'packages', 'containers', 'backups', 'misconf', 'updates', 'exposure', 'secrets', 'history', 'tokens'].includes(window.currentView);
  document.getElementById('filter-node').style.display = nodeFilter ? '' : 'none';
  const pkgFilter = ['packages', 'updates'].includes(window.currentView);
  document.getElementById('filter-package').style.display = pkgFilter ? '' : 'none';
  const tableFilter = ['misconf', 'exposure'].includes(window.currentView);
  const fTable = document.getElementById('filter-table');
  fTable.style.display = tableFilter ? '' : 'none';
  // Per-view filter-table is NOT shared between views — clear on view change
  if (window._lastView !== window.currentView) {
    fTable.value = '';
    window._lastView = window.currentView;
  }
  document.getElementById('filter-type').style.display = window.currentView === 'nodes' ? '' : 'none';
  const sevEl = document.getElementById('filter-severity');
  sevEl.style.display = ['cves', 'nodes', 'misconf', 'updates'].includes(window.currentView) ? '' : 'none';
  if (window.currentView === 'nodes') {
    const envOpts = [['','All env'],['production','prod'],['staging','staging'],['development','dev'],['lab','lab']];
    if (sevEl.options[1]?.value !== 'production') {
      const cur = sevEl.value;
      sevEl.innerHTML = envOpts.map(([v,l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join('');
      sevEl.value = cur;
    }
  } else if (sevEl.options[1]?.value === 'production') {
    const sevOpts = [['','All severities'],['critical','Critical'],['high','High'],['medium','Medium'],['low','Low']];
    sevEl.innerHTML = sevOpts.map(([v,l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join('');
  }

  const needsVersion = ['packages', 'containers'].includes(window.currentView);
  document.getElementById('search-version').style.display = needsVersion ? '' : 'none';

  try {
    switch (window.currentView) {
      case 'dashboard': await renderDashboard(el); break;
      case 'heartbeat': await renderHeartbeat(el); break;
      case 'nodes': await renderNodes(el); break;
      case 'packages': await renderPackages(el); break;
      case 'containers': await renderContainers(el); break;
      case 'exposure': await renderExposure(el); break;
      case 'cves': await renderCVEs(el); break;
      case 'repositories': await renderRepositories(el); break;
      case 'crepositories': await renderCrepositories(el); break;
      case 'updates': await renderUpdates(el); break;
      case 'secrets': await renderSecrets(el); break;
      case 'backups': await renderBackups(el); break;
      case 'misconf': await renderMisconf(el); break;
      case 'compliance': await renderCompliance(el); break;
      case 'automation': await renderAutomation(el); break;
      case 'pipelines': await renderPipelines(el); break;
      case 'versioning': await renderVersioning(el); break;
      case 'deployments': await renderDeployments(el); break;
      case 'delivery': await renderDelivery(el); break;
      case 'managers': await renderManagers(el); break;
      case 'tokens': await renderTokens(el); break;
      case 'scheduler': await renderScheduler(el); break;
      case 'history': await renderHistory(el); break;
      case 'settings': await renderSettings(el); break;
    }
  } catch(e) {
    el.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}
window.loadView = loadView;

// Keyboard navigation
// After each render, make .clickable elements focusable + Enter/Space trigger click
function enableKeyboardNav(root) {
  root.querySelectorAll('.clickable:not([tabindex])').forEach(el => {
    el.setAttribute('tabindex', '0');
    el.setAttribute('role', 'button');
  });
}

document.addEventListener('keydown', e => {
  if ((e.key === 'Enter' || e.key === ' ') && e.target.classList.contains('clickable')) {
    e.preventDefault();
    e.target.click();
  }
});

// Patch loadView to enable keyboard nav after render
const _origLoadView = loadView;
async function loadViewWithKbd() {
  await _origLoadView();
  enableKeyboardNav(document.getElementById('content'));
}
window.loadView = loadViewWithKbd;

// Smooth refresh (sort/filter — no loading anim)
async function refreshView() {
  const el = document.getElementById('content');
  const scrollY = window.scrollY;

  // Dim existing tbody instantly
  el.querySelectorAll('tbody').forEach(tb => tb.classList.add('refreshing'));

  // Render into temp element
  const tmp = document.createElement('div');
  try {
    switch (window.currentView) {
      case 'dashboard': await renderDashboard(tmp); break;
      case 'heartbeat': await renderHeartbeat(tmp); break;
      case 'nodes': await renderNodes(tmp); break;
      case 'packages': await renderPackages(tmp); break;
      case 'containers': await renderContainers(tmp); break;
      case 'exposure': await renderExposure(tmp); break;
      case 'cves': await renderCVEs(tmp); break;
      case 'repositories': await renderRepositories(tmp); break;
      case 'crepositories': await renderCrepositories(tmp); break;
      case 'updates': await renderUpdates(tmp); break;
      case 'secrets': await renderSecrets(tmp); break;
      case 'backups': await renderBackups(tmp); break;
      case 'misconf': await renderMisconf(tmp); break;
      case 'compliance': await renderCompliance(tmp); break;
      case 'automation': await renderAutomation(tmp); break;
      case 'pipelines': await renderPipelines(tmp); break;
      case 'versioning': await renderVersioning(tmp); break;
      case 'deployments': await renderDeployments(tmp); break;
      case 'delivery': await renderDelivery(tmp); break;
      case 'managers': await renderManagers(tmp); break;
      case 'tokens': await renderTokens(tmp); break;
      case 'scheduler': await renderScheduler(tmp); break;
      case 'history': await renderHistory(tmp); break;
      case 'settings': await renderSettings(tmp); break;
    }
  } catch(e) {
    el.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
    return;
  }

  // Swap only thead (arrows) + tbody (data) + pagination — everything else stays
  const oldTbodies = el.querySelectorAll('tbody');
  const newTbodies = tmp.querySelectorAll('tbody');
  const oldTheads = el.querySelectorAll('thead');
  const newTheads = tmp.querySelectorAll('thead');

  if (oldTbodies.length && oldTbodies.length === newTbodies.length) {
    oldTheads.forEach((old, i) => { if (newTheads[i]) old.innerHTML = newTheads[i].innerHTML; });
    oldTbodies.forEach((old, i) => { old.innerHTML = newTbodies[i].innerHTML; old.classList.remove('refreshing'); });
    const oldPag = el.querySelector('.pagination');
    const newPag = tmp.querySelector('.pagination');
    if (oldPag && newPag) oldPag.innerHTML = newPag.innerHTML;
    else if (!oldPag && newPag) el.appendChild(newPag);
    else if (oldPag && !newPag) oldPag.remove();
  } else {
    el.innerHTML = tmp.innerHTML;
  }

  enableKeyboardNav(el);
  window.scrollTo(0, scrollY);
}
window.refreshView = refreshView;

// Also enable on detail panel opens
const _detailObserver = new MutationObserver(() => {
  const panel = document.getElementById('detail');
  if (panel.classList.contains('open')) enableKeyboardNav(panel);
});
_detailObserver.observe(document.getElementById('detail'), { childList: true, subtree: true });

// Service Worker (PWA install banner)
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}

// Dashboard: open Automation → Incidents tab
function _openIncidentsTab() {
  window.automationTab = 'incidents';
  window.currentView = 'automation';
  navigate('automation');
}

// Nav badges (red dot when something critical needs attention)
function _setBadge(id, on) {
  const el = document.getElementById(id);
  if (el) el.hidden = !on;
}

async function refreshNavBadges() {
  const [inc, stats, cicd, dep] = await Promise.all([
    api('/incidents/stats').catch(() => null),
    api('/stats').catch(() => null),
    api('/cicd/stats').catch(() => null),
    api('/deployments/stats').catch(() => null),
  ]);

  // Automation: P1 incidents
  const p1 = (inc && inc.by_priority && inc.by_priority.P1) || 0;
  _setBadge('nav-badge-automation', p1 > 0);

  // Packages group: critical host CVEs surface on the Updates child
  const hostCrit = (stats && stats.cves_host_critical) || 0;
  _setBadge('nav-badge-group-packages', hostCrit > 0);
  _setBadge('nav-badge-updates', hostCrit > 0);

  // Containers group: critical container CVEs surface on the All containers child
  const ctCrit = (stats && stats.cves_container_critical) || 0;
  _setBadge('nav-badge-group-containers', ctCrit > 0);
  _setBadge('nav-badge-containers', ctCrit > 0);

  // Delivery: failed pipelines (30d) OR deployments awaiting action
  const fails = (cicd && cicd.failure_30d) || 0;
  const active = (dep && dep.active) || 0;
  _setBadge('nav-badge-delivery', fails > 0 || active > 0);
}

// Init
initStarfield();
updateSparks();
setInterval(updateSparks, 60000);
refreshNavBadges();
setInterval(refreshNavBadges, 120000);
initMobileNavMode();
initNavGroups();
const hash = window.location.hash.slice(1);
const _deliveryAliases = { versioning: 'versioning', pipelines: 'pipelines', deployments: 'deployments' };
if (hash === 'opencve') { window._cveTab = 'intelligence'; window.currentView = 'cves'; navigate('cves'); }
else if (_deliveryAliases[hash]) { window.deliveryTab = _deliveryAliases[hash]; window.currentView = 'delivery'; navigate('delivery'); }
else if (hash) { window.currentView = hash; navigate(hash); }
else { _markActiveGroup(window.currentView); loadView(); }
