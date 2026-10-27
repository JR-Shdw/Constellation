// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { API, api, clearApiCache, esc, _h, tabBar, txtColor } from '../api.js';
import { blackholeInit, blackholeSetState, blackholeDestroy } from '../blackhole.js';
import { startLoadingPx } from '../starfield.js';

export async function renderSettings(el) {
  const tab = window.settingsTab || 'alerts';

  try {
    const [s, wh, feeds, autoFetch] = await Promise.all([
      api('/settings/alerts'),
      api('/settings/webhooks'),
      tab === 'cve'
        ? api('/cve-feeds').catch(() => ({ items: [] }))
        : Promise.resolve({ items: [] }),
      tab === 'cve'
        ? api('/cve-feeds/auto-fetch').catch(() => ({ scheduled: false }))
        : Promise.resolve({ scheduled: false }),
    ]);
    const webhooks = wh.items || [];
    const cveFeeds = feeds.items || [];
    const thresholds = ['critical', 'high', 'medium', 'low'];

    let html = tabBar(
      [['alerts', 'Alerts'], ['cve', 'CVE'], ['cicd', 'CI/CD'], ['vault', 'Vault'], ['sso', 'SSO / O.U.'], ['features', 'Features'], ['itsm', 'ITSM'], ['plugins', 'Plugins'], ['dev', 'Dev']],
      tab, 'settings'
    );

    // Tab: Alert Settings
    if (tab === 'alerts') {
      html += `
      <div class="detail-section">
        <h3>CVE Alert Threshold</h3>
        <p class="text-dim mb-12">
          Alerts are sent when a CVE at or above this severity is ingested.
        </p>
        <div class="flex gap-8 mb-20">
          ${thresholds.map(t => `
            <button data-action="setThreshold" data-value="${t}" class="badge ${t} threshold-btn${s.cve_severity_threshold === t ? ' active' : ''}">
              ${t}
            </button>
          `).join('')}
        </div>
      </div>

      <div class="detail-section">
        <h3 class="flex items-center gap-lg">
          Matrix Notifications
          <label class="text-md flex items-center gap-sm cursor-pointer">
            <input type="checkbox" id="s-matrix-enabled" ${s.matrix_enabled !== 'false' ? 'checked' : ''}
              class="f-accent">
            Enabled
          </label>
        </h3>
        <div class="detail-grid gap-row-col">
          <span class="k">Server URL</span>
          <input id="s-matrix-url" value="${esc(s.matrix_url || '')}" class="f-iinput">
          <span class="k">Access Token</span>
          <input id="s-matrix-token" value="${esc(s.matrix_token || '')}" type="password" class="f-iinput">
          <span class="k">CVE Room ID</span>
          <input id="s-matrix-room-cve" value="${esc(s.matrix_room_cve || '')}" class="f-iinput">
          <span class="k">Security Room ID</span>
          <input id="s-matrix-room-sec" value="${esc(s.matrix_room_security || '')}" class="f-iinput">
          <span class="k">CI/CD Room ID</span>
          <input id="s-matrix-room-cicd" value="${esc(s.matrix_room_cicd || '')}" class="f-iinput">
          <span class="k">Backup Room ID</span>
          <input id="s-matrix-room-backup" value="${esc(s.matrix_room_backup || '')}" class="f-iinput">
          <span class="k">CMDB Room ID</span>
          <input id="s-matrix-room-cmdb" value="${esc(s.matrix_room_cmdb || '')}" class="f-iinput">
        </div>
      </div>

      <div class="detail-section">
        <h3 class="flex items-center gap-lg">
          Email Notifications
          <label class="text-md flex items-center gap-sm cursor-pointer">
            <input type="checkbox" id="s-email-enabled" ${s.email_enabled !== 'false' ? 'checked' : ''}
              class="f-accent">
            Enabled
          </label>
        </h3>
        <div class="detail-grid gap-row-col">
          <span class="k">SMTP Host</span>
          <input id="s-smtp-host" value="${esc(s.smtp_host || '')}" placeholder="smtp.example.org" class="f-iinput">
          <span class="k">Port</span>
          <input id="s-smtp-port" value="${esc(s.smtp_port || '587')}" placeholder="587" class="f-iinput">
          <span class="k">Encryption</span>
          <div class="smtp-encrypt-row">
            <label class="flex items-center gap-sm cursor-pointer">
              <input type="checkbox" id="s-smtp-starttls" ${s.smtp_use_starttls !== 'false' ? 'checked' : ''}
                class="f-accent">
              STARTTLS
            </label>
            <label class="flex items-center gap-sm cursor-pointer">
              <input type="checkbox" id="s-smtp-ssl" ${s.smtp_use_ssl === 'true' ? 'checked' : ''}
                class="f-accent">
              Implicit TLS (465)
            </label>
          </div>
          <span class="k">User</span>
          <input id="s-smtp-user" value="${esc(s.smtp_user || '')}" placeholder="(optional)" class="f-iinput">
          <span class="k">Password</span>
          <input id="s-smtp-password" value="${esc(s.smtp_password || '')}" type="password" placeholder="(optional)" class="f-iinput">
          <span class="k">From Address</span>
          <input id="s-smtp-from" value="${esc(s.smtp_from || '')}" placeholder="cmdb@example.org" class="f-iinput">
          <span class="k">From Name</span>
          <input id="s-smtp-from-name" value="${esc(s.smtp_from_name || '')}" placeholder="Constellation" class="f-iinput">
          <span class="k">Alert Email</span>
          <input id="s-alert-email" value="${esc(s.alert_email || '')}" placeholder="ops@example.org" class="f-iinput">
        </div>
      </div>

      <div class="detail-section">
        <h3>Notification Webhooks</h3>
        <p class="text-dim mb-12">
          Generic webhooks for Mattermost, Rocket.Chat, Slack, Discord, ntfy, etc.
        </p>
        <button data-action="showAddWebhookForm" class="btn btn-primary btn-md mb-12">Add Webhook</button>

        <div id="webhook-form" class="hidden mb-16">
          <div class="detail-grid gap-row-col w-500">
            <span class="k">Name</span>
            <input id="wh-name" placeholder="mattermost-alerts" class="f-iinput">
            <span class="k">Platform</span>
            <select id="wh-platform" class="f-iinput">
              <option value="mattermost">Mattermost</option>
              <option value="rocketchat">Rocket.Chat</option>
              <option value="slack">Slack</option>
              <option value="discord">Discord</option>
              <option value="ntfy">ntfy</option>
              <option value="gotify">Gotify</option>
              <option value="generic">Generic</option>
            </select>
            <span class="k">Webhook URL</span>
            <input id="wh-url" placeholder="https://..." type="password" class="f-iinput">
            <span class="k">Default Channel</span>
            <input id="wh-channel" placeholder="#alerts (optional)" class="f-iinput">
            <span class="k">Routes</span>
            <div class="flex gap-lg flex-wrap">
              <label class="text-md flex items-center gap-xs cursor-pointer">
                <input type="checkbox" id="wh-r-cve" checked class="f-accent-color"> CVE
              </label>
              <label class="text-md flex items-center gap-xs cursor-pointer">
                <input type="checkbox" id="wh-r-security" checked class="f-accent-color"> Security
              </label>
              <label class="text-md flex items-center gap-xs cursor-pointer">
                <input type="checkbox" id="wh-r-cicd" checked class="f-accent-color"> CI/CD
              </label>
              <label class="text-md flex items-center gap-xs cursor-pointer">
                <input type="checkbox" id="wh-r-backup" checked class="f-accent-color"> Backup
              </label>
            </div>
          </div>
          <button data-action="submitWebhook" class="btn btn-primary btn-md mt-12">Create Webhook</button>
        </div>

        ${webhooks.length ? `<div class="table-wrap"><table>
          <tr><th>Name</th><th>Platform</th><th>Routes</th><th>Enabled</th><th>Actions</th></tr>
          ${webhooks.map(w => {
            const routes = ['cve','security','cicd','backup'].filter(r => w['route_'+r]).join(', ') || 'none';
            const en = w.enabled
              ? '<span class="text-green text-bold">ON</span>'
              : '<span class="text-dim">OFF</span>';
            return `<tr>
              <td class="text-bold">${esc(w.name)}</td>
              <td><span class="text-accent text-sm">${esc(w.platform)}</span></td>
              <td class="text-sm text-dim">${routes}</td>
              <td>${en}</td>
              <td>
                <button data-action="testWebhook" data-id="${w.id}" class="btn btn-primary">Test</button>
                <button data-action="deleteWebhook" data-id="${w.id}" class="btn btn-danger">Del</button>
              </td>
            </tr>`;
          }).join('')}
        </table></div>` : '<div class="empty">No webhooks configured</div>'}
      </div>

      <button data-action="saveSettings" class="btn btn-primary btn-xl mt-16">
        Save
      </button>
      <span id="save-status" class="ml-12 text-green"></span>`;
    }

    // Tab: CVE Options
    if (tab === 'cve') {
      html += `
      <div class="detail-section">
        <h3>CVE Counting</h3>
        <p class="text-dim mb-12">
          Control which severities are included in dashboard totals and node CVE counts.
        </p>
        <label class="text-md flex items-center gap-8 cursor-pointer mb-8">
          <input type="checkbox" id="s-exclude-medium" ${s.cve_count_exclude_medium === 'true' ? 'checked' : ''}
            class="f-accent">
          Exclude medium severity from total CVE counts
        </label>
        <label class="text-md flex items-center gap-8 cursor-pointer">
          <input type="checkbox" id="s-exclude-low" ${s.cve_count_exclude_low === 'true' ? 'checked' : ''}
            class="f-accent">
          Exclude low severity from total CVE counts
        </label>
      </div>

      <div class="detail-section">
        <h3>Resolved CVE Retention</h3>
        <p class="text-dim mb-12">
          Single threshold for every "resolved CVE leftover" the daily retention job removes:
          <code>cve_host_packages</code>, <code>cve_containers</code>, and
          <code>cve_status</code> (the workflow decision).
          One value covers everything — package, container, status — so a CVE
          you resolved past this threshold is fully forgotten.
          A rescan after the threshold can therefore re-create an open finding ;
          raise the slider if you want the decision to stick longer.
        </p>
        <div class="flex items-center gap-12">
          <input type="range" id="s-retention-cve-days"
            min="30" max="365" step="5"
            value="${parseInt(s.retention_resolved_cve_days || 90)}"
            data-change="retentionCveDaysLabel"
            class="flex-1">
          <span class="text-md text-mono"
            ><span id="s-retention-cve-days-display"
              >${parseInt(s.retention_resolved_cve_days || 90)}</span> days</span>
        </div>
        <div class="flex justify-between text-xs text-dim mt-4">
          <span>30</span><span>365</span>
        </div>
      </div>

      <div class="detail-section">
        <h3>RSS / Atom Advisory Feeds</h3>
        <p class="text-dim mb-12">
          Pull external advisories (CERT-FR, vendor PSIRTs, custom feeds) and
          correlate the embedded CVE IDs against your inventory. Matched
          advisories trigger Matrix alerts via the same path as OpenCVE.
        </p>
        <div class="table-wrap"><table>
          <tr><th>Name</th><th>Source</th><th>URL</th><th>Last fetch</th>
              <th>Status</th><th>Advisories</th><th></th></tr>
          ${cveFeeds.length === 0
            ? '<tr><td colspan="7" class="empty">No feeds — add one below.</td></tr>'
            : cveFeeds.map(f => {
              const status = f.last_status === 'ok'
                ? '<span class="text-green">ok</span>'
                : f.last_status === 'error'
                  ? `<span class="text-red" title="${esc(f.last_error || '')}">error</span>`
                  : '<span class="text-dim">—</span>';
              const last = f.last_fetched_at
                ? new Date(f.last_fetched_at).toLocaleString()
                : '—';
              return `<tr ${f.enabled ? '' : 'class="text-dim"'}>
                <td>${esc(f.name)}</td>
                <td><span class="text-mono text-xs">${esc(f.source_label)}</span></td>
                <td class="text-xs text-mono truncate-w-300">${esc(f.url)}</td>
                <td class="text-xs">${last}</td>
                <td>${status}</td>
                <td>${f.advisory_count || 0}</td>
                <td class="flex gap-4">
                  <button data-action="cveFeedFetch" data-id="${f.id}"
                    class="btn-sm btn-primary">Fetch</button>
                  <button data-action="cveFeedToggle" data-id="${f.id}"
                    data-value="${f.enabled ? 'false' : 'true'}"
                    class="btn-sm">${f.enabled ? 'Disable' : 'Enable'}</button>
                  <button data-action="cveFeedDelete" data-id="${f.id}"
                    class="btn-sm btn-danger">Delete</button>
                </td></tr>`;
            }).join('')}
        </table></div>

        <h4 class="mt-16 mb-8">Add a feed</h4>
        <div class="detail-grid gap-row-col">
          <span class="k">Name</span>
          <input id="cf-name" placeholder="My PSIRT" class="f-iinput">
          <span class="k">URL</span>
          <input id="cf-url" placeholder="https://example.com/feed.xml" class="f-iinput">
          <span class="k">Type</span>
          <select id="cf-type" class="f-iinput">
            <option value="rss">RSS</option>
            <option value="atom">Atom</option>
          </select>
          <span class="k">Source label</span>
          <input id="cf-source" placeholder="custom" class="f-iinput">
        </div>
        <button data-action="cveFeedAdd" class="btn btn-primary mt-12">Add feed</button>
        <span id="cf-status" class="ml-12 text-md"></span>

        <h4 class="mt-16 mb-8">Auto-fetch</h4>
        <p class="text-dim mb-8 text-sm">
          Recurring scheduler job that calls <code>fetch-all</code> on the cron
          you set. Default <code>*/30 * * * *</code> (every 30 min).
        </p>
        <div class="flex items-center gap-12">
          <span class="text-md">
            ${autoFetch.scheduled
              ? `<span class="text-green">Scheduled</span> — cron <code>${esc(autoFetch.cron_expr)}</code>${autoFetch.enabled ? '' : ' <span class="text-dim">(disabled)</span>'}`
              : '<span class="text-dim">Not scheduled</span>'}
          </span>
        </div>
        <div class="flex items-center gap-8 mt-8">
          <input id="cf-cron" placeholder="*/30 * * * *"
            value="${esc(autoFetch.cron_expr || '*/30 * * * *')}"
            class="f-iinput w-200">
          <button data-action="cveFeedAutoFetchSet"
            class="btn btn-primary">${autoFetch.scheduled ? 'Update' : 'Schedule'}</button>
          ${autoFetch.scheduled
            ? '<button data-action="cveFeedAutoFetchClear" class="btn btn-danger">Disable</button>'
            : ''}
        </div>
      </div>

      <div class="detail-section">
        <h3>OpenCVE</h3>
        <p class="text-dim mb-12">
          Browser URL for clickable CVE links (not the internal API URL).
        </p>
        <div class="detail-grid gap-row-col">
          <span class="k">OpenCVE Web URL</span>
          <input id="s-opencve-web-url" value="${esc(s.opencve_web_url || '')}" placeholder="https://opencve.example.com" class="f-iinput">
        </div>
      </div>

      <button data-action="saveSettings" class="btn btn-primary btn-xl mt-16">
        Save
      </button>
      <span id="save-status" class="ml-12 text-green"></span>`;
    }

    // Tab: CI/CD
    if (tab === 'cicd') {
      html += `
      <div class="detail-section">
        <h3>CI/CD Integration</h3>
        <p class="text-dim mb-12">
          Git forges and CI/CD systems for pipeline sync, triggers, and repo management.
        </p>
        <div class="detail-grid gap-row-col">
          <span class="k">Woodpecker URL</span>
          <input id="s-woodpecker-url" value="${esc(s.woodpecker_url || '')}" placeholder="https://ci.example.com" class="f-iinput">
          <span class="k">Woodpecker Token</span>
          <input id="s-woodpecker-token" value="${esc(s.woodpecker_token || '')}" type="password" class="f-iinput">
          <span class="k">Gitea URL</span>
          <input id="s-gitea-url" value="${esc(s.gitea_url || '')}" placeholder="https://gitea.example.com" class="f-iinput">
          <span class="k">Gitea Token</span>
          <input id="s-gitea-token" value="${esc(s.gitea_token || '')}" type="password" class="f-iinput">
          <span class="k">GitLab URL</span>
          <input id="s-gitlab-url" value="${esc(s.gitlab_url || '')}" placeholder="https://gitlab.example.com" class="f-iinput">
          <span class="k">GitLab Token</span>
          <input id="s-gitlab-token" value="${esc(s.gitlab_token || '')}" type="password" class="f-iinput">
          <span class="k">Forgejo URL</span>
          <input id="s-forgejo-url" value="${esc(s.forgejo_url || '')}" placeholder="https://forgejo.example.com" class="f-iinput">
          <span class="k">Forgejo Token</span>
          <input id="s-forgejo-token" value="${esc(s.forgejo_token || '')}" type="password" class="f-iinput">
        </div>
      </div>

      <div class="detail-section mt-12">
        <h3>OpenCVE</h3>
        <div class="detail-grid gap-row-col">
          <span class="k">OpenCVE Web URL</span>
          <input id="s-opencve-web-url" value="${esc(s.opencve_web_url || '')}" placeholder="https://opencve.example.com" class="f-iinput">
        </div>
      </div>

      <button data-action="saveSettings" class="btn btn-primary btn-xl mt-16">
        Save
      </button>
      <span id="save-status" class="ml-12 text-green"></span>`;
    }

    // Tab: Vault
    if (tab === 'vault') {
      blackholeDestroy();
      html += `
      <div class="detail-section">
        <div class="flex items-center gap-xl flex-wrap">
          <canvas id="vault-bh-canvas" class="bh-canvas"></canvas>
          <div class="flex-1-min-200">
            <h3 class="vault-h3">
              Resurgamus Horizon
              <span id="vault-status" class="text-sm text-normal text-dim"></span>
              <button data-action="setTab" data-tab="vault" data-group="settings" title="Reload vault status" class="btn btn-surface btn-sm">reload</button>
            </h3>
            <div class="detail-grid vault-detail-grid" id="vault-detail-grid">
              <span class="k">Status</span><span class="text-dim">loading...</span>
            </div>
          </div>
        </div>
      </div>

      <div class="detail-section">
        <h3>Connection</h3>
        <p class="text-dim mb-12 text-md">
          CMDB loads secrets from rhorizon at startup. Auto-discovery tries
          <code class="text-sm">http://rhorizon-api:8200</code> and
          <code class="text-sm">http://rhorizon:8200</code> on the Docker network.
        </p>
        <div class="vault-warning">
          The vault master key is held <strong>in memory only</strong> and never written to disk.
          After a container restart or deploy, the vault returns to <strong>sealed</strong> state
          and must be unsealed again. This is by design — connection settings below are
          persisted, but the unsealed state is per-session only.
        </div>
        <div class="detail-grid gap-row-col">
          <span class="k">Vault URL</span>
          <input id="s-vault-url" value="${esc(s.vault_url || '')}" placeholder="http://rhorizon-api:8200" class="f-iinput">
          <span class="k">Vault Token</span>
          <input id="s-vault-token" value="${esc(s.vault_token || '')}" type="password" placeholder="rh_..." class="f-iinput">
        </div>
        <div class="flex gap-8 mt-12 items-center">
          <button data-action="saveSettings" class="btn btn-primary btn-lg">Save for this session</button>
          <button data-action="checkVault" class="btn btn-bg text-accent text-md">Test Connection</button>
          <button data-action="discoverVault" class="btn btn-bg text-dim text-md">Discover</button>
          <span id="save-status" class="text-green text-md"></span>
        </div>
      </div>

      <div class="detail-section">
        <h3 class="flex items-center gap-lg">
          Secrets Mapping
          <button data-action="bootstrapVault" class="btn btn-bg text-green">Auto-generate</button>
          <span id="vault-bootstrap-status" class="text-sm text-dim"></span>
        </h3>
        <p class="text-dim mb-12 text-md">
          Vault secrets mapped to CMDB settings. Secrets are loaded at API startup.
          <strong>Auto-generate</strong> creates the 3 required secrets (secret-key, collect-token, hmac-key) with random values. Existing secrets are not overwritten.
        </p>
        <div id="vault-secrets-table">
          <div class="empty">Loading secrets status...</div>
        </div>
      </div>

      <div class="detail-section">
        <h3>Execution Guard</h3>
        <p class="text-dim mb-12 text-md">
          When vault is configured, the following operations are <strong>blocked if sealed</strong>:
        </p>
        <div class="table-wrap"><table class="text-md">
          <tr><th>Operation</th><th>Behavior</th></tr>
          <tr><td>Scheduler jobs</td><td>Fail with "Vault sealed — execution blocked"</td></tr>
          <tr><td>CI/CD pipeline trigger</td><td>HTTP 503</td></tr>
          <tr><td>Deployment execute</td><td>HTTP 503 + preflight check</td></tr>
          <tr><td>Automation actions</td><td>Blocked (except <code>notify</code>)</td></tr>
        </table></div>
        <p class="text-dim mt-8 text-sm">
          If vault is not configured, CMDB runs in legacy mode using <code>.env</code> secrets.
        </p>
      </div>`;
    }

    // Tab: SSO / O.U.
    if (tab === 'sso') {
      let ssoData = {};
      try { ssoData = await api('/settings/sso-groups'); } catch {}
      const mappings = ssoData.mappings || {};
      const roles = ssoData.roles || ['admin', 'ops', 'viewer'];
      const entries = Object.entries(mappings);

      html += `
      <div class="detail-section">
        <h3>SSO Group → Role Mapping (O.U.)</h3>
        <p class="text-dim mb-12">
          Map SSO groups (from Active Directory, LDAP, Authelia, Authentik, Keycloak) to CMDB roles.<br>
          Groups are matched case-insensitive. Higher-priority role wins when a user has multiple groups.<br>
          <strong>admin</strong> = full access &nbsp;|&nbsp; <strong>ops</strong> = read-only &nbsp;|&nbsp; <strong>viewer</strong> = read-only
        </p>

        <table class="mb-16">
          <tr><th>SSO Group</th><th>CMDB Role</th><th></th></tr>
          ${entries.map(([g, r], i) => `
            <tr>
              <td><input id="sso-g-${i}" value="${esc(g)}" class="f-iinput w-240"></td>
              <td>
                <select id="sso-r-${i}" class="f-iinput w-120">
                  ${roles.map(role => `<option value="${role}" ${r === role ? 'selected' : ''}>${role}</option>`).join('')}
                </select>
              </td>
              <td><button data-action="removeSsoRow" data-index="${i}" class="btn btn-bg text-red">✕</button></td>
            </tr>
          `).join('')}
          <tr id="sso-new-row">
            <td><input id="sso-g-new" placeholder="e.g. Domain Admins" class="f-iinput w-240"></td>
            <td>
              <select id="sso-r-new" class="f-iinput w-120">
                ${roles.map(role => `<option value="${role}">${role}</option>`).join('')}
              </select>
            </td>
            <td><button data-action="addSsoRow" class="btn btn-primary">+</button></td>
          </tr>
        </table>

        <button data-action="saveSsoGroups" class="btn btn-primary btn-lg">Save Mappings</button>
        <span id="sso-save-status" class="ml-12 text-md text-green"></span>
      </div>

      <div class="detail-section mt-24">
        <h3>SSO Headers</h3>
        <p class="text-dim text-sm">
          The CMDB reads these headers from the reverse proxy (set by the SSO provider):
        </p>
        <div class="detail-grid mt-8 text-sm">
          <span class="k">Authelia</span><span>Remote-User, Remote-Groups</span>
          <span class="k">Authentik</span><span>X-Auth-User, X-Auth-Groups</span>
          <span class="k">Keycloak</span><span>X-Forwarded-User, X-Forwarded-Groups</span>
        </div>
      </div>`;
    }

    if (tab === 'features') {
      const cveOn = s.feature_cve_enabled !== 'false';
      const bkOn = s.feature_backup_enabled !== 'false';

      html += `
      <div class="detail-section">
        <h3>Module Management</h3>
        <p class="text-dim mb-16">
          Disabling a module removes all its data (TRUNCATE) for performance.
          Re-enabling starts fresh — data will repopulate from the next sync.
        </p>

        <div class="flex gap-24 flex-wrap">
          <div class="stat-card-280">
            <div class="flex items-center gap-lg mb-12">
              <span class="text-lg text-bolder">CVE Module</span>
              <span class="feat-state-pill ${cveOn ? 'on' : 'off'}">${cveOn ? 'ON' : 'OFF'}</span>
            </div>
            <p class="text-dim text-sm mb-12">
              CVE scanning, OpenCVE alerts, compliance scoring, findings management.
              ${!cveOn ? '<br><strong class="text-orange">Tables: cve_host_packages, cve_containers, cve_status, opencve_alerts, opencve_subscriptions, alert_sent — all truncated.</strong>' : ''}
            </p>
            <input id="feat-cve-confirm" placeholder="Type '${cveOn ? 'DISABLE CVE' : 'ENABLE CVE'}' to confirm" class="f-iinput w-300 mb-8">
            <br>
            <button data-action="toggleFeature" data-feature="cve" data-value="${!cveOn}" class="btn ${cveOn ? 'btn-danger' : 'btn-primary'} btn-lg">
              ${cveOn ? 'Disable CVE' : 'Enable CVE'}
            </button>
          </div>

          <div class="stat-card-280">
            <div class="flex items-center gap-lg mb-12">
              <span class="text-lg text-bolder">Backup Module</span>
              <span class="feat-state-pill ${bkOn ? 'on' : 'off'}">${bkOn ? 'ON' : 'OFF'}</span>
            </div>
            <p class="text-dim text-sm mb-12">
              Restic backup monitoring, alerts, history.
              ${!bkOn ? '<br><strong class="text-orange">Tables: backup_repositories, backup_runs — all truncated.</strong>' : ''}
            </p>
            <input id="feat-bk-confirm" placeholder="Type '${bkOn ? 'DISABLE BACKUP' : 'ENABLE BACKUP'}' to confirm" class="f-iinput w-300 mb-8">
            <br>
            <button data-action="toggleFeature" data-feature="backup" data-value="${!bkOn}" class="btn ${bkOn ? 'btn-danger' : 'btn-primary'} btn-lg">
              ${bkOn ? 'Disable Backup' : 'Enable Backup'}
            </button>
          </div>
        </div>

        <div id="feat-result" class="mt-12"></div>
      </div>`;
    }

    // Tab: Dev Tools
    if (tab === 'itsm') {
      let integrations = [];
      try { integrations = (await api('/itsm/integrations'))?.items || []; } catch (_) {}
      html += `
      <div class="detail-section">
        <h3>ITSM Integrations</h3>
        <p class="text-dim mb-12">
          Push incidents to external ticketing systems (GLPI, Zammad, Jira).
          Enable <strong>bidirectional sync</strong> to let the ITSM close incidents in CMDB.
        </p>
        <table class="data-table mb-16">
          <thead><tr>
            <th>Name</th><th>Platform</th><th>URL</th><th>Outbound</th><th>Inbound</th><th>Enabled</th><th class="th-w-220"></th>
          </tr></thead>
          <tbody>
            ${integrations.length === 0 ? '<tr><td colspan="7" class="text-dim text-center">No integrations</td></tr>' : integrations.map(it => `
              <tr>
                <td>${esc(it.name)}</td>
                <td>${esc(it.platform)}</td>
                <td class="text-sm text-dim">${esc(it.base_url)}</td>
                <td>${it.sync_outbound ? '✓' : '—'}</td>
                <td>${it.sync_inbound ? (it.has_webhook_secret ? '✓' : '⚠') : '—'}</td>
                <td>${it.enabled ? '✓' : '—'}</td>
                <td>
                  <button data-action="itsmTest" data-id="${it.id}" class="btn btn-surface">Test</button>
                  <button data-action="itsmDelete" data-id="${it.id}" class="btn btn-surface text-red">Delete</button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        <div id="itsm-test-status" class="text-md text-dim mb-12"></div>

        <h4 class="mt-16">Add Integration</h4>
        <div class="detail-grid gap-row-col">
          <span class="k">Name</span>
          <input id="itsm-name" class="f-iinput" placeholder="glpi-prod">
          <span class="k">Platform</span>
          <select id="itsm-platform" class="f-iinput">
            <option value="glpi">GLPI</option>
            <option value="zammad">Zammad</option>
            <option value="jira">Jira Cloud</option>
          </select>
          <span class="k">Base URL</span>
          <input id="itsm-url" class="f-iinput" placeholder="https://glpi.example.com">
          <span class="k">Auth config (JSON)</span>
          <textarea id="itsm-auth" rows="3" class="f-iinput text-mono text-sm" placeholder='{"app_token":"...", "user_token":"..."}'></textarea>
          <span class="k">Project key (Jira)</span>
          <input id="itsm-project" class="f-iinput" placeholder="INC">
          <span class="k">Outbound sync</span>
          <label><input type="checkbox" id="itsm-out" checked> Push new incidents as tickets</label>
          <span class="k">Inbound sync</span>
          <label><input type="checkbox" id="itsm-in"> Accept status updates from ITSM (generates webhook secret)</label>
          <span class="k">Status map (JSON)</span>
          <textarea id="itsm-smap" rows="2" class="f-iinput text-mono text-sm" placeholder='{"Done":"closed","In Progress":"in_progress"}'></textarea>
        </div>
        <button data-action="itsmCreate" class="btn btn-primary mt-12">Add Integration</button>
        <div id="itsm-create-status" class="text-md mt-8"></div>

        <div class="mt-16 p-12 bg-bg border rounded-md text-sm text-dim">
          <strong>Inbound webhook URL</strong> (when bidirectional is enabled):<br>
          <code class="text-accent">POST /api/v1/webhooks/itsm/{integration_id}</code><br>
          Signed with HMAC-SHA256 in header <code>X-CMDB-Signature</code> using the generated webhook secret.
        </div>
      </div>`;
    }

    if (tab === 'plugins') {
      let cat = { summary: {}, categories: [] };
      try { cat = await api('/plugins'); } catch (_) {}
      const sm = cat.summary || {};
      const cats = cat.categories || [];

      html += `
      <div class="detail-section">
        <h3>Plugins</h3>
        <p class="text-dim mb-12">
          Capabilities Constellation can integrate with. Cards marked <strong>planned</strong>
          are roadmap items — not usable yet.
        </p>
        <div class="stats-grid mb-20">
          <div class="stat-card"><div class="label">Categories</div><div class="value">${sm.categories || 0}</div></div>
          <div class="stat-card"><div class="label">Providers</div><div class="value">${sm.providers_total || 0}</div></div>
          <div class="stat-card"><div class="label">Supported</div><div class="value green">${sm.providers_supported || 0}</div></div>
          <div class="stat-card"><div class="label">Planned</div><div class="value text-dim">${sm.providers_planned || 0}</div></div>
          <div class="stat-card"><div class="label">Configured</div><div class="value text-accent">${sm.providers_configured || 0}</div></div>
        </div>`;

      if (!cats.length) {
        html += '<div class="empty">No catalogue data</div>';
      } else {
        for (const c of cats) {
          html += `<div class="mb-20">
            <div class="plugin-cat-head">
              <h4 class="m-0 text-base text-default">${esc(c.name)}</h4>
              <span class="text-sm text-dim">${esc(c.description)}</span>
            </div>
            <div class="plugin-grid">`;
          for (const p of c.providers) {
            const configured = p.configured_count || 0;
            const planned = p.status !== 'supported';
            const cardCls = `plugin-card${configured > 0 ? ' configured' : ''}${planned ? ' planned' : ''}`;
            const stCls = planned ? 'text-dim' : 'text-green';
            const cntCls = `plugin-card-count${configured > 0 ? ' has' : ''}`;
            html += `<div class="${cardCls}">
              <div class="min-w-0">
                <div class="text-bold text-base text-default">${esc(p.name)}</div>
                <div class="plugin-card-status ${stCls}">${esc(p.status)}</div>
              </div>
              <div class="text-right flex-shrink-0">
                <div class="${cntCls}">${configured}</div>
                <div class="plugin-card-count-lbl">configured</div>
              </div>
            </div>`;
          }
          html += '</div></div>';
        }
      }

      html += '</div>';
    }

    if (tab === 'dev') {
      html += `
      <div class="detail-section">
        <h3>Data Resync</h3>
        <p class="text-dim mb-16">
          Re-import CVE data from external sources. Useful after a database rebuild
          or when data is missing. Existing entries are updated (upsert), not duplicated.
        </p>

        <div class="flex gap-24 flex-wrap">
          <div class="stat-card-300">
            <div class="flex items-center gap-sm mb-8">
              <span class="text-15 text-bolder">Wazuh CVEs</span>
              <span class="text-sm text-dim">(OpenSearch)</span>
            </div>
            <p class="text-dim text-sm mb-12">
              Fetches current vulnerability states from all Wazuh agents via OpenSearch
              and re-imports them into CMDB. This syncs the live state, not historical data.
            </p>
            <button data-action="resyncWazuh" class="btn btn-primary btn-lg">
              Resync Wazuh
            </button>
            <span id="resync-wazuh-status" class="ml-12 text-md text-dim"></span>
          </div>

          <div class="stat-card-300">
            <div class="flex items-center gap-sm mb-8">
              <span class="text-15 text-bolder">OpenCVE Alerts</span>
              <span class="text-sm text-dim">(CVE Intelligence)</span>
            </div>
            <p class="text-dim text-sm mb-12">
              Re-fetches CVE alerts from OpenCVE for the specified time window
              and imports them into CMDB alert database.
            </p>
            <div class="flex items-center gap-8 mb-12">
              <span class="text-md text-dim">Last</span>
              <input id="resync-opencve-days" type="number" value="7" min="1" max="90"
                class="f-iinput text-center w-60">
              <span class="text-md text-dim">days</span>
            </div>
            <button data-action="resyncOpencve" class="btn btn-primary btn-lg">
              Resync OpenCVE
            </button>
            <span id="resync-opencve-status" class="ml-12 text-md text-dim"></span>
          </div>
        </div>
      </div>

      <div class="detail-section mt-24">
        <h3 class="text-red">Reset CVE Data</h3>
        <p class="text-dim mb-12">
          Wipe all CVE scan results (host + container + status).
          OpenCVE alerts and subscriptions are preserved.
          Use before a full resync after a database rebuild.
        </p>
        <div class="cve-reset-card">
          <div class="text-sm text-dim mb-8">
            Tables truncated: <strong>cve_host_packages, cve_containers, cve_status</strong>
          </div>
          <label class="cve-reset-label">
            <input type="checkbox" id="reset-resync-wazuh" checked class="f-accent-color">
            Auto-resync Wazuh after reset
          </label>
          <label class="text-md flex items-center gap-sm cursor-pointer mb-12">
            <input type="checkbox" id="reset-resync-opencve" class="f-accent-color">
            Auto-resync OpenCVE after reset
            <input id="reset-opencve-days" type="number" value="7" min="1" max="90"
              class="f-iinput text-center w-50"> days
          </label>
          <input id="reset-cve-confirm" placeholder="Type 'RESET CVE' to confirm" class="f-iinput w-300 mb-8">
          <br>
          <button data-action="resetCve" class="btn btn-danger btn-lg">
            Reset CVE Data
          </button>
          <span id="reset-cve-status" class="ml-12 text-md"></span>
        </div>
      </div>`;
    }

    el.innerHTML = html;

    // Auto-load vault info + blackhole animation when Vault tab is active
    if (tab === 'vault') {
      // Init blackhole canvas — responsive size
      const bhCanvas = document.getElementById('vault-bh-canvas');
      if (bhCanvas) {
        const isSmall = window.innerWidth < 768;
        const sz = isSmall ? 48 : 160;
        bhCanvas.width = sz;
        bhCanvas.height = sz;
        bhCanvas.style.width = sz + 'px';
        bhCanvas.style.height = sz + 'px';
      }

      try {
        let vst = await api('/settings/vault/status');
        if (!vst) vst = { configured: false, sealed: null };
        const span = document.getElementById('vault-status');
        const grid = document.getElementById('vault-detail-grid');

        // Set blackhole state + start animation
        // Only show sealed animation when explicitly sealed, not on unreachable
        const sealed = vst.sealed === true;
        blackholeSetState(sealed);
        blackholeInit('vault-bh-canvas');

        if (grid) {
          if (!vst.configured) {
            grid.innerHTML = `
              <span class="k">Status</span><span class="text-dim">not configured</span>
              <span class="k">Mode</span><span class="text-dim">legacy (.env)</span>`;
            if (span) span.innerHTML = '<span class="text-dim">not configured</span>';
          } else if (vst.sealed === false) {
            const versionRow = vst.version
              ? `<span class="k">Version</span><span class="text-sm">${esc(vst.version)}</span>`
              : '';
            const tfaRow = vst.second_factor && vst.second_factor !== 'none'
              ? `<span class="k">2FA</span><span class="text-sm text-green">${esc(vst.second_factor)}</span>`
              : '';
            grid.innerHTML = `
              <span class="k">Status</span><span class="text-green">unsealed</span>
              <span class="k">URL</span><span class="text-sm">${esc(vst.url || '')}</span>
              ${_h(versionRow)}
              ${_h(tfaRow)}`;
            if (span) span.innerHTML = '<span class="text-green">unsealed</span>';
          } else if (vst.sealed === true) {
            grid.innerHTML = `
              <span class="k">Status</span><span class="text-orange">sealed</span>
              <span class="k">URL</span><span class="text-sm">${esc(vst.url || '')}</span>`;
            if (span) span.innerHTML = '<span class="text-orange">sealed</span>';
          } else {
            grid.innerHTML = `
              <span class="k">Status</span><span class="text-red">unreachable</span>
              <span class="k">URL</span><span class="text-sm">${esc(vst.url || '')}</span>
              <span class="k"></span><span class="text-xs text-dim">vault may be unsealed — network issue</span>`;
            if (span) span.innerHTML = '<span class="text-red">unreachable</span>';
          }
        }
      } catch {
        // Start animation even on error (sealed state)
        blackholeInit('vault-bh-canvas');
      }

      // Load secrets mapping status
      try {
        const sec = await api('/settings/vault/secrets');
        const container = document.getElementById('vault-secrets-table');
        if (container && sec.secrets) {
          const statusIcon = (st) => {
            if (st === 'loaded') return '<span class="text-green">loaded</span>';
            if (st === 'exists') return '<span class="text-yellow">exists (not loaded)</span>';
            if (st === 'missing') return '<span class="text-dim">not in vault</span>';
            if (st === 'not_configured') return '<span class="text-dim">—</span>';
            return `<span class="text-red">${esc(st)}</span>`;
          };
          const rows = sec.secrets.map(s => `<tr>
              <td><code class="text-sm">${esc(s.vault_name)}</code></td>
              <td><code class="text-sm">${esc(s.setting)}</code></td>
              <td>${statusIcon(s.status)}</td>
            </tr>`).join('');
          container.innerHTML = `<div class="table-wrap"><table class="text-md">
            <tr><th>Vault Secret</th><th>CMDB Setting</th><th>Status</th></tr>
            ${_h(rows)}
          </table></div>`;
        }
      } catch {}
    }
  } catch(e) {
    el.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}

export async function setThreshold(level) {
  await fetch(API + '/settings/alerts', {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({cve_severity_threshold: level})
  });
  loadView();
}

export async function saveSettings() {
  const g = id => { const el = document.getElementById(id); return el ? el.value : undefined; };
  const gc = id => { const el = document.getElementById(id); return el ? (el.checked ? 'true' : 'false') : undefined; };
  const raw = {
    matrix_enabled: gc('s-matrix-enabled'),
    matrix_url: g('s-matrix-url'),
    matrix_token: g('s-matrix-token'),
    matrix_room_cve: g('s-matrix-room-cve'),
    matrix_room_security: g('s-matrix-room-sec'),
    matrix_room_cicd: g('s-matrix-room-cicd'),
    matrix_room_backup: g('s-matrix-room-backup'),
    matrix_room_cmdb: g('s-matrix-room-cmdb'),
    email_enabled: gc('s-email-enabled'),
    smtp_host: g('s-smtp-host'),
    smtp_port: g('s-smtp-port'),
    smtp_use_starttls: gc('s-smtp-starttls'),
    smtp_use_ssl: gc('s-smtp-ssl'),
    smtp_user: g('s-smtp-user'),
    smtp_password: g('s-smtp-password'),
    smtp_from: g('s-smtp-from'),
    smtp_from_name: g('s-smtp-from-name'),
    alert_email: g('s-alert-email'),
    woodpecker_url: g('s-woodpecker-url'),
    woodpecker_token: g('s-woodpecker-token'),
    gitea_url: g('s-gitea-url'),
    gitea_token: g('s-gitea-token'),
    gitlab_url: g('s-gitlab-url'),
    gitlab_token: g('s-gitlab-token'),
    forgejo_url: g('s-forgejo-url'),
    forgejo_token: g('s-forgejo-token'),
    opencve_web_url: g('s-opencve-web-url'),
    vault_url: g('s-vault-url'),
    vault_token: g('s-vault-token'),
    cve_count_exclude_medium: gc('s-exclude-medium'),
    cve_count_exclude_low: gc('s-exclude-low'),
    retention_resolved_cve_days: g('s-retention-cve-days'),
  };
  // Only send fields present on current tab
  const payload = {};
  for (const [k, v] of Object.entries(raw)) {
    if (v !== undefined) payload[k] = v;
  }
  const r = await fetch(API + '/settings/alerts', {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  });
  if (r.ok) {
    clearApiCache();
    document.getElementById('save-status').textContent = 'Saved!';
    setTimeout(() => loadView(), 1500);
  }
}

// Webhook actions

export function showAddWebhookForm() {
  const form = document.getElementById('webhook-form');
  form.classList.toggle('hidden');
}

export async function submitWebhook() {
  const name = document.getElementById('wh-name').value.trim();
  const webhook_url = document.getElementById('wh-url').value.trim();
  if (!name || !webhook_url) return alert('Name and URL required');

  await fetch(API + '/settings/webhooks', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      name,
      platform: document.getElementById('wh-platform').value,
      webhook_url,
      default_channel: document.getElementById('wh-channel').value.trim() || null,
      route_cve: document.getElementById('wh-r-cve').checked,
      route_security: document.getElementById('wh-r-security').checked,
      route_cicd: document.getElementById('wh-r-cicd').checked,
      route_backup: document.getElementById('wh-r-backup').checked,
    }),
  });
  loadView();
}

export async function testWebhook(id) {
  const r = await fetch(API + `/settings/webhooks/${id}/test`, { method: 'POST' });
  const d = await r.json();
  alert(d.detail || d.error || 'Done');
}

export async function toggleFeature(feature, enabled) {
  const inputId = feature === 'cve' ? 'feat-cve-confirm' : 'feat-bk-confirm';
  const confirm = document.getElementById(inputId)?.value?.trim() || '';
  const label = feature.toUpperCase();
  const expected = enabled ? `ENABLE ${label}` : `DISABLE ${label}`;

  if (confirm !== expected) {
    alert(`Type "${expected}" to confirm.`);
    return;
  }

  const res = document.getElementById('feat-result');
  try {
    const r = await fetch(API + '/settings/features/toggle', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ feature, enabled, confirm }),
    });
    const d = await r.json();
    if (r.ok) {
      res.innerHTML = `<span class="text-green">${esc(d.detail)}</span>`;
      setTimeout(() => loadView(), 1500);
    } else {
      res.innerHTML = `<span class="text-red">${esc(d.detail || d.error || JSON.stringify(d))}</span>`;
    }
  } catch (e) {
    res.innerHTML = `<span class="text-red">Error: ${esc(e.message)}</span>`;
  }
}

export async function deleteWebhook(id) {
  if (!confirm('Delete this webhook?')) return;
  await fetch(API + `/settings/webhooks/${id}`, { method: 'DELETE' });
  loadView();
}

// CVE feed actions

export async function cveFeedAdd() {
  const status = document.getElementById('cf-status');
  const name = document.getElementById('cf-name').value.trim();
  const url = document.getElementById('cf-url').value.trim();
  if (!name || !url) {
    status.innerHTML = '<span class="text-red">Name and URL required</span>';
    return;
  }
  const r = await fetch(API + '/cve-feeds', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name,
      url,
      feed_type: document.getElementById('cf-type').value,
      source_label: document.getElementById('cf-source').value.trim() || 'custom',
    }),
  });
  if (!r.ok) {
    const d = await r.json().catch(() => ({}));
    status.innerHTML = `<span class="text-red">${esc(d.detail || r.statusText)}</span>`;
    return;
  }
  clearApiCache();
  loadView();
}

export async function cveFeedFetch(id) {
  const r = await fetch(API + `/cve-feeds/${id}/fetch`, { method: 'POST' });
  const d = await r.json().catch(() => ({}));
  const cf = document.getElementById('cf-status');
  if (cf) {
    if (d.status === 'ok') {
      cf.innerHTML = `<span class="text-green">${esc(d.total)} advisories (${esc(d.new)} new, ${esc(d.matched_cves)} matched)</span>`;
    } else {
      cf.innerHTML = `<span class="text-red">${esc(d.error || 'fetch failed')}</span>`;
    }
  }
  clearApiCache();
  setTimeout(() => loadView(), 1200);
}

export async function cveFeedToggle(id, value) {
  await fetch(API + `/cve-feeds/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled: value === 'true' || value === true }),
  });
  clearApiCache();
  loadView();
}

export async function cveFeedDelete(id) {
  if (!confirm('Delete this feed and all its advisories?')) return;
  await fetch(API + `/cve-feeds/${id}`, { method: 'DELETE' });
  clearApiCache();
  loadView();
}

export async function cveFeedAutoFetchSet() {
  const cron = document.getElementById('cf-cron').value.trim() || '*/30 * * * *';
  const r = await fetch(API + '/cve-feeds/auto-fetch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cron_expr: cron, enabled: true }),
  });
  if (!r.ok) {
    const d = await r.json().catch(() => ({}));
    alert(`Failed: ${d.detail || r.statusText}`);
    return;
  }
  clearApiCache();
  loadView();
}

export async function cveFeedAutoFetchClear() {
  if (!confirm('Disable auto-fetch? Manual fetches still work.')) return;
  await fetch(API + '/cve-feeds/auto-fetch', { method: 'DELETE' });
  clearApiCache();
  loadView();
}

// Resync actions

export async function resyncWazuh() {
  if (!confirm('Resync all Wazuh CVEs from OpenSearch?\nThis may take a few minutes.')) return;
  const span = document.getElementById('resync-wazuh-status');
  if (span) { let dots=''; for(let i=0;i<10;i++) dots+=`<canvas id="lp${i}" width="4" height="4" class="inline-block"></canvas>`; span.innerHTML=`<span class="loading-pixels inline-flex gap-sm">${_h(dots)}<span class="text-orange text-sm">Syncing...</span></span>`; startLoadingPx(); }
  try {
    const r = await fetch(API + '/resync/wazuh', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
    });
    const d = await r.json();
    const color = d.status === 'ok' ? 'green' : d.status === 'warning' ? 'orange' : 'red';
    if (span) span.innerHTML = `<span class="${txtColor(color)}">${esc(d.detail)}</span>`;
  } catch (e) {
    if (span) span.innerHTML = `<span class="text-red">Error: ${esc(e.message)}</span>`;
  }
}

export async function resyncOpencve() {
  const days = parseInt(document.getElementById('resync-opencve-days')?.value) || 7;
  if (!confirm(`Resync OpenCVE alerts from the last ${days} days?\nThis may take a while.`)) return;
  const span = document.getElementById('resync-opencve-status');
  if (span) { let dots=''; for(let i=0;i<10;i++) dots+=`<canvas id="lp${i}" width="4" height="4" class="inline-block"></canvas>`; span.innerHTML=`<span class="loading-pixels inline-flex gap-sm">${_h(dots)}<span class="text-orange text-sm">Syncing...</span></span>`; startLoadingPx(); }
  try {
    const r = await fetch(API + '/resync/opencve', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ hours: days * 24 }),
    });
    const d = await r.json();
    const color = d.status === 'ok' ? 'green' : d.status === 'warning' ? 'orange' : 'red';
    if (span) span.innerHTML = `<span class="${txtColor(color)}">${esc(d.detail)}</span>`;
  } catch (e) {
    if (span) span.innerHTML = `<span class="text-red">Error: ${esc(e.message)}</span>`;
  }
}

// SSO Group Mapping actions

export async function saveSsoGroups() {
  const rows = document.querySelectorAll('[id^="sso-g-"]');
  const mappings = {};
  rows.forEach(input => {
    if (input.id === 'sso-g-new') return;
    const idx = input.id.replace('sso-g-', '');
    const group = input.value.trim();
    const role = document.getElementById(`sso-r-${idx}`)?.value;
    if (group && role) mappings[group] = role;
  });
  // Add new row if filled
  const newG = document.getElementById('sso-g-new')?.value?.trim();
  const newR = document.getElementById('sso-r-new')?.value;
  if (newG && newR) mappings[newG] = newR;

  const r = await fetch(API + '/settings/sso-groups', {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ mappings }),
  });
  const span = document.getElementById('sso-save-status');
  if (r.ok) {
    if (span) span.textContent = 'Saved!';
    setTimeout(() => loadView(), 1000);
  } else {
    const d = await r.json();
    if (span) span.innerHTML = `<span class="text-red">${esc(d.detail || 'Error')}</span>`;
  }
}

export function addSsoRow() {
  const newG = document.getElementById('sso-g-new')?.value?.trim();
  const newR = document.getElementById('sso-r-new')?.value;
  if (!newG) return;
  saveSsoGroups();
}

export function removeSsoRow(idx) {
  const input = document.getElementById(`sso-g-${idx}`);
  if (input) input.value = '';
  saveSsoGroups();
}

export async function resetCve() {
  const confirm = document.getElementById('reset-cve-confirm')?.value?.trim() || '';
  if (confirm !== 'RESET CVE') {
    alert("Type 'RESET CVE' to confirm.");
    return;
  }
  const span = document.getElementById('reset-cve-status');
  const resyncWz = document.getElementById('reset-resync-wazuh')?.checked;
  const resyncOc = document.getElementById('reset-resync-opencve')?.checked;
  const ocDays = parseInt(document.getElementById('reset-opencve-days')?.value) || 7;

  try {
    span.innerHTML = '<span class="text-orange">Resetting...</span>';
    const r = await fetch(API + '/resync/reset-cve', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        confirm: 'RESET CVE',
        resync_wazuh: resyncWz,
        resync_opencve: resyncOc,
        opencve_hours: ocDays * 24,
      }),
    });
    const d = await r.json();
    if (r.ok) {
      span.innerHTML = `<span class="text-green">${esc(d.detail)}</span>`;
    } else {
      span.innerHTML = `<span class="text-red">${esc(d.detail || d.error || 'Error')}</span>`;
    }
  } catch (e) {
    span.innerHTML = `<span class="text-red">Error: ${esc(e.message)}</span>`;
  }
}

export async function checkVault() {
  const url = document.getElementById('s-vault-url')?.value?.trim();
  const span = document.getElementById('vault-status');
  if (!url) { if (span) span.innerHTML = '<span class="text-red">No URL</span>'; return; }
  if (span) span.innerHTML = '<span class="text-orange">Checking...</span>';

  // Backend already retries 3 times, but vault-check is a direct probe
  // so we also retry the full round-trip from the frontend
  const maxRetries = 3;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const r = await fetch(API + '/settings/vault-check', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ vault_url: url }),
      });
      const d = await r.json();
      if (r.ok && d.status === 'ok') {
        const sealed = d.sealed ? 'sealed' : 'unsealed';
        const color = d.sealed ? 'orange' : 'green';
        span.innerHTML = `<span class="${txtColor(color)}">${esc(sealed)}</span>`;
        return;
      }
      // Backend returned error — retry
      if (attempt < maxRetries - 1) {
        span.innerHTML = `<span class="text-orange">Retrying (${esc(attempt + 2)}/${esc(maxRetries)})...</span>`;
        await new Promise(ok => setTimeout(ok, 1500));
        continue;
      }
      span.innerHTML = `<span class="text-red">${esc(d.detail || 'unreachable')}</span>`;
    } catch (e) {
      if (attempt < maxRetries - 1) {
        span.innerHTML = `<span class="text-orange">Retrying (${esc(attempt + 2)}/${esc(maxRetries)})...</span>`;
        await new Promise(ok => setTimeout(ok, 1500));
        continue;
      }
      if (span) span.innerHTML = `<span class="text-red">unreachable</span>`;
    }
  }
}

export async function discoverVault() {
  const span = document.getElementById('save-status');
  if (span) span.innerHTML = '<span class="text-orange">Probing Docker network...</span>';
  try {
    const r = await fetch(API + '/settings/vault/discover', { method: 'POST' });
    const d = await r.json();
    if (d.status === 'found') {
      const input = document.getElementById('s-vault-url');
      if (input) input.value = d.url;
      const sealed = d.sealed ? 'sealed' : 'unsealed';
      const color = d.sealed ? 'orange' : 'green';
      if (span) span.innerHTML = `<span class="${txtColor(color)}">Found ${esc(d.url)} (${esc(sealed)})</span>`;
    } else {
      if (span) span.innerHTML = '<span class="text-dim">No vault found on Docker network</span>';
    }
  } catch (e) {
    if (span) span.innerHTML = `<span class="text-red">${esc(e.message)}</span>`;
  }
}

export async function bootstrapVault() {
  const span = document.getElementById('vault-bootstrap-status');
  const url = document.getElementById('s-vault-url')?.value?.trim();
  const token = document.getElementById('s-vault-token')?.value?.trim();
  if (!url || !token) {
    if (span) span.innerHTML = '<span class="text-red">URL and token required</span>';
    return;
  }
  if (span) span.innerHTML = '<span class="text-orange">Generating...</span>';
  try {
    const r = await fetch(API + '/settings/vault/bootstrap', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ vault_url: url, vault_token: token === '********' ? '' : token }),
    });
    const d = await r.json();
    if (!r.ok) {
      if (span) span.innerHTML = `<span class="text-red">${esc(d.detail || 'error')}</span>`;
      return;
    }
    const created = d.created || 0;
    const existed = (d.results || []).filter(s => s.status === 'exists').length;
    const errors = (d.results || []).filter(s => s.status === 'error').length;
    let msg = `<span class="text-green">${created} created</span>`;
    if (existed) msg += ` · <span class="text-dim">${existed} already existed</span>`;
    if (errors) msg += ` · <span class="text-red">${errors} error(s)</span>`;
    if (span) span.innerHTML = msg;
    // Reload secrets table
    setTimeout(() => loadView(), 1500);
  } catch (e) {
    if (span) span.innerHTML = `<span class="text-red">${esc(e.message)}</span>`;
  }
}

export async function itsmCreate() {
  const span = document.getElementById('itsm-create-status');
  const name = document.getElementById('itsm-name').value.trim();
  const platform = document.getElementById('itsm-platform').value;
  const base_url = document.getElementById('itsm-url').value.trim();
  let auth_config = {};
  let status_map = {};
  try {
    const a = document.getElementById('itsm-auth').value.trim();
    if (a) auth_config = JSON.parse(a);
    const s = document.getElementById('itsm-smap').value.trim();
    if (s) status_map = JSON.parse(s);
  } catch (e) {
    span.innerHTML = `<span class="text-red">Invalid JSON: ${esc(e.message)}</span>`;
    return;
  }
  const body = {
    name, platform, base_url, auth_config, status_map,
    project_key: document.getElementById('itsm-project').value.trim() || null,
    sync_outbound: document.getElementById('itsm-out').checked,
    sync_inbound: document.getElementById('itsm-in').checked,
  };
  try {
    const r = await fetch(API + '/itsm/integrations', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (!r.ok) {
      span.innerHTML = `<span class="text-red">${esc(d.detail || 'error')}</span>`;
      return;
    }
    let msg = '<span class="text-green">Created</span>';
    if (d.webhook_secret) {
      msg += ` · <code class="text-xs">secret: ${esc(d.webhook_secret)}</code> <em>(save this now)</em>`;
    }
    span.innerHTML = msg;
    clearApiCache();
    setTimeout(() => window.refreshView && window.refreshView(), 1500);
  } catch (e) {
    span.innerHTML = `<span class="text-red">${esc(e.message)}</span>`;
  }
}

export async function itsmTest(id) {
  const span = document.getElementById('itsm-test-status');
  if (span) span.innerHTML = '<span class="text-orange">Testing...</span>';
  try {
    const r = await fetch(API + `/itsm/integrations/${id}/test`, { method: 'POST' });
    const d = await r.json();
    if (d.ok) {
      if (span) span.innerHTML = `<span class="text-green">OK — ${esc(d.info || d.status || '')}</span>`;
    } else {
      if (span) span.innerHTML = `<span class="text-red">${esc(d.error || 'failed')}</span>`;
    }
  } catch (e) {
    if (span) span.innerHTML = `<span class="text-red">${esc(e.message)}</span>`;
  }
}

export async function itsmDelete(id) {
  if (!confirm('Delete this integration? Linked tickets will also be removed.')) return;
  try {
    await fetch(API + `/itsm/integrations/${id}`, { method: 'DELETE' });
    clearApiCache();
    if (window.refreshView) window.refreshView();
  } catch (e) {
    alert(e.message);
  }
}
