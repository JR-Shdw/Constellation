#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Migrate inline onclick/onchange to data-action/data-change attributes.

Handles the most common patterns automatically.
Edge cases logged for manual review.
"""

import re
import sys
from pathlib import Path

FRONTEND = Path(__file__).resolve().parent.parent / "frontend" / "js"
FILES = sorted(
    list((FRONTEND / "views").glob("*.js"))
    + list((FRONTEND / "panels").glob("*.js"))
    + [FRONTEND / "app.js"]
    + [FRONTEND.parent / "index.html"]
)

# Track what we changed
stats = {"converted": 0, "manual": 0}


def convert_onclick(line: str) -> str:
    """Convert onclick="..." to data-action attributes."""
    original = line

    # Pattern: onclick="event.stopPropagation()" alone (just stop, remove)
    line = re.sub(
        r' onclick="event\.stopPropagation\(\)"',
        ' data-stop',
        line,
    )

    # Pattern: onclick="event.stopPropagation();fn('arg1','arg2')"
    # → data-stop data-action="fn" data-id="arg1" data-value="arg2"
    line = re.sub(
        r""" onclick="event\.stopPropagation\(\);(\w+)\('([^']*?)','([^']*?)'\)""" + '"',
        r' data-stop data-action="\1" data-id="\2" data-value="\3"',
        line,
    )

    # Pattern: onclick="event.stopPropagation();toggleFlag('cid','flag',bool,this)"
    line = re.sub(
        r""" onclick="event\.stopPropagation\(\);toggleFlag\('([^']*?)','([^']*?)',([^,]*?),this\)""" + '"',
        r' data-stop data-action="toggleFlag" data-id="\1" data-flag="\2" data-value="\3"',
        line,
    )

    # Pattern: onclick="window.fn('arg')" → data-action="fn" data-id="arg"
    line = re.sub(
        r""" onclick="window\.(\w+)\('([^']*?)'\)""" + '"',
        r' data-action="\1" data-id="\2"',
        line,
    )

    # Pattern: onclick="window.fn()" → data-action="fn"
    line = re.sub(
        r""" onclick="window\.(\w+)\(\)""" + '"',
        r' data-action="\1"',
        line,
    )

    # Pattern: onclick="fn('arg1','arg2','arg3',this)"
    # editRepoField('id','field','value',this) → data-action="editRepoField" data-id="id" data-field="field" data-value="value"
    line = re.sub(
        r""" onclick="editRepoField\('([^']*?)','([^']*?)','([^']*?)',this\)""" + '"',
        r' data-action="editRepoField" data-id="\1" data-field="\2" data-value="\3"',
        line,
    )

    # Pattern: onclick="editCheckAddress('id','addr')"
    line = re.sub(
        r""" onclick="editCheckAddress\('([^']*?)','([^']*?)'\)""" + '"',
        r' data-action="editCheckAddress" data-id="\1" data-addr="\2"',
        line,
    )

    # Pattern: onclick="editExposure('id','exposure')"
    line = re.sub(
        r""" onclick="editExposure\('([^']*?)','([^']*?)'\)""" + '"',
        r' data-action="editExposure" data-id="\1" data-exposure="\2"',
        line,
    )

    # Pattern: onclick="toggleFeature('name',bool)"
    line = re.sub(
        r""" onclick="toggleFeature\('([^']*?)',\s*([^)]+?)\)""" + '"',
        r' data-action="toggleFeature" data-feature="\1" data-value="\2"',
        line,
    )

    # Pattern: onclick="togglePkgRepo('id',bool)"
    line = re.sub(
        r""" onclick="togglePkgRepo\('([^']*?)',\s*([^)]+?)\)""" + '"',
        r' data-action="togglePkgRepo" data-id="\1" data-value="\2"',
        line,
    )

    # Pattern: onclick="removeSsoRow(N)"
    line = re.sub(
        r""" onclick="removeSsoRow\(([^)]+?)\)""" + '"',
        r' data-action="removeSsoRow" data-index="\1"',
        line,
    )

    # Pattern: onclick="window._setTrendDays(N)"
    line = re.sub(
        r""" onclick="window\._setTrendDays\(([^)]+?)\)""" + '"',
        r' data-action="setTrendDays" data-days="\1"',
        line,
    )

    # Pattern: onclick="document.getElementById('xxx').style.display='none'"
    line = re.sub(
        r""" onclick="document\.getElementById\('([^']+?)'\)\.style\.display='none'""" + '"',
        r' data-action="hideEl" data-target="\1"',
        line,
    )

    # Pattern: onclick="fn('arg')" — most common (single-arg functions)
    # Sort functions: sortX('col') → data-action="sortX" data-col="col"
    sort_fns = "sortNodes|sortContainers|sortCves|sortPackages|sortHeartbeat|sortCompliance|sortMisconf|sortSecrets"
    line = re.sub(
        rf""" onclick="({sort_fns})\('([^']*?)'\)""" + '"',
        r' data-action="\1" data-col="\2"',
        line,
    )

    # setCveGroup('mode') → data-action="setCveGroup" data-value="mode"
    line = re.sub(
        r""" onclick="setCveGroup\('([^']*?)'\)""" + '"',
        r' data-action="setCveGroup" data-value="\1"',
        line,
    )
    # setCveGroup(null) → data-action="setCveGroup" data-value=""
    line = re.sub(
        r""" onclick="setCveGroup\(null\)""" + '"',
        r' data-action="setCveGroup" data-value=""',
        line,
    )

    # setThreshold('t') → data-action="setThreshold" data-value="t"
    line = re.sub(
        r""" onclick="setThreshold\('([^']*?)'\)""" + '"',
        r' data-action="setThreshold" data-value="\1"',
        line,
    )

    # Generic: onclick="fn('arg')" → data-action="fn" data-id="arg"
    # Only for known safe functions (takes single string arg as ID)
    id_fns = (
        "showNode|showCVEDetail|showImageHosts|showPackageHosts|showOsNodes|showImpact|showManagerImages"
        "|deleteToken|revokeToken|activateToken|regenerateToken"
        "|deleteManager|testManager|pullImage"
        "|deleteCicdServer|testCicdServer"
        "|testWebhook|deleteWebhook"
        "|deletePolicy|approveLog|skipLog"
        "|triggerJob|toggleSchedulerJob|deleteSchedulerJob|editSchedulerJob|saveSchedulerJob"
        "|deleteRepo|checkOneRepo|editPkgRepo|deletePkgRepo"
        "|approveDeployment|rejectDeployment|executeDeployment|submitDeployment"
        "|submitDeployment"
    )
    line = re.sub(
        rf""" onclick="({id_fns})\('([^']*?)'\)""" + '"',
        r' data-action="\1" data-id="\2"',
        line,
    )

    # Generic: onclick="fn()" → data-action="fn"  (no-arg functions)
    noarg_fns = (
        "saveSettings|toggleTriage|checkAllRepos|createToken|createDeployment"
        "|revokeAllNodeTokens|deleteExpiredTokens|addManager|addCicdServer|addSsoRow"
        "|showAddJobForm|showAddPkgRepoForm|showAddPolicyForm|showAddRepoForm|showAddWebhookForm"
        "|submitPolicy|submitAddRepo|submitPkgRepo|submitSchedulerJob|submitWebhook"
        "|resetCve|resyncOpencve|resyncWazuh|saveSsoGroups|syncWorkers|checkVault"
        "|runCheckUpdates|runHeartbeatCheck|toggleUpgradeFilter"
        "|closeDetail|toggleFullscreen|toggleSidebar"
    )
    line = re.sub(
        rf""" onclick="({noarg_fns})\(\)""" + '"',
        r' data-action="\1"',
        line,
    )

    # window.backupShowNodePicker('id',this)
    line = re.sub(
        r""" onclick="window\.backupShowNodePicker\('([^']*?)',this\)""" + '"',
        r' data-action="backupShowNodePicker" data-id="\1"',
        line,
    )

    # window.backupDeleteSelected()
    line = re.sub(
        r""" onclick="window\.backupDeleteSelected\(\)""" + '"',
        r' data-action="backupDeleteSelected"',
        line,
    )

    # window.cleanupXxx('arg') or window.cleanupXxx()
    line = re.sub(
        r""" onclick="window\.cleanup(\w+)\('([^']*?)'\)""" + '"',
        r' data-action="cleanup\1" data-value="\2"',
        line,
    )
    line = re.sub(
        r""" onclick="window\.cleanup(\w+)\(\)""" + '"',
        r' data-action="cleanup\1"',
        line,
    )

    # window._exportXxx() → data-action="exportXxx"
    line = re.sub(
        r""" onclick="window\._export(\w+)\(\)""" + '"',
        r' data-action="export\1"',
        line,
    )

    # window._updSort('col') / window._updFilter('v')
    line = re.sub(
        r""" onclick="window\._updSort\('([^']*?)'\)""" + '"',
        r' data-action="updSort" data-col="\1"',
        line,
    )
    line = re.sub(
        r""" onclick="window\._updFilter\('([^']*?)'\)""" + '"',
        r' data-action="updFilter" data-value="\1"',
        line,
    )

    # window._expSort('col')
    line = re.sub(
        r""" onclick="window\._expSort\('([^']*?)'\)""" + '"',
        r' data-action="expSort" data-col="\1"',
        line,
    )

    # window._intelSort('col')
    line = re.sub(
        r""" onclick="window\._intelSort\('([^']*?)'\)""" + '"',
        r' data-action="intelSort" data-col="\1"',
        line,
    )

    # window.repoSort('col')
    line = re.sub(
        r""" onclick="window\.repoSort\('([^']*?)'\)""" + '"',
        r' data-action="repoSort" data-col="\1"',
        line,
    )

    # window.backupSort('col')
    line = re.sub(
        r""" onclick="window\.backupSort\('([^']*?)'\)""" + '"',
        r' data-action="backupSort" data-col="\1"',
        line,
    )

    # event.preventDefault();window.location.hash='settings'
    line = re.sub(
        r""" onclick="event\.preventDefault\(\);window\.location\.hash='([^']*?)'""" + '"',
        r' data-action="goHash" data-hash="\1"',
        line,
    )

    # fn() fallback — cover any remaining no-arg onclick
    line = re.sub(
        r""" onclick="(\w+)\(\)""" + '"',
        r' data-action="\1"',
        line,
    )

    if line != original:
        stats["converted"] += 1
    elif 'onclick="' in line.lower():
        stats["manual"] += 1

    return line


def convert_onchange(line: str) -> str:
    """Convert onchange="..." to data-change attributes."""
    original = line

    # Pattern: onchange="fn('id1','id2',this.value,el)"
    # setCveWorkflow('cveId','nodeId',this.value,document.getElementById('uid_j'))
    line = re.sub(
        r""" onchange="setCveWorkflow\('([^']*?)','([^']*?)',this\.value,document\.getElementById\('([^']*?)'\)\)""" + '"',
        r' data-change="setCveWorkflow" data-cve="\1" data-node="\2" data-justif="\3"',
        line,
    )

    # setCveWorkflow('cveId','nodeId',this.value)
    line = re.sub(
        r""" onchange="setCveWorkflow\('([^']*?)','([^']*?)',this\.value\)""" + '"',
        r' data-change="setCveWorkflow" data-cve="\1" data-node="\2"',
        line,
    )

    # patchFinding('type','id','field',this.value)
    line = re.sub(
        r""" onchange="patchFinding\('([^']*?)','([^']*?)','([^']*?)',this\.value\)""" + '"',
        r' data-change="patchFinding" data-type="\1" data-id="\2" data-field="\3"',
        line,
    )

    # patchRepo('id','field',this.checked)
    line = re.sub(
        r""" onchange="patchRepo\('([^']*?)','([^']*?)',this\.checked\)""" + '"',
        r' data-change="patchRepoChecked" data-id="\1" data-field="\2"',
        line,
    )
    # patchRepo('id','field',this.value)
    line = re.sub(
        r""" onchange="patchRepo\('([^']*?)','([^']*?)',this\.value\)""" + '"',
        r' data-change="patchRepo" data-id="\1" data-field="\2"',
        line,
    )

    # togglePolicy('id',this.checked)
    line = re.sub(
        r""" onchange="togglePolicy\('([^']*?)',this\.checked\)""" + '"',
        r' data-change="togglePolicy" data-id="\1"',
        line,
    )

    # setNodeEnv('id',this.value)
    line = re.sub(
        r""" onchange="setNodeEnv\('([^']*?)',this\.value\)""" + '"',
        r' data-change="setNodeEnv" data-id="\1"',
        line,
    )

    # window.backupToggle('id',this.checked)
    line = re.sub(
        r""" onchange="window\.backupToggle\('([^']*?)',this\.checked\)""" + '"',
        r' data-change="backupToggle" data-id="\1"',
        line,
    )

    # window.backupToggleAll(this.checked)
    line = re.sub(
        r""" onchange="window\.backupToggleAll\(this\.checked\)""" + '"',
        r' data-change="backupToggleAll"',
        line,
    )

    # window.backupAssignNode('id',this.value)
    line = re.sub(
        r""" onchange="window\.backupAssignNode\('([^']*?)',this\.value\)""" + '"',
        r' data-change="backupAssignNode" data-id="\1"',
        line,
    )

    # window._clToggleAll(this.checked)
    line = re.sub(
        r""" onchange="window\._clToggleAll\(this\.checked\)""" + '"',
        r' data-change="clToggleAll"',
        line,
    )

    # window._clUpdateCount()
    line = re.sub(
        r""" onchange="window\._clUpdateCount\(\)""" + '"',
        r' data-change="clUpdateCount"',
        line,
    )

    # fn('id',this.value) pattern — patchSecret, patchMisconf
    for fn in ("patchSecret", "patchMisconf"):
        line = re.sub(
            rf""" onchange="{fn}\('([^']*?)',this\.value\)""" + '"',
            rf' data-change="{fn}" data-id="\1"',
            line,
        )

    # fn(this.value) pattern — simple value handlers
    for fn in (
        "filterComplianceEnv", "filterComplianceHost", "filterMisconfStatus",
        "filterSecretsStatus", "filterSecretsSev", "filterSecretsSearch",
    ):
        line = re.sub(
            rf""" onchange="{fn}\(this\.value\)""" + '"',
            rf' data-change="{fn}"',
            line,
        )

    # window._expFilterHost(this.value) / window._expFilterExp(this.value)
    line = re.sub(
        r""" onchange="window\._expFilter(\w+)\(this\.value\)""" + '"',
        r' data-change="expFilter\1"',
        line,
    )

    # window._repoFilterExposure / _repoFilterRegistry / _repoSearch
    line = re.sub(
        r""" onchange="window\._repoFilter(\w+)\(this\.value\)""" + '"',
        r' data-change="repoFilter\1"',
        line,
    )
    line = re.sub(
        r""" onchange="window\._repoSearch\(this\.value\)""" + '"',
        r' data-change="repoSearch"',
        line,
    )

    # opencveMatchedOnly=this.checked;currentPage=1;loadView()
    line = re.sub(
        r""" onchange="opencveMatchedOnly=this\.checked;currentPage=1;(?:loadView\(\)|navigate\(currentView\))""" + '"',
        r' data-change="opencveMatchedOnly"',
        line,
    )

    # Complex inline: document.querySelectorAll('.cve-noise')... → data-change="toggleCveNoise"
    line = re.sub(
        r""" onchange="document\.querySelectorAll\('\.cve-noise'\).*?""" + '"',
        r' data-change="toggleCveNoise"',
        line,
    )

    if line != original:
        stats["converted"] += 1
    elif 'onchange="' in line.lower():
        stats["manual"] += 1

    return line


def convert_onmouseover(line: str) -> str:
    """Remove onmouseover/onmouseout (replace with CSS :hover)."""
    line = re.sub(r""" onmouseover="this\.style\.\w+='[^']*?'""" + '"', '', line)
    line = re.sub(r""" onmouseout="this\.style\.\w+='[^']*?'""" + '"', '', line)
    return line


def cleanup_escjs(line: str) -> str:
    """Replace escJs() with esc() in data attributes (no longer onclick context)."""
    # In data-id="${escJs(x)}" → data-id="${esc(x)}"
    # escJs was only needed for onclick JS string context
    line = line.replace("escJs(", "esc(")
    return line


def process_file(path: Path, dry_run: bool = False) -> int:
    """Process one file. Returns number of lines changed."""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    changed = 0

    new_lines = []
    for line in lines:
        orig = line
        line = convert_onclick(line)
        line = convert_onchange(line)
        line = convert_onmouseover(line)
        line = cleanup_escjs(line)
        if line != orig:
            changed += 1
        new_lines.append(line)

    if changed and not dry_run:
        path.write_text("".join(new_lines), encoding="utf-8")

    return changed


def main():
    dry_run = "--dry-run" in sys.argv
    total_changed = 0

    for f in FILES:
        if not f.exists():
            continue
        n = process_file(f, dry_run=dry_run)
        if n:
            print(f"  {f.name}: {n} lines {'would change' if dry_run else 'changed'}")
            total_changed += n

    print(f"\nTotal: {total_changed} lines, {stats['converted']} patterns converted, {stats['manual']} need manual review")

    if stats["manual"]:
        print("\nRemaining inline handlers (manual review needed):")
        for f in FILES:
            if not f.exists():
                continue
            text = f.read_text()
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(r'on(click|change)="', line, re.IGNORECASE):
                    print(f"  {f.name}:{i} — {line.strip()[:100]}")


if __name__ == "__main__":
    main()
