// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
// starfield.js — twinkling blue stars behind CMDB CONSTELLATION header
// 100% pixelarray v2 API — dot() + clear() only

import { PixelArray } from './lib/pixelarray.js';
import { _h } from './api.js';

const BLUES = [
  [100, 150, 255],
  [60, 100, 230],
  [80, 130, 250],
  [40, 80, 200],
  [140, 180, 255],
  [50, 70, 180],
  [90, 120, 220],
  [120, 160, 240],
];

const _stars = [];
let _px = null;
let _running = false;

function _spawn(count, w, h) {
  for (let i = 0; i < count; i++) {
    const t = BLUES[Math.floor(Math.random() * BLUES.length)];
    _stars.push({
      x: Math.floor(Math.random() * w),
      y: 1 + Math.floor(Math.random() * Math.max(h - 2, 1)),
      r: t[0], g: t[1], b: t[2],
      alpha: 0, phase: 'in',
      speed: 0.005 + Math.random() * 0.012,
      hold: 40 + Math.floor(Math.random() * 100),
    });
  }
}

function _schedule(w, h) {
  setTimeout(() => {
    _spawn(1 + Math.floor(Math.random() * 2), w, h);
    _schedule(w, h);
  }, 3000 + Math.random() * 9000);
}

function _animate() {
  if (!_px) return;

  _px.clear();

  for (let i = _stars.length - 1; i >= 0; i--) {
    const s = _stars[i];
    if (s.phase === 'in') {
      s.alpha = Math.min(s.alpha + s.speed, 1);
      if (s.alpha >= 1) s.phase = 'hold';
    } else if (s.phase === 'hold') {
      if (--s.hold <= 0) s.phase = 'out';
    } else {
      s.alpha -= s.speed;
      if (s.alpha <= 0) { _stars.splice(i, 1); continue; }
    }

    _px.dot(s.x, s.y, s.r, s.g, s.b, s.alpha);
    // Subtle glow
    const ga = s.alpha * 0.2;
    if (ga > 0.02) {
      _px.dot(s.x - 1, s.y, s.r, s.g, s.b, ga);
      _px.dot(s.x + 1, s.y, s.r, s.g, s.b, ga);
    }
  }

  // Loading pixels animation
  if (_loadActive) {
    const first = document.getElementById('lp0');
    if (!first || !document.contains(first)) { _loadActive = false; }
    else {
      if (++_loadFrame >= _LOAD_SPEED) {
        _loadFrame = 0;
        if (_loadIdx < _LOAD_COUNT) {
          const lc = document.getElementById('lp' + _loadIdx);
          if (lc) {
            const lpx = new PixelArray(lc, { pixelSize: 4 });
            const t = BLUES[_loadIdx % BLUES.length];
            lpx.dot(0, 0, t[0], t[1], t[2], 0.9);
          }
          _loadIdx++;
        } else {
          for (let j = 0; j < _LOAD_COUNT; j++) {
            const lc = document.getElementById('lp' + j);
            if (lc) {
              const lpx = new PixelArray(lc, { pixelSize: 4 });
              lpx.clear();
            }
          }
          _loadIdx = 0;
        }
      }
    }
  }

  requestAnimationFrame(_animate);
}

export function initStarfield() {
  const c = document.getElementById('sidebar-stars');
  if (!c) return;
  const h1 = c.parentElement;
  c.width = h1.offsetWidth;
  c.height = h1.offsetHeight;
  _px = new PixelArray(c, { pixelSize: 1 });
  _spawn(1, c.width, c.height);
  _schedule(c.width, c.height);
  if (!_running) { _running = true; _animate(); }
}

// Loading pixel animation (10 pixels, sequential)
let _loadIdx = 0;
let _loadFrame = 0;
let _loadActive = false;
const _LOAD_COUNT = 10;
const _LOAD_SPEED = 6;

export function initLoadingAnim(el) {
  let dots = '';
  for (let i = 0; i < _LOAD_COUNT; i++) dots += `<canvas id="lp${i}" width="4" height="4" class="load-pixel"></canvas>`;
  el.innerHTML = `<div class="loading-pixels">${_h(dots)}<span>Loading...</span></div>`;
  _loadIdx = 0; _loadFrame = 0; _loadActive = true;
}

export function startLoadingPx() {
  _loadIdx = 0; _loadFrame = 0; _loadActive = true;
}

// Sidebar spark indicators
export async function updateSparks() {
  try {
    const res = await fetch('/api/v1/stats');
    const s = await res.json();
    document.querySelectorAll('.nav-spark').forEach(el => el.remove());
    const rules = [
      { view: 'cves', on: (s.cves_critical || 0) > 0, color: 'red' },
      { view: 'misconf', on: (s.misconf_open || 0) > 0, color: 'red' },
      { view: 'secrets', on: (s.secrets_open || 0) > 0, color: 'red' },
      { view: 'backups', on: (s.backups_failed || 0) > 0, color: 'red' },
      { view: 'backups', on: (s.backups_overdue || 0) > 0 && !(s.backups_failed > 0), color: 'orange' },
      { view: 'automation', on: (s.automation_pending || 0) > 0, color: 'orange' },
    ];
    for (const r of rules) {
      if (!r.on) continue;
      const link = document.querySelector(`nav a[data-view="${r.view}"]`);
      if (!link || link.querySelector('.nav-spark')) continue;
      const dot = document.createElement('span');
      dot.className = `nav-spark ${r.color}`;
      link.appendChild(dot);
    }
  } catch { /* silent */ }
}
