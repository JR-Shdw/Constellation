// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
/**
 * Black hole animation — pixelarray spiral aspiration + relativistic jets.
 * 100% pixelarray v2 API — dot() + fade() only.
 *
 * Usage:
 *   import { blackholeInit, blackholeSetState, blackholeDestroy } from './blackhole.js';
 *   blackholeInit('canvas-id');         // start animation
 *   blackholeSetState(false);           // unsealed = active glow + jets
 *   blackholeDestroy();                 // stop + cleanup
 */
'use strict';

import { PixelArray } from './lib/pixelarray.js';

const BH = {
  px: null,
  particles: [],
  jets: [],
  sealed: true,
  w: 0,
  h: 0,
  cx: 0,
  cy: 0,
  radius: 4,
};

export function blackholeInit(canvasId) {
  const el = document.getElementById(canvasId);
  if (!el) return;
  BH.px = new PixelArray(el, { pixelSize: 1 });
  BH.particles = [];

  const w = el.width, h = el.height;
  BH.w = w; BH.h = h;
  BH.cx = w / 2; BH.cy = h / 2;
  BH.radius = w >= 120 ? 10 : 4;

  const pCount = w >= 120 ? 400 : 100;
  const maxDist = BH.cx * 0.75;
  const minDist = w >= 120 ? 6 : 3;

  for (let i = 0; i < pCount; i++) {
    const dist = minDist + Math.random() * maxDist;
    BH.particles.push({
      angle: Math.random() * Math.PI * 2,
      dist,
      baseDist: dist,
      speed: (0.006 + Math.random() * 0.018) / (dist * 0.04),
      brightness: 0.2 + Math.random() * 0.8,
      hue: Math.random() > 0.45 ? 'v' : 'c',
      trail: [],
      trailMax: w >= 120 ? 4 + Math.floor(Math.random() * 7) : 2,
    });
  }

  BH.jets = [];
  const jCount = w >= 120 ? 40 : 12;
  for (let i = 0; i < jCount; i++) {
    BH.jets.push(_bhNewJet());
  }

  BH.px.run(() => { _bhFrame(); });
}

export function blackholeSetState(sealed) {
  BH.sealed = sealed;
}

export function blackholeDestroy() {
  if (BH.px) BH.px.stop();
  BH.px = null;
  BH.particles = [];
  BH.jets = [];
}

function _bhNewJet() {
  const { cx, cy, radius } = BH;
  const up = Math.random() > 0.5;
  const speed = BH.w >= 120 ? 0.6 + Math.random() * 1.2 : 0.3 + Math.random() * 0.6;
  return {
    x: cx + (Math.random() - 0.5) * 2,
    y: up ? cy - radius - 1 - Math.random() * 3 : cy + radius + 1 + Math.random() * 3,
    vy: up ? -speed : speed,
    brightness: 0.4 + Math.random() * 0.6,
    life: 0.6 + Math.random() * 0.4,
  };
}

function _bhFrame() {
  const px = BH.px;
  const { particles, jets, sealed, w, h, cx, cy, radius } = BH;

  px.fade(5, 5, 8, 0.07);

  // Event horizon — filled ellipse
  for (let dy = -radius; dy <= radius; dy++) {
    for (let dx = -radius; dx <= radius; dx++) {
      if (dx * dx + dy * dy <= radius * radius) {
        px.dot(cx + dx, cy + dy, 5, 5, 8);
      }
    }
  }

  // Glow when unsealed
  if (!sealed) {
    const glowR = radius + (w >= 120 ? 40 : 12);
    for (let ring = 0; ring < 4; ring++) {
      const r = radius + 2 + ring * ((glowR - radius) / 4);
      const a = 0.08 - ring * 0.02;
      if (a <= 0) break;
      for (let ang = 0; ang < Math.PI * 2; ang += 0.08) {
        const blend = ring / 3;
        const rv = Math.floor(124 * (1 - blend) + 6 * blend);
        const gv = Math.floor(58 * (1 - blend) + 182 * blend);
        const bv = Math.floor(237 * (1 - blend) + 212 * blend);
        px.dot(
          (cx + Math.cos(ang) * r) | 0,
          (cy + Math.sin(ang) * r) | 0,
          rv, gv, bv, a);
      }
    }
  }

  // Particles
  for (let i = 0; i < particles.length; i++) {
    const p = particles[i];
    p.angle += p.speed;

    const pull = sealed ? 0.003 : 0.015 + (0.08 / p.dist);
    p.dist -= pull;

    if (p.dist < radius + 0.5) {
      p.dist = p.baseDist;
      p.angle = Math.random() * Math.PI * 2;
      p.trail = [];
      continue;
    }

    const x = cx + Math.cos(p.angle) * p.dist;
    const y = cy + Math.sin(p.angle) * p.dist * 0.35;

    const dx = x - cx, dy = y - cy;
    if (dx * dx + dy * dy < radius * radius) continue;

    const rv = p.hue === 'v' ? 124 : 6;
    const gv = p.hue === 'v' ? 58 : 182;
    const bv = p.hue === 'v' ? 237 : 212;
    let alpha = p.brightness;
    if (sealed) alpha *= 0.1;

    // Trail
    if (p.trailMax > 1) {
      p.trail.push({ x, y });
      if (p.trail.length > p.trailMax) p.trail.shift();
      for (let t = 0; t < p.trail.length; t++) {
        const ta = alpha * (t / p.trail.length) * 0.35;
        px.dot(p.trail[t].x | 0, p.trail[t].y | 0, rv, gv, bv, ta);
      }
    }

    px.dot(x | 0, y | 0, rv, gv, bv, alpha);
  }

  // Photon ring
  if (!sealed) {
    for (let ang = 0; ang < Math.PI * 2; ang += 0.1) {
      px.dot(
        (cx + Math.cos(ang) * (radius + 1)) | 0,
        (cy + Math.sin(ang) * (radius + 1)) | 0,
        124, 58, 237, 0.35);
    }
  }

  // Relativistic jets — only when unsealed
  if (!sealed) {
    const fadeScale = w >= 120 ? 75 : 18;
    const topLimit = 2;
    const bottomLimit = h - 2;

    // Static beam core — continuous bright line
    for (let dy = -(cy - topLimit); dy < -radius - 1; dy++) {
      const fade = Math.max(0, 1 - Math.abs(dy) / fadeScale);
      if (fade <= 0) continue;
      const spread = fade * 0.8;
      px.dot(cx, cy + dy, 180, 180, 255, fade * 0.15);
      if (w >= 120) {
        px.dot(cx - 1, cy + dy, 124, 58, 237, fade * 0.06 * spread);
        px.dot(cx + 1, cy + dy, 124, 58, 237, fade * 0.06 * spread);
      }
    }
    for (let dy = radius + 2; dy < bottomLimit - cy; dy++) {
      const fade = Math.max(0, 1 - dy / fadeScale);
      if (fade <= 0) continue;
      const spread = fade * 0.8;
      px.dot(cx, cy + dy, 180, 180, 255, fade * 0.15);
      if (w >= 120) {
        px.dot(cx - 1, cy + dy, 124, 58, 237, fade * 0.06 * spread);
        px.dot(cx + 1, cy + dy, 124, 58, 237, fade * 0.06 * spread);
      }
    }

    // Moving particles along the beam
    for (let i = 0; i < jets.length; i++) {
      const j = jets[i];
      j.y += j.vy;
      j.life -= 0.015;

      if (j.life <= 0 || j.y < topLimit || j.y > bottomLimit) {
        jets[i] = _bhNewJet();
        continue;
      }

      const a = j.life * j.brightness;
      const dist = Math.abs(j.y - cy);
      const blend = Math.min(1, dist / (fadeScale * 0.8));
      const rv = Math.floor(200 * (1 - blend) + 6 * blend);
      const gv = Math.floor(200 * (1 - blend) + 182 * blend);
      const bv = Math.floor(255 * (1 - blend) + 212 * blend);
      px.dot(j.x | 0, j.y | 0, rv, gv, bv, a * 0.8);
    }
  }
}
