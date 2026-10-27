// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
import { tabBar } from '../api.js';
import { renderVersioning } from './versioning.js';
import { renderPipelines } from './pipelines.js';
import { renderDeployments } from './deployments.js';

const TABS = [
  ['versioning', 'Versioning'],
  ['pipelines', 'Pipelines'],
  ['deployments', 'Deployments'],
];

export async function renderDelivery(el) {
  const tab = window.deliveryTab || 'versioning';
  const wrap = document.createElement('div');
  wrap.innerHTML = tabBar(TABS, tab, 'delivery');
  const body = document.createElement('div');
  wrap.appendChild(body);
  el.innerHTML = '';
  el.appendChild(wrap);

  if (tab === 'versioning') await renderVersioning(body);
  else if (tab === 'pipelines') await renderPipelines(body);
  else if (tab === 'deployments') await renderDeployments(body);
}
