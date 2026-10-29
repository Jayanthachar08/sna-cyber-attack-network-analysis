/**
 * Main Frontend Application Entrypoint
 * Initializes router, layout components, state subscriptions, and API polling.
 */

import './styles/main.css';
import { store } from './state.js';
import { api } from './api.js';
import { renderSidebar } from './components/sidebar.js';
import { renderHeader } from './components/header.js';

import { renderOverviewPage } from './pages/overview.js';
import { renderNetworkExplorerPage } from './pages/network-explorer.js';
import { renderCriticalHostsPage } from './pages/critical-hosts.js';
import { renderCommunitiesPage } from './pages/communities.js';
import { renderTimelinePage } from './pages/timeline.js';
import { renderEvaluationPage } from './pages/evaluation.js';
import { renderReportsPage } from './pages/reports.js';

const ROUTES = {
  overview: renderOverviewPage,
  'network-explorer': renderNetworkExplorerPage,
  'critical-hosts': renderCriticalHostsPage,
  communities: renderCommunitiesPage,
  timeline: renderTimelinePage,
  evaluation: renderEvaluationPage,
  reports: renderReportsPage,
};

async function initApp() {
  const sidebarEl = document.getElementById('sidebar-container');
  const headerEl = document.getElementById('header-container');
  const contentEl = document.getElementById('page-container');

  // Initial layout render
  renderSidebar(sidebarEl);
  renderHeader(headerEl);

  // Router dispatcher
  async function dispatchRoute(pageId) {
    // Update sidebar active item
    renderSidebar(sidebarEl);
    renderHeader(headerEl);

    const renderFn = ROUTES[pageId] || renderOverviewPage;
    contentEl.innerHTML = '';
    try {
      await renderFn(contentEl);
    } catch (err) {
      contentEl.innerHTML = `
        <div class="callout callout-critical">
          <b>Page Render Error:</b> ${err.message}
        </div>
      `;
    }
  }

  // Subscribe to page state changes
  store.subscribe('currentPage', (newPage) => {
    dispatchRoute(newPage);
  });

  store.subscribe('apiOnline', () => {
    renderSidebar(sidebarEl);
  });

  store.subscribe('datasetStatus', () => {
    renderHeader(headerEl);
  });

  // Verify backend health and dataset status
  try {
    const health = await api.getHealth();
    store.set('apiOnline', health.status === 'ok');

    const status = await api.getDatasetStatus();
    store.set('datasetStatus', status);
  } catch (err) {
    console.warn('Backend not currently reachable:', err.message);
    store.set('apiOnline', false);
  }

  // Initial page load
  await dispatchRoute(store.get('currentPage'));
}

window.addEventListener('DOMContentLoaded', initApp);
