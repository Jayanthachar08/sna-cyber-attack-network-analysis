/**
 * Sidebar Navigation Component
 */
import { store } from '../state.js';

const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', icon: '🌐' },
  { id: 'network-explorer', label: 'Network Explorer', icon: '🕸️' },
  { id: 'critical-hosts', label: 'Critical Hosts', icon: '🎯' },
  { id: 'communities', label: 'Community Analysis', icon: '👥' },
  { id: 'timeline', label: 'Timeline Analysis', icon: '⏱️' },
  { id: 'evaluation', label: 'Model & Evaluation', icon: '📊' },
  { id: 'reports', label: 'Reports & Exports', icon: '📑' },
];

export function renderSidebar(container) {
  const current = store.get('currentPage');
  const isOnline = store.get('apiOnline');

  container.innerHTML = `
    <div class="sidebar-header">
      <div class="brand-badge">
        <div class="brand-icon">🛡️</div>
        <div>
          <div class="brand-title">SNA Cyber Defense</div>
          <div class="brand-sub">Critical Hosts & Communities</div>
        </div>
      </div>
    </div>

    <div class="sidebar-nav">
      <div class="nav-section-title">Investigation Views</div>
      ${NAV_ITEMS.map(
        (item) => `
        <div class="nav-item ${current === item.id ? 'active' : ''}" data-page="${item.id}">
          <span class="nav-icon">${item.icon}</span>
          <span>${item.label}</span>
        </div>
      `
      ).join('')}
    </div>

    <div class="sidebar-footer">
      <div class="api-status-badge">
        <span class="status-dot ${isOnline ? 'online' : 'offline'}"></span>
        <span>${isOnline ? 'Backend Connected' : 'Connecting to API...'}</span>
      </div>
      <div style="font-size: 11px; color: var(--text-muted); text-align: center;">
        B.Tech CS SNA Project
      </div>
    </div>
  `;

  // Attach nav click handlers
  container.querySelectorAll('.nav-item').forEach((el) => {
    el.addEventListener('click', () => {
      const pageId = el.getAttribute('data-page');
      store.set('currentPage', pageId);
    });
  });
}
