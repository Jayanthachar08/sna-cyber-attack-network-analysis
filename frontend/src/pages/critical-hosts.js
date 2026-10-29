/**
 * Critical Hosts Page Component
 * Sortable, filterable, and paginated host centrality rankings with
 * algorithmic rationale callouts and forensic CSV export.
 */

import { api } from '../api.js';
import { renderTable } from '../components/data-tables.js';

export async function renderCriticalHostsPage(container) {
  let currentPage = 1;
  let pageSize = 25;
  let sortBy = 'combined_criticality';
  let sortDir = 'desc';
  let searchQuery = '';
  let priorityFilter = '';
  let communityFilter = '';
  let selectedHostData = null;

  container.innerHTML = `
    <!-- Filters & Controls Bar -->
    <div class="heroui-card">
      <div class="card-body" style="padding: 16px 20px;">
        <div style="display: flex; gap: 14px; flex-wrap: wrap; align-items: flex-end;">
          <div class="form-group" style="flex: 1; min-width: 180px;">
            <label class="form-label">Search Host IP</label>
            <input type="text" class="input-control" id="host-search" placeholder="Filter by IP..." />
          </div>

          <div class="form-group">
            <label class="form-label">Priority Tier</label>
            <select class="select-control" id="host-tier-filter">
              <option value="ALL">All Tiers</option>
              <option value="CRITICAL">Critical Priority</option>
              <option value="HIGH">High Priority</option>
              <option value="INFRASTRUCTURE_WATCH">Infrastructure Watch</option>
              <option value="MEDIUM">Medium Priority</option>
              <option value="LOW">Low Priority</option>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label">Sort Metric</label>
            <select class="select-control" id="host-sort-by">
              <option value="combined_criticality" selected>Combined Criticality</option>
              <option value="betweenness_centrality">Betweenness Centrality</option>
              <option value="pagerank">PageRank</option>
              <option value="total_degree">Total Degree</option>
              <option value="attack_flows_associated">Attack Flows</option>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label">Direction</label>
            <select class="select-control" id="host-sort-dir">
              <option value="desc" selected>Descending (Top First)</option>
              <option value="asc">Ascending</option>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label">Page Size</label>
            <select class="select-control" id="host-page-size">
              <option value="10">10 per page</option>
              <option value="25" selected>25 per page</option>
              <option value="50">50 per page</option>
              <option value="100">100 per page</option>
            </select>
          </div>

          <a href="${api.getExportUrl('critical-hosts')}" class="btn btn-secondary" download="critical_hosts.csv" style="text-decoration:none;">
            📥 Export CSV
          </a>
        </div>
      </div>
    </div>

    <!-- Table Container -->
    <div class="heroui-card">
      <div class="card-header">
        <div class="card-title">🎯 Host Centrality & Prioritization Table</div>
        <div class="card-subtitle" id="table-summary-count">Loading hosts...</div>
      </div>
      <div id="table-render-area">
        <div class="loading-container"><div class="spinner"></div><div>Loading hosts...</div></div>
      </div>
      <div class="pagination-bar" id="pagination-bar" style="display:none;">
        <div class="pagination-info" id="pagination-info">Showing 0-0 of 0</div>
        <div class="pagination-controls">
          <button class="btn btn-secondary btn-sm" id="btn-prev-page">← Previous</button>
          <button class="btn btn-secondary btn-sm" id="btn-next-page">Next →</button>
        </div>
      </div>
    </div>

    <!-- Algorithmic Explanation Callout Box -->
    <div class="heroui-card" id="explanation-card" style="display:none;">
      <div class="card-header">
        <div class="card-title">🔍 Selected Host Analytical Explanation</div>
        <div class="card-subtitle" id="selected-host-ip-badge">IP Details</div>
      </div>
      <div class="card-body" id="selected-host-explanation-body">
        Select a row above to inspect its algorithmic justification and forensic evidence.
      </div>
    </div>
  `;

  async function loadTable() {
    const tableArea = container.querySelector('#table-render-area');
    const paginationBar = container.querySelector('#pagination-bar');
    const paginationInfo = container.querySelector('#pagination-info');
    const summaryCount = container.querySelector('#table-summary-count');

    tableArea.innerHTML = '<div class="loading-container"><div class="spinner"></div><div>Loading hosts...</div></div>';

    try {
      const res = await api.getHosts({
        page: currentPage,
        pageSize,
        sortBy,
        sortDir,
        search: searchQuery,
        priorityTier: priorityFilter,
        communityId: communityFilter || null,
      });

      summaryCount.textContent = `Found ${res.total_count} matching hosts`;

      const columns = [
        { title: '#', field: 'rank', style: 'width: 50px;' },
        {
          title: 'Host IP',
          field: 'host_id',
          render: (val, row) => `<code>${val}</code> <span style="font-size:11px; color:var(--text-muted);">(${row.is_internal ? 'Int' : 'Ext'})</span>`,
        },
        {
          title: 'Priority Tier',
          field: 'priority_tier',
          render: (val) => `<span class="badge badge-${val.toLowerCase().replace('_', '-')}">${val}</span>`,
        },
        {
          title: 'Criticality',
          field: 'combined_criticality',
          render: (val) => `<b>${val}</b>`,
        },
        { title: 'Degree Cent.', field: 'degree_centrality' },
        { title: 'Betweenness', field: 'betweenness_centrality' },
        { title: 'PageRank', field: 'pagerank' },
        {
          title: 'In / Out',
          field: 'in_degree',
          render: (_, row) => `${row.in_degree} / ${row.out_degree}`,
        },
        { title: 'Comm ID', field: 'community_id' },
        {
          title: 'Attack Flows',
          field: 'attack_flows_associated',
          render: (val) => (val > 0 ? `<b style="color:var(--critical);">${val}</b>` : '0'),
        },
        {
          title: 'Attack Types',
          field: 'observed_attack_types',
          render: (val) => (val !== 'None' ? `<span style="color:var(--critical); font-size:11.5px;">${val}</span>` : '<span style="color:var(--text-muted); font-size:11.5px;">None</span>'),
        },
      ];

      tableArea.innerHTML = renderTable({
        columns,
        data: res.hosts,
        selectedRowKey: selectedHostData?.host_id,
        emptyMessage: 'No hosts match current filter criteria.',
      });

      // Attach row selection
      tableArea.querySelectorAll('tr[data-row-key]').forEach((tr) => {
        tr.addEventListener('click', () => {
          const key = tr.getAttribute('data-row-key');
          const hostObj = res.hosts.find((h) => h.host_id === key);
          if (hostObj) {
            selectedHostData = hostObj;
            showHostExplanation(hostObj);
            // Update table row active styling
            tableArea.querySelectorAll('tr').forEach((r) => r.classList.remove('selected-row'));
            tr.classList.add('selected-row');
          }
        });
      });

      // Update pagination controls
      if (res.total_pages > 1) {
        paginationBar.style.display = 'flex';
        const start = (res.page - 1) * res.page_size + 1;
        const end = Math.min(res.total_count, res.page * res.page_size);
        paginationInfo.textContent = `Showing ${start}-${end} of ${res.total_count} hosts (Page ${res.page} of ${res.total_pages})`;

        const prevBtn = container.querySelector('#btn-prev-page');
        const nextBtn = container.querySelector('#btn-next-page');

        prevBtn.disabled = res.page <= 1;
        nextBtn.disabled = res.page >= res.total_pages;

        prevBtn.onclick = () => {
          if (currentPage > 1) {
            currentPage--;
            loadTable();
          }
        };

        nextBtn.onclick = () => {
          if (currentPage < res.total_pages) {
            currentPage++;
            loadTable();
          }
        };
      } else {
        paginationBar.style.display = 'none';
      }

      // If nothing selected yet and we have rows, auto-select first row
      if (!selectedHostData && res.hosts.length > 0) {
        selectedHostData = res.hosts[0];
        showHostExplanation(res.hosts[0]);
      }
    } catch (err) {
      tableArea.innerHTML = `<div class="callout callout-critical">Failed to load hosts: ${err.message}</div>`;
    }
  }

  function showHostExplanation(host) {
    const card = container.querySelector('#explanation-card');
    const badge = container.querySelector('#selected-host-ip-badge');
    const body = container.querySelector('#selected-host-explanation-body');

    card.style.display = 'block';
    badge.textContent = `Host: ${host.host_id} | ${host.is_internal ? 'Internal' : 'External'} | Community ${host.community_id}`;

    body.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <span class="badge badge-${host.priority_tier.toLowerCase().replace('_', '-')}">${host.priority_tier}</span>
        <span style="font-weight:600;">Combined Criticality Score: <b>${host.combined_criticality}</b></span>
      </div>

      <div class="callout callout-info" style="margin-bottom:10px;">
        <b>Topological Analysis:</b><br/>
        ${host.explanation}
      </div>

      ${host.attack_flows_associated > 0 ? `
        <div class="callout callout-critical">
          <b>Investigative Attack Evidence:</b><br/>
          ${host.investigation_evidence}
        </div>
      ` : `
        <div class="callout" style="border-left-color:var(--low); background-color:var(--low-subtle);">
          <b>Benign Infrastructure Asset:</b><br/>
          Zero attack flows observed in active slice. High centrality is attributed to core structural routing.
        </div>
      `}
    `;
  }

  // Filter Event Listeners
  container.querySelector('#host-search')?.addEventListener('input', (e) => {
    searchQuery = e.target.value.trim();
    currentPage = 1;
    loadTable();
  });

  container.querySelector('#host-tier-filter')?.addEventListener('change', (e) => {
    priorityFilter = e.target.value;
    currentPage = 1;
    loadTable();
  });

  container.querySelector('#host-sort-by')?.addEventListener('change', (e) => {
    sortBy = e.target.value;
    currentPage = 1;
    loadTable();
  });

  container.querySelector('#host-sort-dir')?.addEventListener('change', (e) => {
    sortDir = e.target.value;
    currentPage = 1;
    loadTable();
  });

  container.querySelector('#host-page-size')?.addEventListener('change', (e) => {
    pageSize = parseInt(e.target.value, 10);
    currentPage = 1;
    loadTable();
  });

  // Initial load
  await loadTable();
}
