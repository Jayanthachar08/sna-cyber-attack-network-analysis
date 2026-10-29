/**
 * Community Analysis Page Component
 * Visualizes Louvain community partitions, Newman-Girvan modularity,
 * community size vs attack concentration, and member host inspection.
 */

import { api } from '../api.js';
import { createMetricCard } from '../components/metric-cards.js';
import { renderTable } from '../components/data-tables.js';
import Plotly from 'plotly.js-dist-min';

export async function renderCommunitiesPage(container) {
  container.innerHTML = `
    <div class="loading-container">
      <div class="spinner"></div>
      <div>Loading community partitions and modularity metrics...</div>
    </div>
  `;

  try {
    const data = await api.getCommunities();
    const communities = data.communities;

    const malCount = communities.filter((c) => c.attack_flows_observed > 0).length;
    const avgDensity =
      communities.length > 0
        ? (communities.reduce((acc, c) => acc + c.density, 0) / communities.length).toFixed(4)
        : '0.0000';

    container.innerHTML = `
      <!-- Community Summary Cards -->
      <div class="metric-grid">
        ${createMetricCard({
          label: 'Detected Communities',
          value: data.total_communities,
          subtext: `Optimal partition via Louvain`,
          icon: '👥',
        })}
        ${createMetricCard({
          label: 'Newman-Girvan Modularity (Q)',
          value: data.modularity.toFixed(4),
          subtext: 'Q > 0.3 indicates strong community structure',
          icon: '📐',
        })}
        ${createMetricCard({
          label: 'Attack-Enriched Communities',
          value: malCount,
          subtext: `${malCount} of ${data.total_communities} contain attack flows`,
          icon: '🚨',
        })}
        ${createMetricCard({
          label: 'Average Cohesion Density',
          value: avgDensity,
          subtext: 'Internal link density across clusters',
          icon: '📊',
        })}
      </div>

      <!-- Methodological Disclosure Callout -->
      <div class="callout callout-info">
        <b>Academic Methodological Principle:</b><br/>
        Louvain modularity optimization detects topological structural clusters. Enterprise networks naturally partition into departments, functional server farms, and subnets.
        <b>A cluster is not labeled malicious merely because it is structurally dense.</b>
        Suspicion is evaluated strictly by correlating structural boundaries with empirical attack-labeled flow telemetry.
      </div>

      <!-- Community Table -->
      <div class="heroui-card">
        <div class="card-header">
          <div class="card-title">👥 Community Risk & Structural Statistics</div>
          <a href="${api.getExportUrl('communities')}" class="btn btn-secondary btn-sm" download="communities.csv" style="text-decoration:none;">
            📥 Export CSV
          </a>
        </div>
        <div class="card-body" style="padding:0;">
          <div id="community-table-container"></div>
        </div>
      </div>

      <!-- Community Size vs Attack Flow Proportion Chart -->
      <div class="heroui-card">
        <div class="card-header">
          <div class="card-title">📊 Community Size vs Attack Flow Proportion</div>
          <div class="card-subtitle">Examines whether attack flows concentrate within specific structural subnets</div>
        </div>
        <div class="card-body">
          <div id="community-bar-chart" style="width: 100%; height: 320px;"></div>
        </div>
      </div>

      <!-- Inspect Specific Community Members -->
      <div class="heroui-card">
        <div class="card-header">
          <div class="card-title">🔍 Inspect Member Hosts in Community</div>
          <div style="display:flex; align-items:center; gap:8px;">
            <label class="form-label" style="margin:0;">Select Community:</label>
            <select class="select-control" id="select-community-id">
              ${communities.map((c) => `<option value="${c.community_id}">Community ${c.community_id} (${c.size} hosts, ${c.attack_flows_observed} attack flows)</option>`).join('')}
            </select>
          </div>
        </div>
        <div class="card-body" id="community-members-area">
          <div class="spinner"></div>
        </div>
      </div>
    `;

    // Render Community Table
    const tableContainer = container.querySelector('#community-table-container');
    const columns = [
      {
        title: 'Community ID',
        field: 'community_id',
        render: (val) => `<b>Community ${val}</b>`,
      },
      {
        title: 'Threat Classification',
        field: 'community_threat_category',
        render: (val) => {
          const isMal = val === 'MALICIOUS_CLUSTER';
          const isMix = val === 'MIXED_SUSPICIOUS';
          return `<span class="badge ${isMal ? 'badge-critical' : isMix ? 'badge-high' : 'badge-low'}">${val}</span>`;
        },
      },
      { title: 'Hosts (Size)', field: 'size' },
      { title: 'Internal Density', field: 'density' },
      { title: 'Internal Edges', field: 'internal_edges' },
      { title: 'External Edges', field: 'external_edges' },
      {
        title: 'Attack Flows',
        field: 'attack_flows_observed',
        render: (val) => (val > 0 ? `<b style="color:var(--critical);">${val}</b>` : '0'),
      },
      {
        title: 'Attack Ratio',
        field: 'attack_flow_proportion',
        render: (val) => `${(val * 100).toFixed(1)}%`,
      },
      { title: 'Attack Hosts', field: 'attack_associated_hosts' },
      {
        title: 'Key Representative Hosts',
        field: 'top_hosts',
        render: (val) => `<code style="font-size:11px;">${val}</code>`,
      },
    ];

    tableContainer.innerHTML = renderTable({
      columns,
      data: communities,
      rowKeyField: 'community_id',
    });

    // Render Plotly Bar Chart
    const commIds = communities.map((c) => `Community ${c.community_id}`);
    const commSizes = communities.map((c) => c.size);
    const attackRatios = communities.map((c) => +(c.attack_flow_proportion * 100).toFixed(1));

    Plotly.newPlot(
      'community-bar-chart',
      [
        {
          x: commIds,
          y: commSizes,
          name: 'Host Count',
          type: 'bar',
          marker: {
            color: attackRatios,
            colorscale: [
              [0, '#10b981'],
              [0.3, '#f59e0b'],
              [1, '#ef4444'],
            ],
            colorbar: {
              title: 'Attack Flow %',
              len: 0.8,
            },
          },
          hovertemplate: '<b>%{x}</b><br>Size: %{y} hosts<br>Attack Ratio: %{marker.color}%<extra></extra>',
        },
      ],
      {
        margin: { t: 20, b: 40, l: 40, r: 20 },
        paper_bgcolor: 'transparent',
        plot_bgcolor: 'transparent',
        font: { family: 'inherit', color: '#334155', size: 12 },
        xaxis: { title: 'Community' },
        yaxis: { title: 'Number of Member Hosts' },
      },
      { responsive: true, displayModeBar: false }
    );

    // Member inspection logic
    const selectComm = container.querySelector('#select-community-id');
    const membersArea = container.querySelector('#community-members-area');

    async function loadCommunityMembers(cid) {
      membersArea.innerHTML = '<div class="loading-container"><div class="spinner"></div><div>Loading member hosts...</div></div>';
      try {
        const detail = await api.getCommunityDetail(cid);
        const memCols = [
          { title: '#', field: 'rank', style: 'width:50px;' },
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
          { title: 'Criticality', field: 'combined_criticality' },
          { title: 'Total Degree', field: 'total_degree' },
          {
            title: 'Attack Flows',
            field: 'attack_flows_associated',
            render: (val) => (val > 0 ? `<b style="color:var(--critical);">${val}</b>` : '0'),
          },
          {
            title: 'Topological Explanation',
            field: 'explanation',
            render: (val) => `<span style="font-size:12px;">${val}</span>`,
          },
        ];

        membersArea.innerHTML = renderTable({
          columns: memCols,
          data: detail.members,
          rowKeyField: 'host_id',
        });
      } catch (err) {
        membersArea.innerHTML = `<div class="callout callout-critical">Failed to load member hosts: ${err.message}</div>`;
      }
    }

    if (communities.length > 0) {
      loadCommunityMembers(communities[0].community_id);
      selectComm?.addEventListener('change', () => {
        loadCommunityMembers(parseInt(selectComm.value, 10));
      });
    } else {
      membersArea.innerHTML = '<div style="color:var(--text-muted); padding:20px;">No communities found.</div>';
    }
  } catch (err) {
    container.innerHTML = `<div class="callout callout-critical">Failed to load community analysis: ${err.message}</div>`;
  }
}
