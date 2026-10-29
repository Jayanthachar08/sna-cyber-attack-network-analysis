/**
 * Overview Page Component
 * Summarizes network flows, topological metrics, priority tier distribution,
 * traffic composition, and data ingestion audit.
 */

import { api } from '../api.js';
import { createMetricCard } from '../components/metric-cards.js';
import Plotly from 'plotly.js-dist-min';

export async function renderOverviewPage(container) {
  container.innerHTML = `
    <div class="loading-container">
      <div class="spinner"></div>
      <div>Loading network telemetry and graph metrics...</div>
    </div>
  `;

  try {
    const data = await api.getOverview();

    const attackRatioPercent = (data.attack_flow_proportion * 100).toFixed(1);
    const densityFormatted = data.density.toFixed(5);
    const modularityFormatted = data.modularity.toFixed(4);

    container.innerHTML = `
      <!-- Top Metric Tiles -->
      <div class="metric-grid">
        ${createMetricCard({
          label: 'Analyzed Flows',
          value: Number(data.total_flow_volume).toLocaleString(),
          subtext: 'Flow records in active slice',
          icon: '⚡',
        })}
        ${createMetricCard({
          label: 'Unique Hosts (Nodes)',
          value: Number(data.num_nodes).toLocaleString(),
          subtext: `${data.internal_hosts} Internal / ${data.external_hosts} External`,
          icon: '🖥️',
        })}
        ${createMetricCard({
          label: 'Directed Edges',
          value: Number(data.num_edges).toLocaleString(),
          subtext: `Graph Density: ${densityFormatted}`,
          icon: '🔗',
        })}
        ${createMetricCard({
          label: 'Attack Flows Observed',
          value: Number(data.total_attack_flows).toLocaleString(),
          subtext: `${attackRatioPercent}% of total volume`,
          icon: '🚨',
        })}
        ${createMetricCard({
          label: 'Communities Detected',
          value: data.num_communities,
          subtext: `Modularity Q: ${modularityFormatted}`,
          icon: '👥',
        })}
      </div>

      <!-- Priority Tiers Summary -->
      <div class="heroui-card">
        <div class="card-header">
          <div class="card-title">🛡️ Investigation Priority Breakdown</div>
          <div class="card-subtitle">Heuristic evidence-aware triage of all active hosts</div>
        </div>
        <div class="card-body">
          <div style="display: flex; gap: 12px; flex-wrap: wrap;">
            <div class="metric-card" style="flex:1; min-width:160px; border-left: 4px solid var(--critical);">
              <div class="metric-label" style="color:var(--critical);">Critical Priority</div>
              <div class="metric-value" style="font-size:20px;">${data.priority_tier_counts.CRITICAL || 0} hosts</div>
              <div class="metric-footer">High Centrality + Confirmed Attacks</div>
            </div>
            <div class="metric-card" style="flex:1; min-width:160px; border-left: 4px solid var(--high);">
              <div class="metric-label" style="color:var(--high);">High Priority</div>
              <div class="metric-value" style="font-size:20px;">${data.priority_tier_counts.HIGH || 0} hosts</div>
              <div class="metric-footer">Elevated Risk & Observed Attacks</div>
            </div>
            <div class="metric-card" style="flex:1; min-width:160px; border-left: 4px solid var(--infrastructure);">
              <div class="metric-label" style="color:var(--infrastructure);">Infrastructure Watch</div>
              <div class="metric-value" style="font-size:20px;">${data.priority_tier_counts.INFRASTRUCTURE_WATCH || 0} hosts</div>
              <div class="metric-footer">High Centrality, Zero Attacks (Protect)</div>
            </div>
            <div class="metric-card" style="flex:1; min-width:160px; border-left: 4px solid var(--medium);">
              <div class="metric-label" style="color:var(--medium);">Medium Priority</div>
              <div class="metric-value" style="font-size:20px;">${data.priority_tier_counts.MEDIUM || 0} hosts</div>
              <div class="metric-footer">Moderate Topology or Incident Involvement</div>
            </div>
            <div class="metric-card" style="flex:1; min-width:160px; border-left: 4px solid var(--low);">
              <div class="metric-label" style="color:var(--low);">Low Priority</div>
              <div class="metric-value" style="font-size:20px;">${data.priority_tier_counts.LOW || 0} hosts</div>
              <div class="metric-footer">Normal Peripheral Endpoints</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Two-column charts and audit -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 20px;">
        <!-- Traffic Composition Chart -->
        <div class="heroui-card">
          <div class="card-header">
            <div class="card-title">🥧 Traffic Class Distribution</div>
            <div class="card-subtitle">Benign vs Malicious flows in active sample</div>
          </div>
          <div class="card-body">
            <div id="traffic-pie-chart" style="width: 100%; height: 280px;"></div>
          </div>
        </div>

        <!-- Data Ingestion Audit -->
        <div class="heroui-card">
          <div class="card-header">
            <div class="card-title">📋 Data Ingestion & Sanitization Audit</div>
            <div class="card-subtitle">Validation telemetry from Preprocessor</div>
          </div>
          <div class="card-body">
            <table class="heroui-table">
              <thead>
                <tr>
                  <th>Validation Metric</th>
                  <th>Record Count</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Loaded Raw Records</td>
                  <td><b>${Number(data.cleaning_audit.loaded).toLocaleString()}</b></td>
                  <td><span class="badge badge-neutral">Raw Input</span></td>
                </tr>
                <tr>
                  <td>Retained Valid Flows</td>
                  <td><b>${Number(data.cleaning_audit.retained).toLocaleString()}</b></td>
                  <td><span class="badge badge-low">Verified</span></td>
                </tr>
                <tr>
                  <td>Dropped (Missing IP)</td>
                  <td>${data.cleaning_audit.dropped_missing_ip}</td>
                  <td><span class="badge ${data.cleaning_audit.dropped_missing_ip > 0 ? 'badge-high' : 'badge-neutral'}">Sanitized</span></td>
                </tr>
                <tr>
                  <td>Dropped (Invalid IP)</td>
                  <td>${data.cleaning_audit.dropped_invalid_ip}</td>
                  <td><span class="badge ${data.cleaning_audit.dropped_invalid_ip > 0 ? 'badge-high' : 'badge-neutral'}">Sanitized</span></td>
                </tr>
                <tr>
                  <td>Dropped (Missing Label)</td>
                  <td>${data.cleaning_audit.dropped_missing_label}</td>
                  <td><span class="badge ${data.cleaning_audit.dropped_missing_label > 0 ? 'badge-high' : 'badge-neutral'}">Sanitized</span></td>
                </tr>
                <tr>
                  <td>Unparseable Timestamps</td>
                  <td>${data.cleaning_audit.dropped_unparseable_time}</td>
                  <td><span class="badge badge-neutral">Checked</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Quick Previews of Critical Hosts and Communities -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 20px;">
        <div class="heroui-card">
          <div class="card-header">
            <div class="card-title">🎯 Top Critical Hosts Preview</div>
            <div class="card-subtitle">Ranked by combined graph criticality score</div>
          </div>
          <div class="card-body">
            <table class="heroui-table">
              <thead>
                <tr>
                  <th>Host IP</th>
                  <th>Priority Tier</th>
                  <th>Criticality</th>
                  <th>Attack Flows</th>
                </tr>
              </thead>
              <tbody>
                ${data.top_critical_hosts
                  .map(
                    (h) => `
                  <tr>
                    <td><code>${h.host_id}</code></td>
                    <td><span class="badge badge-${h.priority_tier.toLowerCase().replace('_', '-')}">${h.priority_tier}</span></td>
                    <td><b>${h.combined_criticality}</b></td>
                    <td>${h.attack_flows}</td>
                  </tr>
                `
                  )
                  .join('')}
              </tbody>
            </table>
          </div>
        </div>

        <div class="heroui-card">
          <div class="card-header">
            <div class="card-title">👥 Top Attack-Enriched Communities</div>
            <div class="card-subtitle">Ranked by observed attack flow volume</div>
          </div>
          <div class="card-body">
            <table class="heroui-table">
              <thead>
                <tr>
                  <th>Community</th>
                  <th>Category</th>
                  <th>Hosts</th>
                  <th>Attack Flows</th>
                  <th>Attack %</th>
                </tr>
              </thead>
              <tbody>
                ${data.top_risk_communities
                  .map(
                    (c) => `
                  <tr>
                    <td><b>Community ${c.community_id}</b></td>
                    <td><span class="badge ${c.attack_flows > 0 ? 'badge-critical' : 'badge-low'}">${c.category}</span></td>
                    <td>${c.size}</td>
                    <td>${c.attack_flows}</td>
                    <td>${(c.attack_flow_proportion * 100).toFixed(1)}%</td>
                  </tr>
                `
                  )
                  .join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    // Render Plotly pie chart
    const labels = data.traffic_composition.map((t) => t.traffic_class);
    const values = data.traffic_composition.map((t) => t.count);

    const pieColors = labels.map((l) => {
      const lower = l.toLowerCase();
      if (lower.includes('benign')) return '#10b981';
      if (lower.includes('ddos') || lower.includes('dos')) return '#ef4444';
      if (lower.includes('portscan')) return '#f97316';
      if (lower.includes('web')) return '#eab308';
      if (lower.includes('bot')) return '#8b5cf6';
      return '#3b82f6';
    });

    Plotly.newPlot(
      'traffic-pie-chart',
      [
        {
          labels,
          values,
          type: 'pie',
          hole: 0.45,
          textinfo: 'label+percent',
          hoverinfo: 'label+value+percent',
          marker: { colors: pieColors },
        },
      ],
      {
        margin: { t: 10, b: 10, l: 10, r: 10 },
        paper_bgcolor: 'transparent',
        plot_bgcolor: 'transparent',
        font: { family: 'inherit', color: '#334155', size: 12 },
        showlegend: false,
      },
      { responsive: true, displayModeBar: false }
    );
  } catch (err) {
    container.innerHTML = `
      <div class="callout callout-critical">
        <b>Failed to load overview:</b> ${err.message}
        <br/><br/>
        <button class="btn btn-secondary btn-sm" onclick="location.reload()">Retry</button>
      </div>
    `;
  }
}
