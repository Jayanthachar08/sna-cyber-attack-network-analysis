/**
 * Network Explorer Page Component
 * Interactive Cytoscape.js directed graph with node coloring, layout options,
 * host search, edge flow inspections, and side drawer host inspector.
 */

import { api } from '../api.js';
import { initNetworkGraph } from '../components/network-graph.js';
import { store } from '../state.js';

export async function renderNetworkExplorerPage(container) {
  container.innerHTML = `
    <!-- Graph Controls Header -->
    <div class="heroui-card">
      <div class="card-body" style="padding: 14px 20px;">
        <div style="display: flex; gap: 16px; flex-wrap: wrap; align-items: flex-end;">
          <div class="form-group">
            <label class="form-label">Color Nodes By</label>
            <select class="select-control" id="net-color-by">
              <option value="priority_tier" selected>Priority Tier</option>
              <option value="community_id">Community Cluster</option>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label">Node Size By</label>
            <select class="select-control" id="net-size-by">
              <option value="degree" selected>Degree Centrality</option>
              <option value="pagerank">PageRank</option>
              <option value="betweenness">Betweenness Centrality</option>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label">Max Vis Nodes</label>
            <select class="select-control" id="net-max-nodes">
              <option value="50">50 nodes (Fast)</option>
              <option value="100" selected>100 nodes (Balanced)</option>
              <option value="150">150 nodes (Detailed)</option>
              <option value="200">200 nodes (Full)</option>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label">Layout</label>
            <select class="select-control" id="net-layout">
              <option value="cose" selected>Force-Directed (CoSE)</option>
              <option value="circle">Circular</option>
            </select>
          </div>

          <div class="form-group" style="flex: 1; min-width: 200px;">
            <label class="form-label">Locate Host IP</label>
            <div style="display: flex; gap: 6px;">
              <input type="text" class="input-control" id="net-search-ip" placeholder="e.g. 192.168.10.50" style="flex:1;" />
              <button class="btn btn-secondary btn-sm" id="net-search-btn">Find</button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Cytoscape Canvas Container -->
    <div class="cytoscape-wrapper">
      <div id="cy"></div>

      <!-- Floating Toolbar -->
      <div class="cytoscape-toolbar">
        <button class="btn btn-secondary btn-sm" id="cy-zoom-in" title="Zoom In">➕</button>
        <button class="btn btn-secondary btn-sm" id="cy-zoom-out" title="Zoom Out">➖</button>
        <button class="btn btn-secondary btn-sm" id="cy-fit" title="Fit to Viewport">⛶ Fit</button>
        <button class="btn btn-secondary btn-sm" id="cy-reset" title="Reset Layout">🔄 Reset</button>
      </div>

      <!-- Legend -->
      <div class="cytoscape-legend">
        <div style="font-weight: 600; font-size: 11px; margin-bottom: 2px;">Priority Tiers</div>
        <div class="legend-item"><span class="legend-swatch" style="background:#ef4444;"></span> Critical (Attacks + Topo)</div>
        <div class="legend-item"><span class="legend-swatch" style="background:#f97316;"></span> High Priority</div>
        <div class="legend-item"><span class="legend-swatch" style="background:#2563eb;"></span> Infrastructure Watch (Core Asset)</div>
        <div class="legend-item"><span class="legend-swatch" style="background:#d97706;"></span> Medium Priority</div>
        <div class="legend-item"><span class="legend-swatch" style="background:#10b981;"></span> Low Priority (Peripheral)</div>
        <div class="legend-item" style="margin-top:4px; border-top:1px solid #e2e8f0; padding-top:4px;">
          <span style="display:inline-block;width:12px;height:2px;background:#ef4444;margin-right:6px;"></span> Attack Edge
        </div>
        <div class="legend-item">
          <span style="display:inline-block;width:12px;height:1px;background:#94a3b8;margin-right:6px;"></span> Benign Edge
        </div>
      </div>
    </div>

    <!-- Host Detail Side Drawer -->
    <div class="drawer-backdrop" id="host-drawer-backdrop"></div>
    <div class="drawer-panel" id="host-drawer-panel">
      <div class="drawer-header">
        <div>
          <div style="font-size:16px; font-weight:700;" id="drawer-host-title">Host Inspector</div>
          <div style="font-size:12px; color:var(--text-muted);" id="drawer-host-subnet">Subnet Details</div>
        </div>
        <button class="close-btn" id="close-drawer-btn">✕</button>
      </div>
      <div class="drawer-body" id="drawer-host-body">
        <div class="spinner"></div>
      </div>
    </div>
  `;

  let cyInstance = null;

  async function loadGraphData() {
    const colorBy = container.querySelector('#net-color-by').value;
    const sizeBy = container.querySelector('#net-size-by').value;
    const maxNodes = parseInt(container.querySelector('#net-max-nodes').value, 10);
    const layout = container.querySelector('#net-layout').value;

    const cyContainer = container.querySelector('#cy');
    cyContainer.innerHTML = `
      <div class="loading-container" style="height:100%;">
        <div class="spinner"></div>
        <div>Generating interactive network topology...</div>
      </div>
    `;

    try {
      const netData = await api.getNetwork({ maxNodes });
      cyContainer.innerHTML = '';

      cyInstance = initNetworkGraph({
        container: cyContainer,
        nodes: netData.nodes,
        edges: netData.edges,
        colorBy,
        nodeSizeMetric: sizeBy,
        layoutType: layout,
        onSelectNode: (nodeData) => {
          openHostDrawer(nodeData.id);
        },
        onSelectEdge: (edgeData) => {
          showEdgeToast(edgeData);
        },
      });
    } catch (err) {
      cyContainer.innerHTML = `
        <div style="padding:24px; color:var(--critical);">
          Failed to load graph data: ${err.message}
        </div>
      `;
    }
  }

  // Drawer interactions
  const drawerPanel = container.querySelector('#host-drawer-panel');
  const drawerBackdrop = container.querySelector('#host-drawer-backdrop');
  const closeDrawerBtn = container.querySelector('#close-drawer-btn');

  function closeHostDrawer() {
    drawerPanel.classList.remove('open');
    drawerBackdrop.style.display = 'none';
  }

  closeDrawerBtn?.addEventListener('click', closeHostDrawer);
  drawerBackdrop?.addEventListener('click', closeHostDrawer);

  async function openHostDrawer(hostId) {
    drawerBackdrop.style.display = 'block';
    drawerPanel.classList.add('open');

    const titleEl = container.querySelector('#drawer-host-title');
    const subnetEl = container.querySelector('#drawer-host-subnet');
    const bodyEl = container.querySelector('#drawer-host-body');

    titleEl.textContent = hostId;
    bodyEl.innerHTML = '<div class="loading-container"><div class="spinner"></div><div>Loading host details & connections...</div></div>';

    try {
      const detail = await api.getHostDetail(hostId);
      const h = detail.host;

      subnetEl.textContent = `${h.is_internal ? 'Internal RFC 1918 Host' : 'External Internet Host'} | Community ${h.community_id}`;

      bodyEl.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <span class="badge badge-${h.priority_tier.toLowerCase().replace('_', '-')}">${h.priority_tier}</span>
          <span style="font-weight:600; font-size:13px;">Criticality: <b>${h.combined_criticality}</b></span>
        </div>

        <div class="callout callout-info" style="font-size:12.5px;">
          <b>Topological Rationale:</b><br/>
          ${h.explanation || 'Calculated based on degree, betweenness, and PageRank metrics.'}
        </div>

        ${h.attack_flows_associated > 0 ? `
          <div class="callout callout-critical" style="font-size:12.5px;">
            <b>Observed Attack Evidence:</b><br/>
            ${h.investigation_evidence || 'Host was observed participating in attack-labeled flow telemetry.'}
          </div>
        ` : `
          <div class="callout" style="font-size:12.5px; border-left-color: var(--low); background-color: var(--low-subtle);">
            <b>Benign Topological Host:</b><br/>
            Zero attack flows observed. Categorized under infrastructure watch to prevent false alarms.
          </div>
        `}

        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
          <div class="metric-card" style="padding:10px 14px;">
            <div class="metric-label">In / Out Degree</div>
            <div class="metric-value" style="font-size:16px;">${h.in_degree} in / ${h.out_degree} out</div>
          </div>
          <div class="metric-card" style="padding:10px 14px;">
            <div class="metric-label">Betweenness</div>
            <div class="metric-value" style="font-size:16px;">${h.betweenness_centrality}</div>
          </div>
          <div class="metric-card" style="padding:10px 14px;">
            <div class="metric-label">PageRank</div>
            <div class="metric-value" style="font-size:16px;">${h.pagerank}</div>
          </div>
          <div class="metric-card" style="padding:10px 14px;">
            <div class="metric-label">Attack Flows</div>
            <div class="metric-value" style="font-size:16px; color:${h.attack_flows_associated > 0 ? 'var(--critical)' : 'inherit'};">
              ${h.attack_flows_associated}
            </div>
          </div>
        </div>

        <div>
          <div style="font-weight:600; font-size:13px; margin-bottom:8px;">
            Active Connections (${detail.incoming_connections.length + detail.outgoing_connections.length} total)
          </div>
          <div class="table-container" style="max-height:220px; overflow-y:auto;">
            <table class="heroui-table">
              <thead>
                <tr>
                  <th>Direction</th>
                  <th>Peer Host</th>
                  <th>Flows</th>
                  <th>Attacks</th>
                </tr>
              </thead>
              <tbody>
                ${detail.incoming_connections.map((c) => `
                  <tr>
                    <td><span class="badge badge-neutral">Incoming</span></td>
                    <td><code>${c.peer_ip}</code></td>
                    <td>${c.flow_volume}</td>
                    <td>${c.attack_flows > 0 ? `<b style="color:var(--critical);">${c.attack_flows}</b>` : '0'}</td>
                  </tr>
                `).join('')}
                ${detail.outgoing_connections.map((c) => `
                  <tr>
                    <td><span class="badge badge-neutral">Outgoing</span></td>
                    <td><code>${c.peer_ip}</code></td>
                    <td>${c.flow_volume}</td>
                    <td>${c.attack_flows > 0 ? `<b style="color:var(--critical);">${c.attack_flows}</b>` : '0'}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `;
    } catch (err) {
      bodyEl.innerHTML = `<div class="callout callout-critical">Failed to load host detail: ${err.message}</div>`;
    }
  }

  function showEdgeToast(edgeData) {
    alert(
      `Directed Communication Link:\n` +
      `From: ${edgeData.source}\n` +
      `To: ${edgeData.target}\n` +
      `Total Flows: ${edgeData.weight}\n` +
      `Attack Flows: ${edgeData.attack_flows}\n` +
      `Protocols: ${edgeData.protocols}\n` +
      `Attack Types: ${edgeData.attack_types}`
    );
  }

  // Filter change handlers
  ['net-color-by', 'net-size-by', 'net-max-nodes', 'net-layout'].forEach((id) => {
    container.querySelector(`#${id}`)?.addEventListener('change', loadGraphData);
  });

  // Search Host IP
  const searchInput = container.querySelector('#net-search-ip');
  const searchBtn = container.querySelector('#net-search-btn');

  const doSearch = () => {
    const q = searchInput?.value.trim();
    if (!q || !cyInstance) return;

    const node = cyInstance.getElementById(q);
    if (node && node.length > 0) {
      cyInstance.elements().unselect();
      node.select();
      cyInstance.animate({
        center: { eles: node },
        zoom: 1.5,
        duration: 400,
      });
      openHostDrawer(q);
    } else {
      alert(`Host "${q}" was not found in the current subgraph. Try increasing Max Vis Nodes or check IP address.`);
    }
  };

  searchBtn?.addEventListener('click', doSearch);
  searchInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doSearch();
  });

  // Toolbar Actions
  container.querySelector('#cy-zoom-in')?.addEventListener('click', () => {
    if (cyInstance) cyInstance.zoom(cyInstance.zoom() * 1.25);
  });
  container.querySelector('#cy-zoom-out')?.addEventListener('click', () => {
    if (cyInstance) cyInstance.zoom(cyInstance.zoom() * 0.8);
  });
  container.querySelector('#cy-fit')?.addEventListener('click', () => {
    if (cyInstance) cyInstance.fit(null, 30);
  });
  container.querySelector('#cy-reset')?.addEventListener('click', () => {
    loadGraphData();
  });

  // Initial load
  await loadGraphData();
}
