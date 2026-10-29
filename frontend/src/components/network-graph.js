/**
 * Cytoscape.js Network Graph Component
 * Interactive host-to-host directed graph visualization with priority tier coloring,
 * community mapping, edge attack highlights, and node selection inspector.
 */

import cytoscape from 'cytoscape';

const TIER_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  INFRASTRUCTURE_WATCH: '#2563eb',
  MEDIUM: '#d97706',
  LOW: '#10b981',
};

const COMMUNITY_PALETTE = [
  '#6366f1', '#06b6d4', '#10b981', '#f59e0b', '#ec4899',
  '#8b5cf6', '#14b8a6', '#f97316', '#3b82f6', '#84cc16'
];

export function initNetworkGraph({
  container,
  nodes,
  edges,
  colorBy = 'priority_tier',
  nodeSizeMetric = 'degree',
  layoutType = 'cose',
  onSelectNode = null,
  onSelectEdge = null,
}) {
  if (!container) return null;

  // Build Cytoscape elements
  const elements = [];

  // Determine scaling ranges for node sizes
  let maxMetric = 1;
  nodes.forEach((n) => {
    let val = 1;
    if (nodeSizeMetric === 'pagerank') val = n.pagerank || 0.001;
    else if (nodeSizeMetric === 'betweenness') val = n.betweenness || 0.001;
    else val = n.degree || 1;
    if (val > maxMetric) maxMetric = val;
  });

  nodes.forEach((n) => {
    let nodeColor = TIER_COLORS[n.priority_tier] || '#64748b';
    if (colorBy === 'community_id' && n.community_id >= 0) {
      nodeColor = COMMUNITY_PALETTE[n.community_id % COMMUNITY_PALETTE.length];
    }

    // Node size formula: min 16px, max 48px
    let rawVal = 1;
    if (nodeSizeMetric === 'pagerank') rawVal = n.pagerank || 0.001;
    else if (nodeSizeMetric === 'betweenness') rawVal = n.betweenness || 0.001;
    else rawVal = n.degree || 1;
    const computedSize = Math.max(18, Math.min(50, 18 + (rawVal / maxMetric) * 32));

    elements.push({
      group: 'nodes',
      data: {
        id: n.id,
        label: n.label,
        is_internal: n.is_internal,
        priority_tier: n.priority_tier,
        community_id: n.community_id,
        degree: n.degree,
        in_degree: n.in_degree,
        out_degree: n.out_degree,
        betweenness: n.betweenness,
        pagerank: n.pagerank,
        combined_criticality: n.combined_criticality,
        attack_flows: n.attack_flows,
        has_attack_evidence: n.has_attack_evidence,
        color: nodeColor,
        size: computedSize,
      },
    });
  });

  edges.forEach((e, idx) => {
    const isAttack = e.has_attack;
    elements.push({
      group: 'edges',
      data: {
        id: `e_${e.source}_${e.target}_${idx}`,
        source: e.source,
        target: e.target,
        weight: e.weight,
        attack_flows: e.attack_flows,
        has_attack: isAttack,
        color: isAttack ? '#ef4444' : '#94a3b8',
        width: isAttack ? 2.5 : Math.max(1, Math.min(4, Math.log10(e.weight + 1) * 1.5)),
        protocols: e.protocols,
        attack_types: e.attack_types,
      },
    });
  });

  const cy = cytoscape({
    container,
    elements,
    style: [
      {
        selector: 'node',
        style: {
          'background-color': 'data(color)',
          label: 'data(label)',
          width: 'data(size)',
          height: 'data(size)',
          'font-size': '10px',
          'font-family': 'ui-monospace, monospace',
          color: '#0f172a',
          'text-valign': 'bottom',
          'text-margin-y': 5,
          'text-outline-color': '#ffffff',
          'text-outline-width': 2,
          'border-width': 2,
          'border-color': '#ffffff',
          'transition-property': 'border-width, border-color, width, height',
          'transition-duration': '0.15s',
        },
      },
      {
        selector: 'node:selected',
        style: {
          'border-color': '#0f172a',
          'border-width': 4,
          'text-outline-width': 3,
        },
      },
      {
        selector: 'edge',
        style: {
          width: 'data(width)',
          'line-color': 'data(color)',
          'target-arrow-color': 'data(color)',
          'target-arrow-shape': 'triangle',
          'arrow-scale': 0.8,
          'curve-style': 'bezier',
          opacity: 0.75,
        },
      },
      {
        selector: 'edge:selected',
        style: {
          width: 4,
          opacity: 1,
          'line-color': '#4f46e5',
          'target-arrow-color': '#4f46e5',
        },
      },
    ],
    layout: {
      name: layoutType === 'circle' ? 'circle' : 'cose',
      animate: false,
      padding: 30,
      nodeRepulsion: 600000,
      idealEdgeLength: 80,
    },
    minZoom: 0.2,
    maxZoom: 3.0,
    wheelSensitivity: 0.3,
  });

  // Attach selection events
  cy.on('tap', 'node', (evt) => {
    const node = evt.target;
    if (onSelectNode) {
      onSelectNode(node.data());
    }
  });

  cy.on('tap', 'edge', (evt) => {
    const edge = evt.target;
    if (onSelectEdge) {
      onSelectEdge(edge.data());
    }
  });

  return cy;
}
