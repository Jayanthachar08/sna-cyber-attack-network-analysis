"""
Plotly Interactive Network Graph Component.
Renders host-to-host topology with layout algorithms, community coloring,
edge traffic weights, and attack evidence highlights.
"""

from typing import Dict, Any, Optional, List
import networkx as nx
import plotly.graph_objects as go
import numpy as np


def create_plotly_network_figure(
    G: nx.DiGraph,
    color_by: str = "priority_tier",  # 'priority_tier' or 'community_id'
    node_size_metric: str = "degree",  # 'degree' or 'pagerank'
    layout_type: str = "spring",  # 'spring' or 'circular'
    host_risk_df: Optional[Any] = None,
) -> go.Figure:
    """
    Generate an interactive Plotly figure representing the host communication network.
    """
    if G.number_of_nodes() == 0:
        fig = go.Figure()
        fig.update_layout(
            title="No hosts match current filter criteria.",
            paper_bgcolor="#0e1117",
            plot_bgcolor="#0e1117",
            font=dict(color="#94a3b8"),
        )
        return fig

    # Merge risk attributes if provided
    risk_dict = {}
    if host_risk_df is not None and not host_risk_df.empty:
        for _, r in host_risk_df.iterrows():
            risk_dict[r["host_id"]] = r.to_dict()

    # Calculate 2D coordinates
    if layout_type == "circular":
        pos = nx.circular_layout(G)
    else:
        # Spring layout with reasonable iterations
        k_val = 1.0 / np.sqrt(G.number_of_nodes()) if G.number_of_nodes() > 0 else 0.2
        pos = nx.spring_layout(G, k=k_val, seed=42, iterations=50)

    # Prepare Edges
    edge_x = []
    edge_y = []
    attack_edge_x = []
    attack_edge_y = []

    for u, v, d in G.edges(data=True):
        if u not in pos or v not in pos:
            continue
        x0, y0 = pos[u]
        x1, y1 = pos[v]

        has_att = d.get("attack_flows", 0) > 0
        if has_att:
            attack_edge_x.extend([x0, x1, None])
            attack_edge_y.extend([y0, y1, None])
        else:
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

    # Benign edge trace
    benign_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=0.8, color="#334155"),
        hoverinfo="none",
        mode="lines",
        name="Benign Traffic",
    )

    # Attack edge trace
    attack_trace = go.Scatter(
        x=attack_edge_x,
        y=attack_edge_y,
        line=dict(width=1.8, color="#ef4444"),
        hoverinfo="none",
        mode="lines",
        name="Attack-Labeled Traffic",
    )

    # Prepare Nodes
    node_x = []
    node_y = []
    node_text = []
    node_color = []
    node_size = []

    tier_color_map = {
        "CRITICAL": "#ef4444",           # Bright red
        "HIGH": "#f97316",               # Orange
        "INFRASTRUCTURE_WATCH": "#3b82f6",# Blue
        "MEDIUM": "#eab308",             # Yellow
        "LOW": "#10b981",                # Green
    }

    # Community color palette
    palette = [
        "#38bdf8", "#f43f5e", "#a855f7", "#10b981", "#fbbf24",
        "#6366f1", "#14b8a6", "#ec4899", "#84cc16", "#06b6d4"
    ]

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

        node_data = G.nodes[node]
        r_info = risk_dict.get(node, {})

        deg = G.degree(node)
        in_d = G.in_degree(node)
        out_d = G.out_degree(node)
        tier = r_info.get("priority_tier", "LOW" if not node_data.get("has_attack_evidence", False) else "HIGH")
        comm_id = r_info.get("community_id", node_data.get("community_id", 0))
        att_flows = node_data.get("total_attack_flows", r_info.get("attack_flows_associated", 0))
        att_types = node_data.get("attack_types", r_info.get("observed_attack_types", "None"))
        is_int = node_data.get("is_internal", False)

        # Determine node color
        if color_by == "community_id":
            c_idx = abs(int(comm_id)) % len(palette)
            node_color.append(palette[c_idx])
        else:
            node_color.append(tier_color_map.get(tier, "#94a3b8"))

        # Determine node size
        base_size = 8
        if node_size_metric == "pagerank":
            pr = r_info.get("pagerank", 0.01)
            size = min(35, max(8, int(pr * 500)))
        else:
            size = min(35, max(8, int(np.log1p(deg) * 6)))
        node_size.append(size)

        # Hover tooltip
        tooltip = (
            f"<b>Host IP:</b> {node} ({'Internal' if is_int else 'External'})<br>"
            f"<b>Priority Tier:</b> {tier}<br>"
            f"<b>Community:</b> C{comm_id}<br>"
            f"<b>Connections:</b> Total={deg} (In={in_d}, Out={out_d})<br>"
            f"<b>Total Flows:</b> {node_data.get('total_flows', 0):,}<br>"
            f"<b>Attack Flows:</b> {att_flows:,}<br>"
            f"<b>Observed Attacks:</b> {att_types}"
        )
        node_text.append(tooltip)

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers",
        hoverinfo="text",
        text=node_text,
        marker=dict(
            color=node_color,
            size=node_size,
            line=dict(width=1.5, color="#0f172a"),
            opacity=0.9,
        ),
        name="Network Hosts",
    )

    fig = go.Figure(
        data=[benign_trace, attack_trace, node_trace],
        layout=go.Layout(
            showlegend=True,
            hovermode="closest",
            margin=dict(b=10, l=10, r=10, t=30),
            paper_bgcolor="#0e1117",
            plot_bgcolor="#0e1117",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1,
                font=dict(color="#cbd5e1", size=10),
            ),
        ),
    )

    return fig
