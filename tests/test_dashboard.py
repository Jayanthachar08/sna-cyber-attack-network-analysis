import pytest
import os
import networkx as nx
import pandas as pd
import plotly.graph_objects as go
from dashboard.components.network_graph import create_plotly_network_figure
from dashboard.app import run_pipeline


def test_plotly_network_figure_empty():
    G = nx.DiGraph()
    fig = create_plotly_network_figure(G)
    assert isinstance(fig, go.Figure)


def test_plotly_network_figure_with_nodes():
    G = nx.DiGraph()
    G.add_edge("10.0.0.1", "10.0.0.2", weight=10, attack_flows=2)
    G.nodes["10.0.0.1"]["is_internal"] = True
    G.nodes["10.0.0.2"]["is_internal"] = True

    risk_df = pd.DataFrame([
        {"host_id": "10.0.0.1", "priority_tier": "HIGH", "community_id": 0, "pagerank": 0.5},
        {"host_id": "10.0.0.2", "priority_tier": "CRITICAL", "community_id": 0, "pagerank": 0.5},
    ])

    fig = create_plotly_network_figure(G, host_risk_df=risk_df)
    assert isinstance(fig, go.Figure)
    assert len(fig.data) >= 3  # benign trace, attack trace, node trace


def test_dashboard_pipeline_run_integration():
    file_path = os.path.join("Datasets", "TrafficLabelling", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    if os.path.exists(file_path):
        res = run_pipeline(file_path, max_rows=1000, skip_rows=95000)
        assert "G" in res
        assert "graph_stats" in res
        assert "host_risk_df" in res
        assert "comm_risk_df" in res
        assert "eval_results" in res
        assert res["graph_stats"]["num_nodes"] > 0
