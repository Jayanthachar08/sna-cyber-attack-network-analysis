import os
import pytest
import networkx as nx
import pandas as pd
from src.centrality_analysis import CentralityAnalyzer, min_max_scale


def test_min_max_scale():
    s = pd.Series([10.0, 20.0, 30.0, 40.0, 50.0])
    scaled = min_max_scale(s)
    assert scaled.min() == 0.0
    assert scaled.max() == 1.0
    assert scaled.iloc[2] == 0.5

    # Constant series
    s_const = pd.Series([5.0, 5.0, 5.0])
    scaled_const = min_max_scale(s_const)
    assert (scaled_const == 0.0).all()


def test_bridge_host_betweenness():
    # Build a bridge topology: (Cluster 1: A, B, C) -> Bridge X -> (Cluster 2: D, E, F)
    G = nx.DiGraph()
    # Cluster 1 internal
    G.add_edge("10.0.0.1", "10.0.0.2", weight=5)
    G.add_edge("10.0.0.2", "10.0.0.3", weight=5)
    G.add_edge("10.0.0.3", "10.0.0.1", weight=5)

    # Connections to bridge X (10.0.0.100)
    G.add_edge("10.0.0.1", "10.0.0.100", weight=10)
    G.add_edge("10.0.0.100", "192.168.1.1", weight=10)

    # Cluster 2 internal
    G.add_edge("192.168.1.1", "192.168.1.2", weight=5)
    G.add_edge("192.168.1.2", "192.168.1.3", weight=5)
    G.add_edge("192.168.1.3", "192.168.1.1", weight=5)

    analyzer = CentralityAnalyzer()
    df = analyzer.compute_all_centralities(G)

    assert len(df) == 7
    bridge_row = df[df["host_id"] == "10.0.0.100"].iloc[0]
    # Bridge should have highest betweenness centrality in this topology
    assert bridge_row["betweenness_centrality"] == df["betweenness_centrality"].max()
    assert "bridge" in bridge_row["explanation"].lower() or "gateway" in bridge_row["explanation"].lower()


def test_star_network_degree_and_pagerank():
    # Star graph: Central server receives connections from 5 clients
    G = nx.DiGraph()
    server = "192.168.10.50"
    for i in range(5):
        client = f"10.0.0.{i+1}"
        G.add_edge(client, server, weight=10)

    analyzer = CentralityAnalyzer()
    df = analyzer.compute_all_centralities(G)

    server_row = df[df["host_id"] == server].iloc[0]
    assert server_row["in_degree"] == 5
    assert server_row["out_degree"] == 0
    # Central server should have highest PageRank and in-degree
    assert server_row["pagerank"] == df["pagerank"].max()
    assert server_row["combined_criticality"] == df["combined_criticality"].max()
    assert "sink" in server_row["explanation"].lower() or "incoming" in server_row["explanation"].lower()


def test_rank_hosts_and_export(tmp_path):
    G = nx.DiGraph()
    G.add_edge("10.0.0.1", "10.0.0.2", weight=1)
    G.add_edge("10.0.0.2", "10.0.0.3", weight=1)

    analyzer = CentralityAnalyzer()
    df = analyzer.compute_all_centralities(G)

    export_path = str(tmp_path / "test_critical_hosts.csv")
    ranked = analyzer.rank_hosts(df, sort_by="combined_criticality", top_k=2, save_path=export_path)

    assert len(ranked) == 2
    assert os.path.exists(export_path)
    loaded = pd.read_csv(export_path)
    assert len(loaded) == 2
    assert "host_id" in loaded.columns
