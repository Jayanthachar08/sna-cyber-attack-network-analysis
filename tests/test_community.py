import os
import pytest
import networkx as nx
import pandas as pd
from src.community_detection import CommunityDetector


def build_two_cluster_network():
    """Build a graph with two clear cliques: {A1, A2, A3, A4} and {B1, B2, B3, B4} with 1 bridge."""
    G = nx.DiGraph()

    # Cluster A (internal clique)
    nodes_A = [f"10.0.0.{i}" for i in range(1, 5)]
    for u in nodes_A:
        for v in nodes_A:
            if u != v:
                G.add_edge(u, v, weight=10, attack_flows=0, attack_types="None", protocols="TCP")

    # Cluster B (internal clique with attack traffic)
    nodes_B = [f"192.168.1.{i}" for i in range(1, 5)]
    for u in nodes_B:
        for v in nodes_B:
            if u != v:
                G.add_edge(u, v, weight=10, attack_flows=5, attack_types="DDoS", protocols="TCP")

    # Sparse bridge between clusters
    G.add_edge("10.0.0.1", "192.168.1.1", weight=1, attack_flows=0, attack_types="None", protocols="TCP")

    return G, set(nodes_A), set(nodes_B)


def test_louvain_detects_clusters():
    G, set_A, set_B = build_two_cluster_network()
    detector = CommunityDetector()
    communities, modularity, UG = detector.detect_communities(G, method="louvain")

    # Modularity should be strong (> 0.3)
    assert modularity > 0.3
    # Two main communities should be discovered
    assert len(communities) == 2

    # Verify each community matches set_A or set_B
    found_sets = [c for c in communities]
    assert (found_sets[0] == set_A and found_sets[1] == set_B) or (found_sets[0] == set_B and found_sets[1] == set_A)


def test_greedy_modularity_comparison():
    G, set_A, set_B = build_two_cluster_network()
    detector = CommunityDetector()
    comms, mod, _ = detector.detect_communities(G, method="greedy_modularity")

    assert len(comms) == 2
    assert mod > 0.3


def test_community_summaries_and_persistence(tmp_path):
    G, set_A, set_B = build_two_cluster_network()
    detector = CommunityDetector()
    communities, modularity, UG = detector.detect_communities(G)

    mem_path = str(tmp_path / "test_membership.csv")
    comm_path = str(tmp_path / "test_communities.csv")

    mem_df = detector.build_membership_dataframe(G, communities, save_path=mem_path)
    assert len(mem_df) == 8
    assert os.path.exists(mem_path)

    comm_df = detector.summarize_communities(G, UG, communities, save_path=comm_path)
    assert len(comm_df) == 2
    assert os.path.exists(comm_path)

    # Check metrics
    row_b = comm_df[comm_df["observed_attack_types"].str.contains("DDoS")].iloc[0]
    assert row_b["attack_flows_observed"] > 0
    assert bool(row_b["has_attack_activity"]) is True

    row_a = comm_df[~comm_df["observed_attack_types"].str.contains("DDoS")].iloc[0]
    assert row_a["attack_flows_observed"] == 0
    assert bool(row_a["has_attack_activity"]) is False
