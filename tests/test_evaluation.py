import os
import pytest
import numpy as np
import pandas as pd
from src.evaluation import compute_precision_at_k, ModelEvaluator


def test_compute_precision_at_k():
    y_true = np.array([1, 1, 0, 0, 1])
    y_scores = np.array([0.9, 0.8, 0.7, 0.4, 0.1])

    # Top 2 scores: 0.9 (y=1) and 0.8 (y=1) -> Precision@2 = 2/2 = 1.0
    p2 = compute_precision_at_k(y_true, y_scores, k=2)
    assert p2 == 1.0

    # Top 3 scores: 0.9 (1), 0.8 (1), 0.7 (0) -> Precision@3 = 2/3
    p3 = compute_precision_at_k(y_true, y_scores, k=3)
    assert round(p3, 2) == 0.67


def test_evaluate_centrality_rankings():
    df = pd.DataFrame({
        "host_id": [f"10.0.0.{i}" for i in range(10)],
        "degree_centrality": [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.05],
        "betweenness_centrality": [0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.05, 0.0],
        "pagerank": [0.3, 0.2, 0.15, 0.1, 0.08, 0.06, 0.04, 0.03, 0.02, 0.01],
        "combined_criticality": [0.85, 0.75, 0.65, 0.55, 0.45, 0.35, 0.25, 0.15, 0.08, 0.02],
        "attack_flows_associated": [10, 15, 20, 0, 0, 0, 0, 0, 0, 0],  # First 3 hosts are attack-involved
    })

    evaluator = ModelEvaluator()
    res = evaluator.evaluate_centrality_rankings(df, k_values=[3, 5])

    assert res["total_hosts"] == 10
    assert res["attack_involved_hosts"] == 3
    assert res["attack_host_base_rate"] == 0.3

    p_dict = res["precision_at_k"]["Degree Centrality"]
    assert p_dict["P@3"] == 1.0  # Top 3 in degree are all 3 attack hosts
    assert p_dict["P@5"] == 3 / 5


def test_plot_generation(tmp_path):
    evaluator = ModelEvaluator(figures_dir=str(tmp_path))

    # Test plot_precision_at_k
    mock_res = {
        "attack_host_base_rate": 0.25,
        "precision_at_k": {
            "Degree Centrality": {"P@5": 0.8, "P@10": 0.6},
            "PageRank": {"P@5": 0.6, "P@10": 0.5},
        }
    }
    p_path = evaluator.plot_precision_at_k(mock_res, filename="test_prec.png")
    assert os.path.exists(p_path)

    # Test plot_community_attack_enrichment
    comm_df = pd.DataFrame({
        "community_id": [0, 1],
        "size": [25, 10],
        "attack_flow_proportion": [0.75, 0.05],
    })
    c_path = evaluator.plot_community_attack_enrichment(comm_df, filename="test_comm.png")
    assert os.path.exists(c_path)


def test_temporal_predictive_utility():
    t1_centrality = pd.DataFrame({
        "host_id": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
        "combined_criticality": [0.9, 0.8, 0.3, 0.1],
        "degree_centrality": [0.9, 0.7, 0.4, 0.1],
    })

    # In time window T2, an attack occurs involving 10.0.0.1 and 10.0.0.2
    t2_flows = pd.DataFrame({
        "source_ip": ["10.0.0.1", "10.0.0.5"],
        "destination_ip": ["10.0.0.2", "10.0.0.6"],
        "is_attack": [True, False],
    })

    evaluator = ModelEvaluator()
    res = evaluator.evaluate_temporal_predictive_utility(t1_centrality, t2_flows, k=2)

    assert res["combined_criticality_future_P@2"] == 1.0
    assert res["future_attack_hosts_count"] == 2
