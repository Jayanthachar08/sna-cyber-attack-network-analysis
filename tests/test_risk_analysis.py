import os
import pytest
import pandas as pd
from src.risk_analysis import RiskAnalyzer


def test_separation_of_centrality_and_attack():
    # 4 hosts representing distinct investigative cases
    hosts = pd.DataFrame([
        {
            # Central benign server (e.g. DNS or Active Directory)
            "host_id": "192.168.10.1",
            "combined_criticality": 0.95,
            "degree_centrality": 0.9,
            "betweenness_centrality": 0.85,
            "pagerank": 0.9,
            "total_flows": 1000,
            "attack_flows_associated": 0,
            "observed_attack_types": "None",
            "community_id": 0,
        },
        {
            # Compromised core server / Target under attack
            "host_id": "192.168.10.50",
            "combined_criticality": 0.90,
            "degree_centrality": 0.8,
            "betweenness_centrality": 0.80,
            "pagerank": 0.85,
            "total_flows": 800,
            "attack_flows_associated": 600,
            "observed_attack_types": "DDoS",
            "community_id": 1,
        },
        {
            # Peripheral external attacker / bot
            "host_id": "104.16.200.1",
            "combined_criticality": 0.05,
            "degree_centrality": 0.05,
            "betweenness_centrality": 0.0,
            "pagerank": 0.01,
            "total_flows": 100,
            "attack_flows_associated": 95,
            "observed_attack_types": "PortScan",
            "community_id": 1,
        },
        {
            # Normal client workstation
            "host_id": "192.168.10.15",
            "combined_criticality": 0.05,
            "degree_centrality": 0.02,
            "betweenness_centrality": 0.0,
            "pagerank": 0.01,
            "total_flows": 50,
            "attack_flows_associated": 0,
            "observed_attack_types": "None",
            "community_id": 0,
        },
    ])

    analyzer = RiskAnalyzer()
    risk_df = analyzer.compute_host_risk(hosts, save_path=None)

    # Case 1: Benign central server MUST NOT be labeled malicious
    row_server = risk_df[risk_df["host_id"] == "192.168.10.1"].iloc[0]
    assert row_server["observed_attack_evidence"] == 0.0
    assert row_server["priority_tier"] == "INFRASTRUCTURE_WATCH"
    assert "critical benign backbone" in row_server["investigation_evidence"].lower()

    # Case 2: Target under attack with high centrality and attack flows
    row_target = risk_df[risk_df["host_id"] == "192.168.10.50"].iloc[0]
    assert row_target["observed_attack_evidence"] > 0.5
    assert row_target["priority_tier"] == "CRITICAL"
    assert "critical priority" in row_target["investigation_evidence"].lower()

    # Case 3: External attacker
    row_attacker = risk_df[risk_df["host_id"] == "104.16.200.1"].iloc[0]
    assert row_attacker["observed_attack_evidence"] > 0.5
    assert row_attacker["priority_tier"] in ["HIGH", "CRITICAL"]

    # Case 4: Normal workstation
    row_normal = risk_df[risk_df["host_id"] == "192.168.10.15"].iloc[0]
    assert row_normal["priority_tier"] == "LOW"


def test_community_risk_classification(tmp_path):
    comms = pd.DataFrame([
        {
            "community_id": 0,
            "size": 50,
            "density": 0.1,
            "total_flow_volume": 5000,
            "attack_flows_observed": 4000,
            "attack_flow_proportion": 0.80,
            "observed_attack_types": "DDoS",
        },
        {
            "community_id": 1,
            "size": 20,
            "density": 0.2,
            "total_flow_volume": 2000,
            "attack_flows_observed": 0,
            "attack_flow_proportion": 0.0,
            "observed_attack_types": "None",
        },
    ])

    analyzer = RiskAnalyzer()
    out_path = str(tmp_path / "test_comm_risk.csv")
    comm_risk = analyzer.compute_community_risk(comms, save_path=out_path)

    assert len(comm_risk) == 2
    assert os.path.exists(out_path)

    row_mal = comm_risk[comm_risk["community_id"] == 0].iloc[0]
    assert row_mal["community_threat_category"] == "MALICIOUS_CLUSTER"

    row_benign = comm_risk[comm_risk["community_id"] == 1].iloc[0]
    assert row_benign["community_threat_category"] != "MALICIOUS_CLUSTER"
