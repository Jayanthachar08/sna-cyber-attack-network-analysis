import pytest
import pandas as pd
import networkx as nx
from src.graph_builder import NetworkGraphBuilder, is_private_ip


def test_private_ip_detection():
    assert is_private_ip("192.168.10.5") is True
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("172.16.1.1") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("104.16.207.165") is False
    assert is_private_ip("not-an-ip") is False


def test_build_graph_from_flows():
    flows = pd.DataFrame({
        "source_ip": ["192.168.10.5", "192.168.10.5", "104.16.207.165", "192.168.10.15"],
        "destination_ip": ["172.16.0.1", "172.16.0.1", "192.168.10.5", "172.16.0.1"],
        "label": ["BENIGN", "DDoS", "BENIGN", "PortScan"],
        "timestamp": ["7/7/2017 10:00", "7/7/2017 10:01", "7/7/2017 10:02", "7/7/2017 10:05"],
        "protocol": [6, 6, 6, 17],
    })

    builder = NetworkGraphBuilder()
    G = builder.build_graph_from_flows(flows)

    assert isinstance(G, nx.DiGraph)
    # 4 unique hosts: 192.168.10.5, 172.16.0.1, 104.16.207.165, 192.168.10.15
    assert G.number_of_nodes() == 4
    # 3 directed edges:
    # (192.168.10.5 -> 172.16.0.1), (104.16.207.165 -> 192.168.10.5), (192.168.10.15 -> 172.16.0.1)
    assert G.number_of_edges() == 3

    # Check edge weight and attack flows on (192.168.10.5 -> 172.16.0.1)
    edge = G["192.168.10.5"]["172.16.0.1"]
    assert edge["weight"] == 2
    assert edge["attack_flows"] == 1
    assert edge["benign_flows"] == 1
    assert edge["attack_ratio"] == 0.5
    assert "DDoS" in edge["attack_types"]

    # Check node attributes
    target_node = G.nodes["172.16.0.1"]
    assert target_node["is_internal"] is True
    assert target_node["received_flows"] == 3
    assert target_node["attack_flows_received"] == 2
    assert target_node["has_attack_evidence"] is True


def test_graph_statistics():
    flows = pd.DataFrame({
        "source_ip": ["192.168.1.1", "192.168.1.2"],
        "destination_ip": ["192.168.1.2", "192.168.1.1"],
        "label": ["BENIGN", "DDoS"],
        "timestamp": ["7/7/2017 10:00", "7/7/2017 10:01"],
        "protocol": [6, 6],
    })
    builder = NetworkGraphBuilder()
    G = builder.build_graph_from_flows(flows)
    stats = builder.get_graph_statistics(G)

    assert stats["num_nodes"] == 2
    assert stats["num_edges"] == 2
    assert stats["total_flow_volume"] == 2
    assert stats["total_attack_flows"] == 1
    assert stats["attack_flow_proportion"] == 0.5
    assert stats["internal_hosts"] == 2


def test_undirected_projection():
    # Reciprocal directed communication between A and B
    flows = pd.DataFrame({
        "source_ip": ["10.0.0.1", "10.0.0.2"],
        "destination_ip": ["10.0.0.2", "10.0.0.1"],
        "label": ["BENIGN", "PortScan"],
        "timestamp": ["7/7/2017 10:00", "7/7/2017 10:01"],
        "protocol": [6, 17],
    })
    builder = NetworkGraphBuilder()
    G = builder.build_graph_from_flows(flows)
    UG = builder.get_undirected_projection(G)

    assert not UG.is_directed()
    assert UG.number_of_nodes() == 2
    assert UG.number_of_edges() == 1  # Collapsed into single undirected edge
    edge = UG["10.0.0.1"]["10.0.0.2"]
    assert edge["weight"] == 2  # 1 + 1
    assert edge["attack_flows"] == 1
    assert "PortScan" in edge["attack_types"]


def test_subgraph_extraction():
    # Create star network with 10 leaf nodes
    edges = []
    for i in range(10):
        edges.append({
            "source_ip": "10.0.0.1",
            "destination_ip": f"10.0.0.{i+10}",
            "label": "BENIGN",
            "timestamp": "7/7/2017 10:00",
            "protocol": 6,
        })
    df = pd.DataFrame(edges)
    builder = NetworkGraphBuilder()
    G = builder.build_graph_from_flows(df)

    assert G.number_of_nodes() == 11
    subG = builder.get_subgraph_for_visualization(G, max_nodes=5)
    assert subG.number_of_nodes() <= 5
    # Hub 10.0.0.1 should be retained due to highest degree
    assert "10.0.0.1" in subG
