"""
Network Graph Construction Module.
Constructs directed, weighted graphs using NetworkX from aggregated network flows.
Supports:
- Directed communication modeling (Source IP -> Destination IP).
- Edge weights (observed flow volume).
- Edge and node level attack evidence aggregation.
- Temporal filtering across configurable time windows.
- Comprehensive structural statistics (nodes, edges, density, components).
- Undirected projection for community detection.
- Subgraph extraction for performant, responsive visualization.
"""

import ipaddress
import logging
from typing import Dict, Any, Optional, Tuple, List, Set
import networkx as nx
import pandas as pd
from src.preprocessing import Preprocessor

logger = logging.getLogger(__name__)


def is_private_ip(ip: str) -> bool:
    """Determine whether an IP address belongs to RFC 1918 private space."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class NetworkGraphBuilder:
    def __init__(self):
        self.preprocessor = Preprocessor()

    def build_graph_from_flows(
        self,
        flows_df: pd.DataFrame,
        time_window: Optional[Tuple[pd.Timestamp, pd.Timestamp]] = None,
    ) -> nx.DiGraph:
        """
        Construct a directed NetworkX graph (nx.DiGraph) from raw or preprocessed flows.
        If the input is not yet aggregated into (source_ip, destination_ip) pairs,
        it is automatically cleaned and aggregated.
        """
        if flows_df.empty:
            return nx.DiGraph()

        df = flows_df.copy()

        # Apply time window filter if timestamps exist and window is specified
        if time_window is not None:
            start_time, end_time = time_window
            time_col = "timestamp_parsed" if "timestamp_parsed" in df.columns else "timestamp"
            if time_col in df.columns:
                if not pd.api.types.is_datetime64_any_dtype(df[time_col]):
                    df[time_col] = pd.to_datetime(df[time_col], errors="coerce")
                mask = (df[time_col] >= start_time) & (df[time_col] <= end_time)
                df = df[mask]

        if df.empty:
            return nx.DiGraph()

        # Check if already aggregated (has 'weight' and 'attack_flows')
        if "weight" in df.columns and "attack_flows" in df.columns:
            agg_df = df
        else:
            # Clean and aggregate
            clean_df, _ = self.preprocessor.clean_chunk(df)
            agg_df = self.preprocessor.aggregate_flows(clean_df)

        G = nx.DiGraph()

        # Populate directed edges and aggregate node attributes
        node_stats: Dict[str, Dict[str, Any]] = {}

        for _, row in agg_df.iterrows():
            src = str(row["source_ip"]).strip()
            dst = str(row["destination_ip"]).strip()
            weight = int(row.get("weight", 1))
            attack_flows = int(row.get("attack_flows", 0))
            benign_flows = int(row.get("benign_flows", weight - attack_flows))
            attack_ratio = float(row.get("attack_ratio", (attack_flows / weight) if weight > 0 else 0.0))
            attack_types = str(row.get("attack_types", "None"))
            protocols = str(row.get("protocols", "Unknown"))
            earliest = row.get("earliest_time", pd.NaT)
            latest = row.get("latest_time", pd.NaT)

            # Edge attributes
            edge_attrs = {
                "weight": weight,
                "attack_flows": attack_flows,
                "benign_flows": benign_flows,
                "attack_ratio": attack_ratio,
                "attack_types": attack_types,
                "protocols": protocols,
                "earliest_time": earliest,
                "latest_time": latest,
                "has_attack": attack_flows > 0,
            }
            G.add_edge(src, dst, **edge_attrs)

            # Track node-level summaries
            for node, role in [(src, "src"), (dst, "dst")]:
                if node not in node_stats:
                    node_stats[node] = {
                        "ip": node,
                        "is_internal": is_private_ip(node),
                        "sent_flows": 0,
                        "received_flows": 0,
                        "attack_flows_sent": 0,
                        "attack_flows_received": 0,
                        "associated_attack_types": set(),
                    }

                if role == "src":
                    node_stats[node]["sent_flows"] += weight
                    node_stats[node]["attack_flows_sent"] += attack_flows
                else:
                    node_stats[node]["received_flows"] += weight
                    node_stats[node]["attack_flows_received"] += attack_flows

                if attack_types != "None" and attack_types:
                    for att in attack_types.split(", "):
                        if att and att != "None":
                            node_stats[node]["associated_attack_types"].add(att)

        # Assign node attributes
        for node, stats in node_stats.items():
            att_set = stats["associated_attack_types"]
            total_flows = stats["sent_flows"] + stats["received_flows"]
            total_attack_flows = stats["attack_flows_sent"] + stats["attack_flows_received"]
            G.nodes[node]["ip"] = stats["ip"]
            G.nodes[node]["is_internal"] = stats["is_internal"]
            G.nodes[node]["sent_flows"] = stats["sent_flows"]
            G.nodes[node]["received_flows"] = stats["received_flows"]
            G.nodes[node]["total_flows"] = total_flows
            G.nodes[node]["attack_flows_sent"] = stats["attack_flows_sent"]
            G.nodes[node]["attack_flows_received"] = stats["attack_flows_received"]
            G.nodes[node]["total_attack_flows"] = total_attack_flows
            G.nodes[node]["attack_types"] = ", ".join(sorted(att_set)) if att_set else "None"
            G.nodes[node]["has_attack_evidence"] = total_attack_flows > 0

        return G

    def get_graph_statistics(self, G: nx.DiGraph) -> Dict[str, Any]:
        """
        Calculate graph-level structural and security statistics.
        """
        num_nodes = G.number_of_nodes()
        num_edges = G.number_of_edges()

        if num_nodes == 0:
            return {
                "num_nodes": 0,
                "num_edges": 0,
                "density": 0.0,
                "is_directed": True,
                "weakly_connected_components": 0,
                "strongly_connected_components": 0,
                "total_flow_volume": 0,
                "total_attack_flows": 0,
                "attack_flow_proportion": 0.0,
                "internal_hosts": 0,
                "external_hosts": 0,
            }

        density = nx.density(G)
        wcc_count = nx.number_weakly_connected_components(G)
        scc_count = nx.number_strongly_connected_components(G)

        total_weight = sum(d.get("weight", 1) for _, _, d in G.edges(data=True))
        total_attack = sum(d.get("attack_flows", 0) for _, _, d in G.edges(data=True))
        attack_prop = (total_attack / total_weight) if total_weight > 0 else 0.0

        internal_count = sum(1 for _, d in G.nodes(data=True) if d.get("is_internal", False))
        external_count = num_nodes - internal_count

        return {
            "num_nodes": num_nodes,
            "num_edges": num_edges,
            "density": round(float(density), 6),
            "is_directed": G.is_directed(),
            "weakly_connected_components": wcc_count,
            "strongly_connected_components": scc_count,
            "total_flow_volume": total_weight,
            "total_attack_flows": total_attack,
            "attack_flow_proportion": round(float(attack_prop), 4),
            "internal_hosts": internal_count,
            "external_hosts": external_count,
        }

    def get_undirected_projection(self, G: nx.DiGraph) -> nx.Graph:
        """
        Create an undirected weighted projection suitable for community detection.
        Combines reciprocal directed edges (u -> v and v -> u) into a single edge
        with summed weights and merged attack attributes.
        """
        UG = nx.Graph()

        for node, data in G.nodes(data=True):
            UG.add_node(node, **data)

        for u, v, data in G.edges(data=True):
            weight = data.get("weight", 1)
            attack_flows = data.get("attack_flows", 0)
            benign_flows = data.get("benign_flows", 0)
            attack_types = data.get("attack_types", "None")

            if UG.has_edge(u, v):
                # Edge already exists from opposite direction; aggregate
                UG[u][v]["weight"] += weight
                UG[u][v]["attack_flows"] += attack_flows
                UG[u][v]["benign_flows"] += benign_flows
                # Combine attack types
                existing_att = set(UG[u][v]["attack_types"].split(", ")) if UG[u][v]["attack_types"] != "None" else set()
                new_att = set(attack_types.split(", ")) if attack_types != "None" else set()
                combined = existing_att.union(new_att) - {"None", ""}
                UG[u][v]["attack_types"] = ", ".join(sorted(combined)) if combined else "None"
                total_w = UG[u][v]["weight"]
                UG[u][v]["attack_ratio"] = round(UG[u][v]["attack_flows"] / total_w, 4) if total_w > 0 else 0.0
            else:
                UG.add_edge(
                    u, v,
                    weight=weight,
                    attack_flows=attack_flows,
                    benign_flows=benign_flows,
                    attack_ratio=data.get("attack_ratio", 0.0),
                    attack_types=attack_types,
                    protocols=data.get("protocols", "Unknown"),
                )

        return UG

    def get_subgraph_for_visualization(
        self,
        G: nx.DiGraph,
        max_nodes: int = 150,
        focus_nodes: Optional[List[str]] = None,
        min_weight: int = 1,
    ) -> nx.DiGraph:
        """
        Extract a bounded subgraph for interactive web visualization.
        Prevents browser freeze on dense large networks.
        Prioritizes:
        1. Explicit focus nodes and their 1-hop neighborhood.
        2. Hosts with highest degree and observed attack evidence.
        """
        if G.number_of_nodes() <= max_nodes:
            return G.copy()

        selected_nodes: Set[str] = set()

        if focus_nodes:
            for fn in focus_nodes:
                if fn in G:
                    selected_nodes.add(fn)
                    # Add predecessors and successors
                    selected_nodes.update(G.predecessors(fn))
                    selected_nodes.update(G.successors(fn))
                    if len(selected_nodes) >= max_nodes:
                        break

        # If still room, fill with top degree / attack nodes
        if len(selected_nodes) < max_nodes:
            # Score nodes by total degree + attack flow presence
            scored_nodes = []
            for n, d in G.nodes(data=True):
                if n in selected_nodes:
                    continue
                deg = G.degree(n)
                att_score = 10 if d.get("has_attack_evidence", False) else 0
                scored_nodes.append((deg + att_score, n))

            scored_nodes.sort(reverse=True, key=lambda x: x[0])
            for _, n in scored_nodes:
                selected_nodes.add(n)
                if len(selected_nodes) >= max_nodes:
                    break

        subG = G.subgraph(selected_nodes).copy()

        # Optional edge weight filter
        if min_weight > 1:
            edges_to_remove = [(u, v) for u, v, d in subG.edges(data=True) if d.get("weight", 1) < min_weight]
            subG.remove_edges_from(edges_to_remove)

        return subG
