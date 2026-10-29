"""
Community Detection Module.
Groups hosts based on network communication structure and modularity optimization.
Implements:
- Louvain community detection using NetworkX on weighted undirected graph projections.
- Secondary comparison method (Greedy Modularity / Clauset-Newman-Moore).
- Graph modularity calculation.
- Community structural metrics: internal vs external edges, conductance, density.
- Association of observed attack flows at community level (clearly maintaining distinction
  between structural topology and empirical attack evidence).
- Community subgraph inspection and membership persistence.
"""

import os
import logging
from typing import Dict, Any, List, Set, Tuple, Optional
import networkx as nx
import pandas as pd
from src.graph_builder import NetworkGraphBuilder

logger = logging.getLogger(__name__)


class CommunityDetector:
    def __init__(self, resolution: float = 1.0, random_state: int = 42):
        """
        Initialize community detector.
        :param resolution: Louvain resolution parameter (>1 produces smaller communities, <1 larger)
        :param random_state: Seed for reproducibility
        """
        self.resolution = resolution
        self.random_state = random_state
        self.graph_builder = NetworkGraphBuilder()

    def detect_communities(
        self,
        G: nx.DiGraph,
        method: str = "louvain",
    ) -> Tuple[List[Set[str]], float, nx.Graph]:
        """
        Run community detection on the undirected projection of graph G.
        :param G: Directed NetworkX communication graph
        :param method: 'louvain' (default) or 'greedy_modularity'
        :return: (list of communities as node sets, modularity score, undirected graph)
        """
        if G.number_of_nodes() == 0:
            return [], 0.0, nx.Graph()

        # Build undirected weighted projection
        UG = self.graph_builder.get_undirected_projection(G)

        if UG.number_of_edges() == 0 or UG.number_of_nodes() < 2:
            communities = [{n} for n in UG.nodes()]
            return communities, 0.0, UG

        if method == "greedy_modularity":
            raw_comms = nx.community.greedy_modularity_communities(UG, weight="weight")
            communities = [set(c) for c in raw_comms]
        else:
            # Default: Louvain algorithm
            raw_comms = nx.community.louvain_communities(
                UG,
                weight="weight",
                resolution=self.resolution,
                seed=self.random_state,
            )
            communities = [set(c) for c in raw_comms]

        # Calculate Newman-Girvan modularity
        try:
            modularity = nx.community.modularity(UG, communities, weight="weight")
        except ZeroDivisionError:
            modularity = 0.0

        return communities, round(float(modularity), 4), UG

    def build_membership_dataframe(
        self,
        G: nx.DiGraph,
        communities: List[Set[str]],
        save_path: Optional[str] = "results/host_community_membership.csv",
    ) -> pd.DataFrame:
        """
        Create host-level mapping of community membership and local attributes.
        """
        records = []
        for comm_id, node_set in enumerate(communities):
            for node in node_set:
                node_data = G.nodes[node] if node in G else {}
                records.append({
                    "host_id": node,
                    "community_id": comm_id,
                    "is_internal": node_data.get("is_internal", False),
                    "total_flows": node_data.get("total_flows", 0),
                    "attack_flows_associated": node_data.get("total_attack_flows", 0),
                    "observed_attack_types": node_data.get("attack_types", "None"),
                })

        df = pd.DataFrame(records)

        if save_path and not df.empty:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            df.to_csv(save_path, index=False)
            logger.info(f"Saved host community memberships to {save_path}")

        return df

    def summarize_communities(
        self,
        G: nx.DiGraph,
        UG: nx.Graph,
        communities: List[Set[str]],
        save_path: Optional[str] = "results/communities.csv",
    ) -> pd.DataFrame:
        """
        Compute structural and attack metrics for each community.
        Note: Modularity and density are structural; attack flow proportion is empirical evidence.
        """
        if not communities:
            return pd.DataFrame()

        # Map each node to its community ID
        node_to_comm = {}
        for c_id, comm in enumerate(communities):
            for n in comm:
                node_to_comm[n] = c_id

        summaries = []
        for c_id, comm in enumerate(communities):
            size = len(comm)
            internal_edges = 0
            external_edges = 0
            internal_flow_vol = 0
            external_flow_vol = 0
            comm_attack_flows = 0
            attack_types_set = set()

            # Inspect edges in undirected graph
            for u in comm:
                for v, edge_data in UG[u].items():
                    w = edge_data.get("weight", 1)
                    att = edge_data.get("attack_flows", 0)
                    types = edge_data.get("attack_types", "None")

                    if types != "None" and types:
                        for t in types.split(", "):
                            if t and t != "None":
                                attack_types_set.add(t)

                    if v in comm:
                        # Count once per undirected edge (u < v)
                        if str(u) < str(v):
                            internal_edges += 1
                            internal_flow_vol += w
                            comm_attack_flows += att
                    else:
                        external_edges += 1
                        external_flow_vol += w
                        comm_attack_flows += att

            # Structural density: 2 * E_int / (N * (N - 1))
            if size > 1:
                possible_edges = size * (size - 1) / 2
                density = round(internal_edges / possible_edges, 4)
            else:
                density = 0.0

            total_comm_volume = internal_flow_vol + external_flow_vol
            conductance = round(external_flow_vol / total_comm_volume, 4) if total_comm_volume > 0 else 0.0
            attack_ratio = round(comm_attack_flows / total_comm_volume, 4) if total_comm_volume > 0 else 0.0

            # Find top hub hosts in community
            comm_degrees = [(G.degree(n) if n in G else 0, n) for n in comm]
            comm_degrees.sort(reverse=True, key=lambda x: x[0])
            top_hosts = ", ".join([h for _, h in comm_degrees[:3]])

            summaries.append({
                "community_id": c_id,
                "size": size,
                "internal_edges": internal_edges,
                "external_edges": external_edges,
                "density": density,
                "internal_flow_volume": internal_flow_vol,
                "external_flow_volume": external_flow_vol,
                "conductance": conductance,
                "total_flow_volume": total_comm_volume,
                "attack_flows_observed": comm_attack_flows,
                "attack_flow_proportion": attack_ratio,
                "observed_attack_types": ", ".join(sorted(attack_types_set)) if attack_types_set else "None",
                "top_hosts": top_hosts,
                "has_attack_activity": bool(comm_attack_flows > 0),
            })

        df = pd.DataFrame(summaries)
        # Sort by size descending
        df = df.sort_values(by="size", ascending=False).reset_index(drop=True)

        if save_path and not df.empty:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            df.to_csv(save_path, index=False)
            logger.info(f"Saved community summaries to {save_path}")

        return df

    def get_community_subgraph(
        self,
        G: nx.DiGraph,
        community_nodes: Set[str],
        include_boundary: bool = False,
    ) -> nx.DiGraph:
        """
        Extract the directed subgraph for a specific community.
        If include_boundary=True, also includes adjacent boundary nodes.
        """
        if not include_boundary:
            return G.subgraph(community_nodes).copy()

        boundary_nodes = set(community_nodes)
        for n in community_nodes:
            if n in G:
                boundary_nodes.update(G.predecessors(n))
                boundary_nodes.update(G.successors(n))

        return G.subgraph(boundary_nodes).copy()
