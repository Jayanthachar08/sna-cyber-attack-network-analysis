"""
Pipeline Service Manager.
Integrates SNA algorithms with backend state management, caching, and querying.
"""

import os
import sys
import time
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
import networkx as nx
import pandas as pd
import numpy as np

# Ensure root dir in path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src.data_loader import DataLoader
from src.preprocessing import Preprocessor
from src.graph_builder import NetworkGraphBuilder
from src.centrality_analysis import CentralityAnalyzer
from src.community_detection import CommunityDetector
from src.risk_analysis import RiskAnalyzer
from src.evaluation import ModelEvaluator


class PipelineService:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PipelineService, cls).__new__(cls)
            cls._instance._init_service()
        return cls._instance

    def _init_service(self):
        self.loader = DataLoader()
        self.preprocessor = Preprocessor()
        self.graph_builder = NetworkGraphBuilder()
        self.results: Optional[Dict[str, Any]] = None
        self.active_file: Optional[str] = None
        self.last_run_timestamp: Optional[str] = None
        self.last_run_duration: float = 0.0
        self.current_params: Dict[str, Any] = {}

    def get_dataset_files(self) -> List[Dict[str, Any]]:
        found = self.loader.find_dataset_files()
        traffic_files = [
            f for f in found
            if "trafficlabelling" in f["path"].lower() or "raw" in f["path"].lower()
        ]
        return traffic_files if traffic_files else found

    def get_status(self) -> Dict[str, Any]:
        files = self.get_dataset_files()
        return {
            "available_files": files,
            "active_file": self.active_file,
            "is_analyzed": self.results is not None,
            "last_run_timestamp": self.last_run_timestamp,
            "cleaning_stats": self.results.get("cleaning_stats") if self.results else None,
            "parameters": self.current_params,
        }

    def run_analysis(
        self,
        file_path: Optional[str] = None,
        max_rows: int = 15000,
        skip_rows: int = 0,
        w_deg: float = 0.35,
        w_bet: float = 0.35,
        w_pr: float = 0.30,
        louvain_res: float = 1.0,
    ) -> Dict[str, Any]:
        start_time = time.time()

        # Resolve file path
        if not file_path:
            files = self.get_dataset_files()
            if files:
                # Prefer Friday DDoS file if available for rich attack demonstration
                ddos_files = [f for f in files if "ddos" in f["filename"].lower()]
                target_file = ddos_files[0] if ddos_files else files[0]
                file_path = target_file["path"]
                if "ddos" in target_file["filename"].lower() and skip_rows == 0:
                    skip_rows = 95000
            else:
                raise ValueError("No dataset files found in Datasets/ or data/raw/")

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Dataset file not found at: {file_path}")

        raw_df = self.loader.load_dataframe(file_path, max_rows=max_rows, skip_rows=skip_rows)
        clean_df, cleaning_stats = self.preprocessor.clean_chunk(raw_df)

        G = self.graph_builder.build_graph_from_flows(clean_df)
        graph_stats = self.graph_builder.get_graph_statistics(G)

        # Centrality
        analyzer = CentralityAnalyzer(
            weight_degree=w_deg, weight_betweenness=w_bet, weight_pagerank=w_pr
        )
        centrality_df = analyzer.compute_all_centralities(G)

        # Community Detection
        detector = CommunityDetector(resolution=louvain_res)
        communities, modularity, UG = detector.detect_communities(G)
        membership_df = detector.build_membership_dataframe(
            G, communities, save_path="results/host_community_membership.csv"
        )
        community_df = detector.summarize_communities(
            G, UG, communities, save_path="results/communities.csv"
        )

        # Risk Analysis
        risk_analyzer = RiskAnalyzer()
        host_risk_df = risk_analyzer.compute_host_risk(
            centrality_df, membership_df, community_df, save_path="results/suspicious_hosts.csv"
        )
        comm_risk_df = risk_analyzer.compute_community_risk(
            community_df, save_path="results/community_risk.csv"
        )

        # Evaluation
        evaluator = ModelEvaluator()
        eval_results = evaluator.evaluate_centrality_rankings(centrality_df, k_values=[5, 10, 20])
        evaluator.plot_precision_at_k(eval_results)
        evaluator.plot_community_attack_enrichment(community_df)

        duration = round(time.time() - start_time, 2)
        self.active_file = file_path
        self.last_run_timestamp = datetime.now().isoformat()
        self.last_run_duration = duration
        self.current_params = {
            "file_path": file_path,
            "max_rows": max_rows,
            "skip_rows": skip_rows,
            "w_deg": w_deg,
            "w_bet": w_bet,
            "w_pr": w_pr,
            "louvain_res": louvain_res,
        }

        self.results = {
            "clean_df": clean_df,
            "cleaning_stats": cleaning_stats,
            "G": G,
            "UG": UG,
            "graph_stats": graph_stats,
            "centrality_df": centrality_df,
            "host_risk_df": host_risk_df,
            "comm_risk_df": comm_risk_df,
            "membership_df": membership_df,
            "communities": communities,
            "modularity": modularity,
            "eval_results": eval_results,
        }

        return {
            "success": True,
            "message": f"Pipeline completed successfully in {duration}s",
            "duration_seconds": duration,
            "num_nodes": graph_stats["num_nodes"],
            "num_edges": graph_stats["num_edges"],
            "num_communities": len(communities),
            "active_file": file_path,
        }

    def ensure_analyzed(self):
        if self.results is None:
            self.run_analysis()

    def get_overview(self) -> Dict[str, Any]:
        self.ensure_analyzed()
        stats = self.results["graph_stats"]
        host_risk_df = self.results["host_risk_df"]
        comm_risk_df = self.results["comm_risk_df"]
        clean_df = self.results["clean_df"]
        cleaning_stats = self.results["cleaning_stats"]

        # Priority tier breakdown
        tier_counts = {}
        if not host_risk_df.empty and "priority_tier" in host_risk_df.columns:
            tier_counts = host_risk_df["priority_tier"].value_counts().to_dict()

        for t in ["CRITICAL", "HIGH", "INFRASTRUCTURE_WATCH", "MEDIUM", "LOW"]:
            tier_counts.setdefault(t, 0)

        # Traffic composition
        traffic_comp = []
        if not clean_df.empty and "label_clean" in clean_df.columns:
            vc = clean_df["label_clean"].value_counts()
            tot = len(clean_df)
            for label, count in vc.items():
                traffic_comp.append({
                    "traffic_class": str(label),
                    "count": int(count),
                    "percentage": round((count / tot) * 100, 2) if tot > 0 else 0.0,
                })

        # Top critical hosts preview
        top_hosts = []
        if not host_risk_df.empty:
            sorted_hosts = host_risk_df.sort_values(by="combined_criticality", ascending=False).head(5)
            for _, r in sorted_hosts.iterrows():
                top_hosts.append({
                    "host_id": str(r["host_id"]),
                    "priority_tier": str(r.get("priority_tier", "LOW")),
                    "combined_criticality": round(float(r.get("combined_criticality", 0.0)), 4),
                    "attack_flows": int(r.get("attack_flows_associated", 0)),
                    "explanation": str(r.get("explanation", "")),
                })

        # Top risk communities preview
        top_communities = []
        if not comm_risk_df.empty:
            sorted_comms = comm_risk_df.sort_values(by="attack_flows_observed", ascending=False).head(5)
            for _, r in sorted_comms.iterrows():
                top_communities.append({
                    "community_id": int(r["community_id"]),
                    "category": str(r.get("community_threat_category", "BENIGN_INTERNAL")),
                    "size": int(r.get("size", 0)),
                    "attack_flows": int(r.get("attack_flows_observed", 0)),
                    "attack_flow_proportion": round(float(r.get("attack_flow_proportion", 0.0)), 4),
                })

        return {
            "total_flow_volume": stats["total_flow_volume"],
            "num_nodes": stats["num_nodes"],
            "internal_hosts": stats["internal_hosts"],
            "external_hosts": stats["external_hosts"],
            "num_edges": stats["num_edges"],
            "density": stats["density"],
            "total_attack_flows": stats["total_attack_flows"],
            "attack_flow_proportion": stats["attack_flow_proportion"],
            "num_communities": len(self.results["communities"]),
            "modularity": self.results["modularity"],
            "priority_tier_counts": tier_counts,
            "traffic_composition": traffic_comp,
            "cleaning_audit": cleaning_stats,
            "top_critical_hosts": top_hosts,
            "top_risk_communities": top_communities,
        }

    def get_network(
        self,
        max_nodes: int = 100,
        focus_host: Optional[str] = None,
        community_id: Optional[int] = None,
        min_weight: int = 1,
    ) -> Dict[str, Any]:
        self.ensure_analyzed()
        G: nx.DiGraph = self.results["G"]
        host_risk_df = self.results["host_risk_df"]

        risk_map = {}
        if not host_risk_df.empty:
            for _, row in host_risk_df.iterrows():
                risk_map[row["host_id"]] = row.to_dict()

        target_G = G
        # Filter by community if requested
        if community_id is not None:
            comm_nodes = [
                n for n in G.nodes()
                if risk_map.get(n, {}).get("community_id") == community_id
            ]
            if comm_nodes:
                target_G = G.subgraph(comm_nodes).copy()
            else:
                target_G = nx.DiGraph()

        # Subgraph extraction
        focus_list = [focus_host] if focus_host and focus_host in target_G else None
        subG = self.graph_builder.get_subgraph_for_visualization(
            target_G, max_nodes=max_nodes, focus_nodes=focus_list, min_weight=min_weight
        )

        nodes = []
        for n, data in subG.nodes(data=True):
            r = risk_map.get(n, {})
            nodes.append({
                "id": str(n),
                "label": str(n),
                "is_internal": bool(data.get("is_internal", False)),
                "priority_tier": str(r.get("priority_tier", "LOW")),
                "community_id": int(r.get("community_id", -1)),
                "degree": int(subG.degree(n)),
                "in_degree": int(subG.in_degree(n)),
                "out_degree": int(subG.out_degree(n)),
                "betweenness": round(float(r.get("betweenness_centrality", 0.0)), 5),
                "pagerank": round(float(r.get("pagerank", 0.0)), 5),
                "combined_criticality": round(float(r.get("combined_criticality", 0.0)), 4),
                "attack_flows": int(data.get("total_attack_flows", 0)),
                "has_attack_evidence": bool(data.get("has_attack_evidence", False)),
                "attack_types": str(data.get("observed_attack_types", "None")),
            })

        edges = []
        for u, v, data in subG.edges(data=True):
            edges.append({
                "source": str(u),
                "target": str(v),
                "weight": int(data.get("weight", 1)),
                "attack_flows": int(data.get("attack_flows", 0)),
                "has_attack": bool(data.get("attack_flows", 0) > 0),
                "attack_types": str(data.get("attack_types", "None")),
                "protocols": str(data.get("protocols", "TCP")),
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "total_graph_nodes": G.number_of_nodes(),
            "total_graph_edges": G.number_of_edges(),
            "is_subgraph": subG.number_of_nodes() < G.number_of_nodes(),
            "applied_filter": {
                "max_nodes": max_nodes,
                "focus_host": focus_host,
                "community_id": community_id,
                "min_weight": min_weight,
            },
        }

    def get_hosts(
        self,
        page: int = 1,
        page_size: int = 25,
        sort_by: str = "combined_criticality",
        sort_dir: str = "desc",
        search: Optional[str] = None,
        priority_tier: Optional[str] = None,
        community_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        self.ensure_analyzed()
        df = self.results["host_risk_df"].copy()

        if df.empty:
            return {"hosts": [], "total_count": 0, "page": 1, "page_size": page_size, "total_pages": 0}

        # Filter: Search IP
        if search:
            search_str = search.strip().lower()
            df = df[df["host_id"].str.lower().str.contains(search_str, na=False)]

        # Filter: Priority tier
        if priority_tier and priority_tier != "ALL":
            df = df[df["priority_tier"] == priority_tier]

        # Filter: Community ID
        if community_id is not None:
            df = df[df["community_id"] == community_id]

        # Sort
        ascending = sort_dir.lower() == "asc"
        if sort_by in df.columns:
            df = df.sort_values(by=sort_by, ascending=ascending)
        else:
            df = df.sort_values(by="combined_criticality", ascending=False)

        total_count = len(df)
        total_pages = max(1, (total_count + page_size - 1) // page_size)
        page = max(1, min(page, total_pages))

        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        slice_df = df.iloc[start_idx:end_idx]

        records = []
        for idx, (_, row) in enumerate(slice_df.iterrows(), start=start_idx + 1):
            records.append({
                "rank": idx,
                "host_id": str(row["host_id"]),
                "is_internal": bool(row.get("is_internal", False)),
                "priority_tier": str(row.get("priority_tier", "LOW")),
                "combined_criticality": round(float(row.get("combined_criticality", 0.0)), 4),
                "degree_centrality": round(float(row.get("degree_centrality", 0.0)), 4),
                "betweenness_centrality": round(float(row.get("betweenness_centrality", 0.0)), 5),
                "pagerank": round(float(row.get("pagerank", 0.0)), 5),
                "in_degree": int(row.get("in_degree", 0)),
                "out_degree": int(row.get("out_degree", 0)),
                "total_degree": int(row.get("total_degree", 0)),
                "community_id": int(row.get("community_id", -1)),
                "attack_flows_associated": int(row.get("attack_flows_associated", 0)),
                "observed_attack_types": str(row.get("observed_attack_types", "None")),
                "explanation": str(row.get("explanation", "")),
                "investigation_evidence": str(row.get("investigation_evidence", "")),
            })

        return {
            "hosts": records,
            "total_count": total_count,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
        }

    def get_host_detail(self, host_id: str) -> Optional[Dict[str, Any]]:
        self.ensure_analyzed()
        G: nx.DiGraph = self.results["G"]
        host_risk_df = self.results["host_risk_df"]
        comm_risk_df = self.results["comm_risk_df"]

        matched = host_risk_df[host_risk_df["host_id"] == host_id]
        if matched.empty and host_id not in G:
            return None

        # Build HostRecord
        if not matched.empty:
            row = matched.iloc[0]
            host_rec = {
                "rank": 0,
                "host_id": str(row["host_id"]),
                "is_internal": bool(row.get("is_internal", False)),
                "priority_tier": str(row.get("priority_tier", "LOW")),
                "combined_criticality": round(float(row.get("combined_criticality", 0.0)), 4),
                "degree_centrality": round(float(row.get("degree_centrality", 0.0)), 4),
                "betweenness_centrality": round(float(row.get("betweenness_centrality", 0.0)), 5),
                "pagerank": round(float(row.get("pagerank", 0.0)), 5),
                "in_degree": int(row.get("in_degree", 0)),
                "out_degree": int(row.get("out_degree", 0)),
                "total_degree": int(row.get("total_degree", 0)),
                "community_id": int(row.get("community_id", -1)),
                "attack_flows_associated": int(row.get("attack_flows_associated", 0)),
                "observed_attack_types": str(row.get("observed_attack_types", "None")),
                "explanation": str(row.get("explanation", "")),
                "investigation_evidence": str(row.get("investigation_evidence", "")),
            }
            comm_id = int(row.get("community_id", -1))
        else:
            host_rec = {
                "rank": 0,
                "host_id": host_id,
                "is_internal": G.nodes[host_id].get("is_internal", False),
                "priority_tier": "LOW",
                "combined_criticality": 0.0,
                "degree_centrality": 0.0,
                "betweenness_centrality": 0.0,
                "pagerank": 0.0,
                "in_degree": G.in_degree(host_id) if host_id in G else 0,
                "out_degree": G.out_degree(host_id) if host_id in G else 0,
                "total_degree": G.degree(host_id) if host_id in G else 0,
                "community_id": -1,
                "attack_flows_associated": 0,
                "observed_attack_types": "None",
                "explanation": "No risk profile found.",
                "investigation_evidence": "No evidence recorded.",
            }
            comm_id = -1

        # Community Info
        comm_info = None
        if comm_id != -1 and not comm_risk_df.empty:
            c_match = comm_risk_df[comm_risk_df["community_id"] == comm_id]
            if not c_match.empty:
                c_row = c_match.iloc[0]
                comm_info = {
                    "community_id": comm_id,
                    "threat_category": str(c_row.get("community_threat_category", "")),
                    "size": int(c_row.get("size", 0)),
                    "density": round(float(c_row.get("density", 0.0)), 4),
                    "attack_flows": int(c_row.get("attack_flows_observed", 0)),
                    "attack_proportion": round(float(c_row.get("attack_flow_proportion", 0.0)), 4),
                }

        # Connections
        incoming = []
        outgoing = []
        if host_id in G:
            for p in G.predecessors(host_id):
                ed = G[p][host_id]
                incoming.append({
                    "direction": "incoming",
                    "peer_ip": str(p),
                    "is_peer_internal": bool(G.nodes[p].get("is_internal", False)),
                    "flow_volume": int(ed.get("weight", 1)),
                    "attack_flows": int(ed.get("attack_flows", 0)),
                    "attack_types": str(ed.get("attack_types", "None")),
                    "protocols": str(ed.get("protocols", "TCP")),
                })

            for s in G.successors(host_id):
                ed = G[host_id][s]
                outgoing.append({
                    "direction": "outgoing",
                    "peer_ip": str(s),
                    "is_peer_internal": bool(G.nodes[s].get("is_internal", False)),
                    "flow_volume": int(ed.get("weight", 1)),
                    "attack_flows": int(ed.get("attack_flows", 0)),
                    "attack_types": str(ed.get("attack_types", "None")),
                    "protocols": str(ed.get("protocols", "TCP")),
                })

        return {
            "host": host_rec,
            "incoming_connections": incoming,
            "outgoing_connections": outgoing,
            "community_info": comm_info,
        }

    def get_communities(self) -> Dict[str, Any]:
        self.ensure_analyzed()
        comm_risk_df = self.results["comm_risk_df"]
        modularity = self.results["modularity"]

        if comm_risk_df.empty:
            return {
                "communities": [],
                "total_communities": 0,
                "modularity": 0.0,
                "largest_community_size": 0,
            }

        communities = []
        for _, row in comm_risk_df.iterrows():
            communities.append({
                "community_id": int(row["community_id"]),
                "community_threat_category": str(row.get("community_threat_category", "BENIGN_INTERNAL")),
                "size": int(row.get("size", 0)),
                "density": round(float(row.get("density", 0.0)), 4),
                "internal_edges": int(row.get("internal_edges", 0)),
                "external_edges": int(row.get("external_edges", 0)),
                "attack_flows_observed": int(row.get("attack_flows_observed", 0)),
                "attack_flow_proportion": round(float(row.get("attack_flow_proportion", 0.0)), 4),
                "attack_associated_hosts": int(row.get("attack_associated_hosts", 0)),
                "observed_attack_types": str(row.get("observed_attack_types", "None")),
                "top_hosts": str(row.get("top_hosts", "")),
                "investigation_priority_score": round(float(row.get("community_risk_score", 0.0)), 4),
            })

        largest_size = int(comm_risk_df["size"].max()) if "size" in comm_risk_df.columns else 0

        return {
            "communities": communities,
            "total_communities": len(communities),
            "modularity": round(float(modularity), 4),
            "largest_community_size": largest_size,
        }

    def get_community_detail(self, community_id: int) -> Optional[Dict[str, Any]]:
        self.ensure_analyzed()
        comm_risk_df = self.results["comm_risk_df"]
        host_risk_df = self.results["host_risk_df"]

        c_match = comm_risk_df[comm_risk_df["community_id"] == community_id]
        if c_match.empty:
            return None

        c_row = c_match.iloc[0]
        comm_rec = {
            "community_id": community_id,
            "community_threat_category": str(c_row.get("community_threat_category", "BENIGN_INTERNAL")),
            "size": int(c_row.get("size", 0)),
            "density": round(float(c_row.get("density", 0.0)), 4),
            "internal_edges": int(c_row.get("internal_edges", 0)),
            "external_edges": int(c_row.get("external_edges", 0)),
            "attack_flows_observed": int(c_row.get("attack_flows_observed", 0)),
            "attack_flow_proportion": round(float(c_row.get("attack_flow_proportion", 0.0)), 4),
            "attack_associated_hosts": int(c_row.get("attack_associated_hosts", 0)),
            "observed_attack_types": str(c_row.get("observed_attack_types", "None")),
            "top_hosts": str(c_row.get("top_hosts", "")),
            "investigation_priority_score": round(float(c_row.get("community_risk_score", 0.0)), 4),
        }

        # Member hosts
        member_hosts = host_risk_df[host_risk_df["community_id"] == community_id]
        members = []
        for idx, (_, r) in enumerate(member_hosts.iterrows(), start=1):
            members.append({
                "rank": idx,
                "host_id": str(r["host_id"]),
                "is_internal": bool(r.get("is_internal", False)),
                "priority_tier": str(r.get("priority_tier", "LOW")),
                "combined_criticality": round(float(r.get("combined_criticality", 0.0)), 4),
                "degree_centrality": round(float(r.get("degree_centrality", 0.0)), 4),
                "betweenness_centrality": round(float(r.get("betweenness_centrality", 0.0)), 5),
                "pagerank": round(float(r.get("pagerank", 0.0)), 5),
                "in_degree": int(r.get("in_degree", 0)),
                "out_degree": int(r.get("out_degree", 0)),
                "total_degree": int(r.get("total_degree", 0)),
                "community_id": community_id,
                "attack_flows_associated": int(r.get("attack_flows_associated", 0)),
                "observed_attack_types": str(r.get("observed_attack_types", "None")),
                "explanation": str(r.get("explanation", "")),
                "investigation_evidence": str(r.get("investigation_evidence", "")),
            })

        # Community subgraph
        subgraph = self.get_network(max_nodes=100, community_id=community_id)

        return {
            "community": comm_rec,
            "members": members,
            "subgraph": subgraph,
        }

    def get_timeline(self) -> Dict[str, Any]:
        self.ensure_analyzed()
        clean_df = self.results["clean_df"]

        if clean_df.empty or "timestamp_parsed" not in clean_df.columns:
            return {
                "available": False,
                "message": "No timestamp data found in active dataset slice.",
                "points": [],
                "total_time_bins": 0,
            }

        time_df = clean_df.dropna(subset=["timestamp_parsed"]).copy()
        if time_df.empty:
            return {
                "available": False,
                "message": "All timestamps were unparseable or missing.",
                "points": [],
                "total_time_bins": 0,
            }

        # 1-minute binning
        time_df["time_bin"] = time_df["timestamp_parsed"].dt.floor("1min")
        grouped = time_df.groupby("time_bin")

        points = []
        for t_bin, group in grouped:
            benign_cnt = int((~group["is_attack"]).sum())
            attack_cnt = int(group["is_attack"].sum())
            att_cat_counts = {}
            if attack_cnt > 0 and "attack_category" in group.columns:
                att_cat_counts = group[group["is_attack"]]["attack_category"].value_counts().to_dict()

            points.append({
                "time_bin": t_bin.strftime("%Y-%m-%d %H:%M:%S"),
                "benign_count": benign_cnt,
                "attack_count": attack_cnt,
                "total_count": len(group),
                "attack_categories": att_cat_counts,
            })

        points.sort(key=lambda x: x["time_bin"])

        return {
            "available": True,
            "message": None,
            "points": points,
            "total_time_bins": len(points),
        }

    def get_evaluation(self) -> Dict[str, Any]:
        self.ensure_analyzed()
        eval_res = self.results.get("eval_results", {})
        modularity = self.results.get("modularity", 0.0)

        # Check existing figures
        fig1_path = os.path.join("results", "figures", "precision_at_k_comparison.png")
        fig2_path = os.path.join("results", "figures", "community_attack_enrichment.png")

        return {
            "precision_at_k": eval_res.get("precision_at_k", {}),
            "attack_host_base_rate": eval_res.get("attack_host_base_rate", 0.0),
            "community_modularity": round(float(modularity), 4),
            "classification_metrics": eval_res.get("classification_metrics", {}),
            "figures": {
                "precision_at_k": os.path.exists(fig1_path),
                "community_enrichment": os.path.exists(fig2_path),
            },
        }

    def export_csv(self, file_type: str) -> Tuple[str, str]:
        self.ensure_analyzed()
        host_risk_df = self.results["host_risk_df"]
        comm_risk_df = self.results["comm_risk_df"]
        membership_df = self.results.get("membership_df")

        if file_type == "critical-hosts":
            csv_data = host_risk_df.to_csv(index=False)
            filename = "critical_hosts.csv"
        elif file_type == "communities":
            csv_data = comm_risk_df.to_csv(index=False)
            filename = "communities.csv"
        elif file_type == "suspicious-hosts":
            csv_data = host_risk_df.to_csv(index=False)
            filename = "suspicious_hosts.csv"
        elif file_type == "host-community-membership":
            if membership_df is not None:
                csv_data = membership_df.to_csv(index=False)
            else:
                csv_data = host_risk_df[["host_id", "community_id"]].to_csv(index=False)
            filename = "host_community_membership.csv"
        elif file_type == "community-risk":
            csv_data = comm_risk_df.to_csv(index=False)
            filename = "community_risk.csv"
        else:
            raise ValueError(f"Unknown export type: {file_type}")

        return csv_data, filename
