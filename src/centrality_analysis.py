"""
Critical-Host Centrality Analysis Module.
Implements:
- In-degree, Out-degree, and Normalized Degree Centrality.
- Exact and Approximate Betweenness Centrality (with sample heuristics for scalability).
- Weighted PageRank.
- Configurable Min-Max Normalized Combined Criticality Scoring.
- Natural language structural explanation generation for investigative triage.
- Persistence to results/critical_hosts.csv.
"""

import os
import logging
from typing import Dict, Any, Optional, List, Tuple
import networkx as nx
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)


def min_max_scale(series: pd.Series) -> pd.Series:
    """Scale a numeric series to [0, 1]. Returns 0.0 if range is zero."""
    min_val = series.min()
    max_val = series.max()
    if pd.isna(min_val) or pd.isna(max_val) or (max_val - min_val) < 1e-12:
        return pd.Series(0.0, index=series.index)
    return (series - min_val) / (max_val - min_val)


class CentralityAnalyzer:
    def __init__(
        self,
        weight_degree: float = 0.35,
        weight_betweenness: float = 0.35,
        weight_pagerank: float = 0.30,
        pagerank_alpha: float = 0.85,
        betweenness_sample_threshold: int = 500,
    ):
        """
        Initialize centrality configuration.
        """
        self.w_deg = weight_degree
        self.w_bet = weight_betweenness
        self.w_pr = weight_pagerank
        self.pr_alpha = pagerank_alpha
        self.bet_threshold = betweenness_sample_threshold

    def compute_all_centralities(
        self,
        G: nx.DiGraph,
        approximate_betweenness: bool = True,
    ) -> pd.DataFrame:
        """
        Compute degree, betweenness, and PageRank metrics for all hosts in the network.
        Returns a DataFrame indexed by host IP.
        """
        if G.number_of_nodes() == 0:
            return pd.DataFrame(columns=[
                "host_id", "in_degree", "out_degree", "total_degree",
                "in_degree_centrality", "out_degree_centrality", "degree_centrality",
                "betweenness_centrality", "pagerank", "combined_criticality",
                "is_internal", "attack_flows_associated", "observed_attack_types",
                "explanation"
            ])

        N = G.number_of_nodes()
        nodes = list(G.nodes())

        # 1. Degree metrics
        in_degrees = dict(G.in_degree())
        out_degrees = dict(G.out_degree())
        in_deg_cent = nx.in_degree_centrality(G)
        out_deg_cent = nx.out_degree_centrality(G)
        deg_cent = nx.degree_centrality(G)

        # 2. Betweenness Centrality
        # If network is large, use Brandes approximation via k-node sampling
        approx_used = False
        k_samples = None
        if approximate_betweenness and N > self.bet_threshold:
            k_samples = max(50, min(self.bet_threshold, int(0.2 * N)))
            logger.info(f"Using approximate betweenness centrality with k={k_samples} samples (N={N})")
            bet_cent = nx.betweenness_centrality(G, k=k_samples, normalized=True, seed=42)
            approx_used = True
        else:
            bet_cent = nx.betweenness_centrality(G, normalized=True)

        # 3. PageRank
        try:
            pr = nx.pagerank(G, alpha=self.pr_alpha, weight="weight", max_iter=200)
        except nx.PowerIterationFailedConvergence:
            logger.warning("PageRank power iteration did not converge, falling back to uniform PageRank.")
            pr = {n: 1.0 / N for n in nodes}

        # Build records
        records = []
        for n in nodes:
            d = G.nodes[n]
            in_d = in_degrees.get(n, 0)
            out_d = out_degrees.get(n, 0)
            tot_d = in_d + out_d

            rec = {
                "host_id": n,
                "in_degree": in_d,
                "out_degree": out_d,
                "total_degree": tot_d,
                "in_degree_centrality": in_deg_cent.get(n, 0.0),
                "out_degree_centrality": out_deg_cent.get(n, 0.0),
                "degree_centrality": deg_cent.get(n, 0.0),
                "betweenness_centrality": bet_cent.get(n, 0.0),
                "pagerank": pr.get(n, 0.0),
                "is_internal": d.get("is_internal", False),
                "total_flows": d.get("total_flows", 0),
                "attack_flows_associated": d.get("total_attack_flows", 0),
                "observed_attack_types": d.get("attack_types", "None"),
            }
            records.append(rec)

        df = pd.DataFrame(records)

        # 4. Normalize metrics to [0, 1] for combined criticality calculation
        norm_deg = min_max_scale(df["degree_centrality"])
        norm_bet = min_max_scale(df["betweenness_centrality"])
        norm_pr = min_max_scale(df["pagerank"])

        # Combined criticality formula
        total_w = self.w_deg + self.w_bet + self.w_pr
        w_d = self.w_deg / total_w
        w_b = self.w_bet / total_w
        w_p = self.w_pr / total_w

        df["combined_criticality"] = (
            w_d * norm_deg +
            w_b * norm_bet +
            w_p * norm_pr
        ).round(4)

        # 5. Generate explanations
        df["explanation"] = df.apply(
            lambda r: self._generate_explanation(r, df, approx_used),
            axis=1
        )

        return df

    def _generate_explanation(self, row: pd.Series, df: pd.DataFrame, approx_used: bool) -> str:
        """
        Generate human-readable justification for why a host ranked as critical.
        """
        reasons = []

        # Compare to percentiles
        deg_p75 = df["degree_centrality"].quantile(0.75)
        bet_p75 = df["betweenness_centrality"].quantile(0.75)
        pr_p75 = df["pagerank"].quantile(0.75)

        if row["betweenness_centrality"] >= bet_p75 and row["betweenness_centrality"] > 0:
            reasons.append("Structural bridge/gateway interconnecting disparate network clusters")
        if row["in_degree"] > row["out_degree"] * 2 and row["in_degree"] >= 3:
            reasons.append(f"Major communication sink/destination ({row['in_degree']} incoming connections)")
        elif row["out_degree"] > row["in_degree"] * 2 and row["out_degree"] >= 3:
            reasons.append(f"High-fanout origin ({row['out_degree']} outgoing destinations - scanner or active sender)")
        elif row["degree_centrality"] >= deg_p75 and row["degree_centrality"] > 0:
            reasons.append(f"High connectivity hub ({row['total_degree']} total direct connections)")

        if row["pagerank"] >= pr_p75 and row["pagerank"] > 0:
            reasons.append("High topological authority (communicates with other key hosts)")

        # Attack evidence context
        att_flows = row.get("attack_flows_associated", 0)
        att_types = row.get("observed_attack_types", "None")
        if att_flows > 0:
            reasons.append(f"Involved in {att_flows} attack-labeled flows ({att_types})")
        else:
            reasons.append("No attack traffic observed (benign/infrastructure structural role)")

        if not reasons:
            return "Standard peripheral host with baseline connectivity."

        return "; ".join(reasons) + "."

    def rank_hosts(
        self,
        centrality_df: pd.DataFrame,
        sort_by: str = "combined_criticality",
        top_k: Optional[int] = None,
        save_path: Optional[str] = "results/critical_hosts.csv",
    ) -> pd.DataFrame:
        """
        Sort and filter ranked hosts, with optional CSV export.
        """
        if centrality_df.empty:
            return centrality_df

        valid_sort_cols = [
            "combined_criticality", "degree_centrality", "betweenness_centrality",
            "pagerank", "total_degree", "in_degree", "out_degree", "attack_flows_associated"
        ]
        sort_col = sort_by if sort_by in valid_sort_cols else "combined_criticality"

        ranked = centrality_df.sort_values(by=sort_col, ascending=False).reset_index(drop=True)

        if top_k is not None and top_k > 0:
            ranked = ranked.head(top_k)

        if save_path:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            ranked.to_csv(save_path, index=False)
            logger.info(f"Saved {len(ranked)} critical hosts to {save_path}")

        return ranked
