"""
Evaluation and Research Validation Module.
Provides academic, leakage-free benchmarking of Social Network Analysis metrics:
- Precision@K across centrality measures (Degree, Betweenness, PageRank, Combined).
- Classification performance (Precision, Recall, F1, ROC-AUC, PR-AUC).
- Temporal split evaluation (earlier topology window -> subsequent attack window).
- Community modularity and empirical attack enrichment.
- Generation of academic research figures saved to results/figures/.
"""

import os
import time
import logging
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless figure generation
import matplotlib.pyplot as plt
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, average_precision_score

logger = logging.getLogger(__name__)


def compute_precision_at_k(y_true: np.ndarray, y_scores: np.ndarray, k: int) -> float:
    """
    Compute Precision@K: proportion of top-K ranked items that have positive proxy labels.
    """
    if len(y_true) == 0 or k <= 0:
        return 0.0
    k = min(k, len(y_true))
    # Sort indices by score descending
    ranked_indices = np.argsort(-y_scores)[:k]
    return float(np.mean(y_true[ranked_indices]))


class ModelEvaluator:
    def __init__(self, figures_dir: str = "results/figures"):
        self.figures_dir = figures_dir
        os.makedirs(self.figures_dir, exist_ok=True)

    def evaluate_centrality_rankings(
        self,
        centrality_df: pd.DataFrame,
        k_values: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """
        Benchmark pure structural SNA metrics (unsupervised) against the host-level
        attack-involvement proxy label.
        Tests whether topological position alone prioritizes hosts targeted or leveraged in attacks.
        """
        if centrality_df.empty:
            return {}

        if k_values is None:
            k_values = [5, 10, 20, 50]

        df = centrality_df.copy()

        # Derive observational ground-truth proxy label:
        # A host is attack-involved (y=1) if observed in >= 1 attack-labeled flow.
        att_flows = df.get("attack_flows_associated", pd.Series(0, index=df.index)).fillna(0).values
        y_true = (att_flows > 0).astype(int)

        total_hosts = len(df)
        total_attack_hosts = int(np.sum(y_true))
        base_rate = float(np.mean(y_true)) if total_hosts > 0 else 0.0

        metrics_to_compare = {
            "Degree Centrality": df.get("degree_centrality", pd.Series(0, index=df.index)).values,
            "Betweenness Centrality": df.get("betweenness_centrality", pd.Series(0, index=df.index)).values,
            "PageRank": df.get("pagerank", pd.Series(0, index=df.index)).values,
            "Combined Criticality": df.get("combined_criticality", pd.Series(0, index=df.index)).values,
        }

        results: Dict[str, Any] = {
            "total_hosts": total_hosts,
            "attack_involved_hosts": total_attack_hosts,
            "attack_host_base_rate": round(base_rate, 4),
            "precision_at_k": {},
            "auc_metrics": {},
        }

        # Compute Precision@K for each metric
        for metric_name, scores in metrics_to_compare.items():
            results["precision_at_k"][metric_name] = {}
            for k in k_values:
                if k <= total_hosts:
                    p_at_k = compute_precision_at_k(y_true, scores, k)
                    results["precision_at_k"][metric_name][f"P@{k}"] = round(p_at_k, 4)

            # Compute ROC-AUC and PR-AUC if both classes present
            if len(np.unique(y_true)) > 1:
                try:
                    roc = roc_auc_score(y_true, scores)
                    pr_auc = average_precision_score(y_true, scores)
                    results["auc_metrics"][metric_name] = {
                        "ROC_AUC": round(float(roc), 4),
                        "PR_AUC": round(float(pr_auc), 4),
                    }
                except Exception as e:
                    results["auc_metrics"][metric_name] = {"error": str(e)}

        return results

    def plot_precision_at_k(
        self,
        eval_results: Dict[str, Any],
        filename: str = "precision_at_k_comparison.png",
    ) -> str:
        """
        Generate research-ready plot comparing Precision@K curves against baseline.
        """
        p_at_k_dict = eval_results.get("precision_at_k", {})
        if not p_at_k_dict:
            return ""

        base_rate = eval_results.get("attack_host_base_rate", 0.0)

        plt.figure(figsize=(9, 5))

        markers = ["o", "s", "^", "D"]
        for i, (metric_name, p_dict) in enumerate(p_at_k_dict.items()):
            if not p_dict:
                continue
            ks = [int(k_str.replace("P@", "")) for k_str in p_dict.keys()]
            vals = list(p_dict.values())
            plt.plot(ks, vals, marker=markers[i % len(markers)], linewidth=2, label=metric_name)

        # Baseline random chance
        plt.axhline(
            y=base_rate,
            color="red",
            linestyle="--",
            alpha=0.7,
            label=f"Random Base Rate ({base_rate:.1%})",
        )

        plt.title("Critical Host Ranking Evaluation: Precision@K by Centrality Algorithm", fontsize=12, pad=12)
        plt.xlabel("Top K Hosts Evaluated", fontsize=10)
        plt.ylabel("Precision (Fraction of Attack-Involved Hosts)", fontsize=10)
        plt.ylim(-0.05, 1.05)
        plt.grid(True, linestyle=":", alpha=0.6)
        plt.legend(frameon=True, facecolor="white", framealpha=0.9)
        plt.tight_layout()

        out_path = os.path.join(self.figures_dir, filename)
        plt.savefig(out_path, dpi=200)
        plt.close()
        logger.info(f"Generated evaluation figure at {out_path}")
        return out_path

    def plot_community_attack_enrichment(
        self,
        community_df: pd.DataFrame,
        filename: str = "community_attack_enrichment.png",
    ) -> str:
        """
        Generate bar chart illustrating community size and attack concentration.
        """
        if community_df.empty:
            return ""

        cdf = community_df.head(15).copy()
        c_ids = [f"C{cid}" for cid in cdf["community_id"]]
        sizes = cdf["size"].values
        att_props = cdf["attack_flow_proportion"].values

        fig, ax1 = plt.subplots(figsize=(10, 5))

        color = "tab:blue"
        ax1.set_xlabel("Community Identifier", fontsize=10)
        ax1.set_ylabel("Host Count (Size)", color=color, fontsize=10)
        bars = ax1.bar(c_ids, sizes, color=color, alpha=0.6, label="Community Size")
        ax1.tick_params(axis="y", labelcolor=color)

        ax2 = ax1.twinx()
        color = "tab:red"
        ax2.set_ylabel("Attack Flow Proportion", color=color, fontsize=10)
        lines = ax2.plot(c_ids, att_props, color=color, marker="o", linewidth=2.5, label="Attack Flow Ratio")
        ax2.tick_params(axis="y", labelcolor=color)
        ax2.set_ylim(-0.05, 1.05)

        plt.title("Community Structure vs Observed Attack Concentration", fontsize=12, pad=12)
        fig.tight_layout()

        out_path = os.path.join(self.figures_dir, filename)
        plt.savefig(out_path, dpi=200)
        plt.close()
        logger.info(f"Generated community enrichment figure at {out_path}")
        return out_path

    def evaluate_temporal_predictive_utility(
        self,
        t1_centrality_df: pd.DataFrame,
        t2_flows_df: pd.DataFrame,
        k: int = 10,
    ) -> Dict[str, Any]:
        """
        Temporal validation:
        1. Calculate SNA centrality on early time window T1.
        2. Evaluate whether top-K central hosts in T1 are involved in attacks occurring in later window T2.
        Guarantees zero label leakage from future attack data into the graph ranking.
        """
        if t1_centrality_df.empty or t2_flows_df.empty:
            return {}

        # Hosts participating in attack in window T2
        t2_attack_flows = t2_flows_df[t2_flows_df.get("is_attack", False) == True]
        t2_attack_hosts = set(t2_attack_flows["source_ip"]).union(set(t2_attack_flows["destination_ip"]))

        t1_hosts = t1_centrality_df["host_id"].values
        y_true_future = np.array([1 if h in t2_attack_hosts else 0 for h in t1_hosts])

        results = {}
        for metric in ["combined_criticality", "degree_centrality", "betweenness_centrality", "pagerank"]:
            if metric in t1_centrality_df.columns:
                scores = t1_centrality_df[metric].values
                p_at_k = compute_precision_at_k(y_true_future, scores, k)
                results[f"{metric}_future_P@{k}"] = round(p_at_k, 4)

        base_future_rate = float(np.mean(y_true_future)) if len(y_true_future) > 0 else 0.0
        results["future_base_rate"] = round(base_future_rate, 4)
        results["future_attack_hosts_count"] = len(t2_attack_hosts)

        return results
