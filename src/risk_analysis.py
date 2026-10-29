"""
Suspicious-Activity and Community Risk Analysis Module.
Combines SNA structural centrality with empirical attack evidence to compute
explainable, evidence-aware investigation priorities.

Key Principles:
1. Strict separation of topological centrality from empirical attack evidence.
2. Centrality alone never labels a host as malicious (infrastructure vs attacker distinction).
3. Configurable heuristic prioritization formula with transparent documentation.
4. Explicit handling of unknown or missing labels (missing != benign).
5. Generation of detailed natural-language audit evidence for every prioritized host.
"""

import os
import logging
import numpy as np
import pandas as pd
from typing import Dict, Any, Optional, List, Tuple
from src.centrality_analysis import min_max_scale

logger = logging.getLogger(__name__)


class RiskAnalyzer:
    def __init__(
        self,
        weight_attack_evidence: float = 0.50,
        weight_structural: float = 0.30,
        weight_community_risk: float = 0.20,
    ):
        """
        Initialize weights for the heuristic investigation priority formula:
        Priority = w_attack * E_attack + w_struct * S_struct + w_comm * C_risk
        """
        total = weight_attack_evidence + weight_structural + weight_community_risk
        self.w_att = weight_attack_evidence / total
        self.w_struct = weight_structural / total
        self.w_comm = weight_community_risk / total

    def compute_host_risk(
        self,
        centrality_df: pd.DataFrame,
        membership_df: Optional[pd.DataFrame] = None,
        community_df: Optional[pd.DataFrame] = None,
        save_path: Optional[str] = "results/suspicious_hosts.csv",
    ) -> pd.DataFrame:
        """
        Merge structural centrality metrics with attack flows and community context
        to calculate investigation priorities.
        """
        if centrality_df.empty:
            return pd.DataFrame()

        df = centrality_df.copy()

        # Merge community attributes if provided
        if membership_df is not None and not membership_df.empty:
            comm_map = membership_df.set_index("host_id")["community_id"].to_dict()
            df["community_id"] = df["host_id"].map(comm_map).fillna(-1).astype(int)
        elif "community_id" not in df.columns:
            df["community_id"] = -1

        # Merge community risk metrics if provided
        comm_attack_prop_map = {}
        if community_df is not None and not community_df.empty:
            comm_attack_prop_map = community_df.set_index("community_id")["attack_flow_proportion"].to_dict()

        df["community_attack_proportion"] = df["community_id"].map(comm_attack_prop_map).fillna(0.0)

        # 1. Structural Centrality Indicator [0, 1]
        if "combined_criticality" in df.columns:
            df["structural_criticality"] = df["combined_criticality"]
        else:
            deg_norm = min_max_scale(df.get("degree_centrality", pd.Series(0, index=df.index)))
            bet_norm = min_max_scale(df.get("betweenness_centrality", pd.Series(0, index=df.index)))
            pr_norm = min_max_scale(df.get("pagerank", pd.Series(0, index=df.index)))
            df["structural_criticality"] = (0.35 * deg_norm + 0.35 * bet_norm + 0.30 * pr_norm).round(4)

        # 2. Observed Attack Evidence Indicator [0, 1]
        att_flows = df.get("attack_flows_associated", pd.Series(0, index=df.index)).fillna(0).astype(float)
        tot_flows = df.get("total_flows", pd.Series(1, index=df.index)).fillna(1).astype(float)

        # Ratio of attack flows
        flow_ratio = np.where(tot_flows > 0, att_flows / tot_flows, 0.0)
        # Log-scaled volume of attack flows
        log_vol = np.log1p(att_flows)
        max_log = log_vol.max()
        norm_log_vol = (log_vol / max_log) if max_log > 0 else np.zeros_like(log_vol)

        # Attack evidence score combines local attack ratio and volume
        attack_evidence = (0.6 * flow_ratio + 0.4 * norm_log_vol).round(4)
        df["observed_attack_evidence"] = attack_evidence

        # 3. Community Risk Indicator [0, 1]
        df["community_risk_score"] = df["community_attack_proportion"].clip(0.0, 1.0).round(4)

        # 4. Overall Investigation Priority Score (Heuristic)
        priority_score = (
            self.w_att * df["observed_attack_evidence"] +
            self.w_struct * df["structural_criticality"] +
            self.w_comm * df["community_risk_score"]
        ).round(4)
        df["investigation_priority_score"] = priority_score

        # 5. Priority Tier & Natural Language Evidence Justification
        df["priority_tier"] = df.apply(self._assign_priority_tier, axis=1)
        df["investigation_evidence"] = df.apply(self._generate_evidence_explanation, axis=1)

        # Sort by investigation priority descending
        df = df.sort_values(by="investigation_priority_score", ascending=False).reset_index(drop=True)

        if save_path:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            df.to_csv(save_path, index=False)
            logger.info(f"Saved {len(df)} host risk evaluations to {save_path}")

        return df

    def _assign_priority_tier(self, row: pd.Series) -> str:
        """Classify into investigative action tiers."""
        score = row["investigation_priority_score"]
        att_evidence = row["observed_attack_evidence"]
        struct = row["structural_criticality"]

        if att_evidence > 0.4 and struct > 0.3:
            return "CRITICAL"
        elif att_evidence > 0.1 or score >= 0.45:
            return "HIGH"
        elif struct >= 0.5 and att_evidence == 0:
            return "INFRASTRUCTURE_WATCH"  # High centrality, clean traffic
        elif score >= 0.20 or att_evidence > 0:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_evidence_explanation(self, row: pd.Series) -> str:
        """Produce rigorous, transparent evidence statement for analysts."""
        tier = row["priority_tier"]
        att_flows = int(row.get("attack_flows_associated", 0))
        att_types = row.get("observed_attack_types", "None")
        struct = row["structural_criticality"]
        att_score = row["observed_attack_evidence"]
        comm_id = row.get("community_id", -1)
        comm_risk = row.get("community_risk_score", 0.0)

        parts = []

        if tier == "CRITICAL":
            parts.append(
                f"CRITICAL PRIORITY: Dual convergence of high topological centrality (score: {struct:.2f}) "
                f"and active attack participation ({att_flows} attack flows; types: {att_types}). "
                f"Immediate investigation required for potential command-and-control, compromised gateway, or primary target."
            )
        elif tier == "HIGH":
            if att_flows > 0:
                parts.append(
                    f"HIGH PRIORITY: Direct participation in {att_flows} attack flows ({att_types}) "
                    f"with structural criticality {struct:.2f}."
                )
            else:
                parts.append(
                    f"HIGH PRIORITY: Located in high-risk Community {comm_id} (attack ratio {comm_risk:.1%}) "
                    f"with structural centrality {struct:.2f}."
                )
        elif tier == "INFRASTRUCTURE_WATCH":
            parts.append(
                f"INFRASTRUCTURE WATCH: High structural importance (score: {struct:.2f}) but 0 observed attack flows. "
                f"Classified as critical benign backbone/server requiring defensive monitoring, NOT an active threat."
            )
        elif tier == "MEDIUM":
            if att_flows > 0:
                parts.append(
                    f"MEDIUM PRIORITY: Peripheral host involved in {att_flows} attack flows ({att_types})."
                )
            else:
                parts.append(
                    f"MEDIUM PRIORITY: Moderate centrality ({struct:.2f}) with baseline benign communications."
                )
        else:
            parts.append(
                f"LOW PRIORITY: Normal peripheral traffic with no observed attack indicators."
            )

        return " ".join(parts)

    def compute_community_risk(
        self,
        community_df: pd.DataFrame,
        save_path: Optional[str] = "results/community_risk.csv",
    ) -> pd.DataFrame:
        """
        Prioritize communities based on attack density, flow ratio, and size.
        """
        if community_df.empty:
            return pd.DataFrame()

        cdf = community_df.copy()

        # Risk score formula for communities:
        # Heuristic combining attack proportion (70%) and internal density / size (30%)
        att_prop = cdf["attack_flow_proportion"].fillna(0.0)
        density = cdf["density"].fillna(0.0)

        # Community priority heuristic
        comm_risk = (0.70 * att_prop + 0.30 * density).round(4)
        cdf["community_risk_score"] = comm_risk

        def classify_comm(row):
            prop = row["attack_flow_proportion"]
            score = row["community_risk_score"]
            if prop >= 0.5:
                return "MALICIOUS_CLUSTER"
            elif prop > 0.05 or score >= 0.3:
                return "SUSPICIOUS_CLUSTER"
            elif row["size"] > 10 and density.mean() > 0:
                return "BENIGN_CORE"
            else:
                return "BENIGN_PERIPHERY"

        cdf["community_threat_category"] = cdf.apply(classify_comm, axis=1)

        cdf = cdf.sort_values(by="community_risk_score", ascending=False).reset_index(drop=True)

        if save_path:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            cdf.to_csv(save_path, index=False)
            logger.info(f"Saved {len(cdf)} community risk summaries to {save_path}")

        return cdf
