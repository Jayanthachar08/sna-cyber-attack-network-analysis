"""
Preprocessing Module for Cybersecurity Flow Data.
Handles:
- IP address validation and sanitization.
- Multi-format robust timestamp parsing (e.g. CIC-IDS2017 day-first formats).
- Attack label preservation and categorization.
- Comprehensive exclusion logging (rows loaded, retained, dropped with reasons).
- Flow aggregation for graph construction (preserving attack evidence and traffic volume).
"""

import re
import os
import logging
from typing import Dict, Any, Tuple, Optional, List
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

# Basic IPv4 validation regex
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# Standard CIC-IDS2017 attack family mapping
ATTACK_CATEGORY_MAPPING = {
    "benign": "BENIGN",
    "ddos": "DDoS",
    "portscan": "PortScan",
    "bot": "Botnet",
    "infiltration": "Infiltration",
    "web attack  brute force": "Web Attack - Brute Force",
    "web attack - brute force": "Web Attack - Brute Force",
    "web attack  xss": "Web Attack - XSS",
    "web attack - xss": "Web Attack - XSS",
    "web attack  sql injection": "Web Attack - SQL Injection",
    "web attack - sql injection": "Web Attack - SQL Injection",
    "ftp-patator": "Brute Force - FTP",
    "ssh-patator": "Brute Force - SSH",
    "dos slowloris": "DoS - Slowloris",
    "dos slowhttptest": "DoS - Slowhttptest",
    "dos hulk": "DoS - Hulk",
    "dos goldeneye": "DoS - GoldenEye",
    "heartbleed": "Heartbleed",
}


def is_valid_ipv4(ip: Any) -> bool:
    """Check if value is a valid IPv4 string."""
    if not isinstance(ip, str):
        return False
    ip = ip.strip()
    return bool(IPV4_REGEX.match(ip))


def normalize_attack_label(raw_label: Any) -> Tuple[str, bool, str]:
    """
    Standardize raw label string.
    Returns: (cleaned_label, is_attack, broad_category)
    """
    if pd.isna(raw_label):
        return "UNKNOWN", False, "Unknown"

    cleaned = str(raw_label).strip()
    lowered = cleaned.lower()

    if lowered == "benign":
        return "BENIGN", False, "BENIGN"

    # Match attack category
    broad_cat = "Other Attack"
    for pattern, std_name in ATTACK_CATEGORY_MAPPING.items():
        if pattern in lowered:
            broad_cat = std_name
            break

    return cleaned, True, broad_cat


def parse_timestamps(series: pd.Series) -> pd.Series:
    """
    Parse timestamps with format fallback.
    CIC-IDS2017 uses 'd/m/Y H:M' or 'dd/mm/yyyy hh:mm:ss'.
    """
    if series.empty:
        return pd.Series(dtype="datetime64[ns]")

    # Convert to string and strip
    str_series = series.astype(str).str.strip()

    # Try fast parsing with format='mixed' and dayfirst=True
    try:
        parsed = pd.to_datetime(str_series, format="mixed", dayfirst=True, errors="coerce")
        return parsed
    except Exception as e:
        logger.warning(f"Default datetime parsing encountered issues: {e}. Falling back to format list.")

    # Fallback to specific formats if coerce failed on all
    formats = [
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y %I:%M:%S %p",
        "%d/%m/%Y %I:%M %p",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M",
    ]
    result = pd.Series(pd.NaT, index=series.index)
    for fmt in formats:
        mask = result.isna()
        if not mask.any():
            break
        try:
            parsed = pd.to_datetime(str_series[mask], format=fmt, errors="coerce")
            result.update(parsed)
        except Exception:
            pass

    return result


class Preprocessor:
    def __init__(self):
        self.stats = {
            "total_rows_loaded": 0,
            "retained_rows": 0,
            "dropped_missing_ip": 0,
            "dropped_invalid_ip": 0,
            "dropped_missing_label": 0,
            "dropped_malformed_timestamp": 0,
        }

    def clean_chunk(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, int]]:
        """
        Sanitize and validate a single dataframe chunk.
        Enforces IP validation, timestamp conversion, and label normalization.
        """
        initial_count = len(df)
        chunk_stats = {
            "loaded": initial_count,
            "dropped_missing_ip": 0,
            "dropped_invalid_ip": 0,
            "dropped_missing_label": 0,
            "dropped_unparseable_time": 0,
            "retained": 0,
        }

        if initial_count == 0:
            return df.copy(), chunk_stats

        work_df = df.copy()

        # 1. Missing IP check
        missing_ip_mask = work_df["source_ip"].isna() | work_df["destination_ip"].isna()
        missing_ip_count = int(missing_ip_mask.sum())
        chunk_stats["dropped_missing_ip"] = missing_ip_count
        if missing_ip_count > 0:
            work_df = work_df[~missing_ip_mask]

        if work_df.empty:
            return work_df, chunk_stats

        # 2. String strip for IPs
        work_df["source_ip"] = work_df["source_ip"].astype(str).str.strip()
        work_df["destination_ip"] = work_df["destination_ip"].astype(str).str.strip()

        # 3. IP address format validation
        valid_src = work_df["source_ip"].apply(is_valid_ipv4)
        valid_dst = work_df["destination_ip"].apply(is_valid_ipv4)
        valid_ip_mask = valid_src & valid_dst
        invalid_ip_count = int((~valid_ip_mask).sum())
        chunk_stats["dropped_invalid_ip"] = invalid_ip_count
        if invalid_ip_count > 0:
            work_df = work_df[valid_ip_mask]

        if work_df.empty:
            return work_df, chunk_stats

        # 4. Label normalization
        if "label" in work_df.columns:
            missing_label_mask = work_df["label"].isna()
            chunk_stats["dropped_missing_label"] = int(missing_label_mask.sum())
            if missing_label_mask.any():
                work_df = work_df[~missing_label_mask]

            norm_results = work_df["label"].apply(normalize_attack_label)
            work_df["label_clean"] = [res[0] for res in norm_results]
            work_df["is_attack"] = [res[1] for res in norm_results]
            work_df["attack_category"] = [res[2] for res in norm_results]
        else:
            work_df["label_clean"] = "UNKNOWN"
            work_df["is_attack"] = False
            work_df["attack_category"] = "Unknown"

        # 5. Timestamp parsing
        if "timestamp" in work_df.columns:
            parsed_times = parse_timestamps(work_df["timestamp"])
            unparseable_mask = parsed_times.isna()
            chunk_stats["dropped_unparseable_time"] = int(unparseable_mask.sum())
            work_df["timestamp_parsed"] = parsed_times
            # We retain records even if timestamp is unparseable for topology, but mark it NaT
        else:
            work_df["timestamp_parsed"] = pd.NaT

        # Port and protocol normalization if present
        if "protocol" in work_df.columns:
            work_df["protocol"] = pd.to_numeric(work_df["protocol"], errors="coerce").fillna(0).astype(int)
        if "destination_port" in work_df.columns:
            work_df["destination_port"] = pd.to_numeric(work_df["destination_port"], errors="coerce").fillna(0).astype(int)
        if "source_port" in work_df.columns:
            work_df["source_port"] = pd.to_numeric(work_df["source_port"], errors="coerce").fillna(0).astype(int)

        chunk_stats["retained"] = len(work_df)

        # Update cumulative stats
        self.stats["total_rows_loaded"] += initial_count
        self.stats["retained_rows"] += chunk_stats["retained"]
        self.stats["dropped_missing_ip"] += chunk_stats["dropped_missing_ip"]
        self.stats["dropped_invalid_ip"] += chunk_stats["dropped_invalid_ip"]
        self.stats["dropped_missing_label"] += chunk_stats["dropped_missing_label"]
        self.stats["dropped_malformed_timestamp"] += chunk_stats["dropped_unparseable_time"]

        return work_df, chunk_stats

    def aggregate_flows(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Aggregate individual network flows into directed host-to-host edges.
        Calculates:
        - total_flows (weight)
        - attack_flows (count of flows with attack label)
        - benign_flows (count of benign flows)
        - attack_ratio (attack_flows / total_flows)
        - attack_types (set or comma-separated list of observed attack labels)
        - protocols (list of distinct IP protocols)
        - earliest_time & latest_time
        """
        if df.empty:
            return pd.DataFrame(columns=[
                "source_ip", "destination_ip", "weight", "attack_flows",
                "benign_flows", "attack_ratio", "attack_types", "protocols",
                "earliest_time", "latest_time"
            ])

        def summarize_attack_types(series: pd.Series) -> str:
            attacks = set(series[series != "BENIGN"].dropna().unique())
            return ", ".join(sorted(str(a) for a in attacks)) if attacks else "None"

        def summarize_protocols(series: pd.Series) -> str:
            unique_p = sorted(set(series.dropna().astype(int).unique()))
            # Convert 6 -> TCP, 17 -> UDP, 1 -> ICMP
            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            names = [proto_map.get(p, str(p)) for p in unique_p]
            return ", ".join(names) if names else "Unknown"

        # Group by directed pair (source_ip, destination_ip)
        grouped = df.groupby(["source_ip", "destination_ip"])

        agg_dict = {
            "source_ip": "count",  # total flows
            "is_attack": ["sum", lambda x: (x == False).sum()],
            "label_clean": summarize_attack_types,
        }

        if "protocol" in df.columns:
            agg_dict["protocol"] = summarize_protocols

        if "timestamp_parsed" in df.columns:
            agg_dict["timestamp_parsed"] = ["min", "max"]

        agg_df = grouped.agg(agg_dict)

        # Flatten multi-level columns
        flat_cols = []
        for col_name, agg_func in agg_df.columns:
            if col_name == "source_ip":
                flat_cols.append("weight")
            elif col_name == "is_attack" and agg_func == "sum":
                flat_cols.append("attack_flows")
            elif col_name == "is_attack":
                flat_cols.append("benign_flows")
            elif col_name == "label_clean":
                flat_cols.append("attack_types")
            elif col_name == "protocol":
                flat_cols.append("protocols")
            elif col_name == "timestamp_parsed" and agg_func == "min":
                flat_cols.append("earliest_time")
            elif col_name == "timestamp_parsed" and agg_func == "max":
                flat_cols.append("latest_time")
            else:
                flat_cols.append(f"{col_name}_{agg_func}")

        agg_df.columns = flat_cols
        agg_df = agg_df.reset_index()

        # Compute attack ratio
        agg_df["attack_ratio"] = (agg_df["attack_flows"] / agg_df["weight"]).round(4)

        return agg_df

    def get_summary_report(self) -> Dict[str, Any]:
        """Return cumulative processing audit metrics."""
        return dict(self.stats)
