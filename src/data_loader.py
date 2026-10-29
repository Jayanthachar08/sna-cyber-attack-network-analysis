"""
Data Loader Module for CIC-IDS2017 Dataset.
Supports:
- Scanning datasets in directory or archives.
- Inspection of headers, size, and essential columns.
- Direct loading of CSV and ZIP archives containing CSVs.
- Chunked processing to handle multi-gigabyte datasets without memory crashes.
- Verification of required IP addresses and timestamps.
"""

import os
import glob
import zipfile
import logging
from typing import List, Dict, Generator, Optional, Tuple, Any
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Standard candidate column names in CIC-IDS2017 variations
COLUMN_MAPPING_CANDIDATES = {
    "source_ip": ["source ip", "src ip", "source_ip", "src_ip", "srcip"],
    "destination_ip": ["destination ip", "dst ip", "dest ip", "destination_ip", "dst_ip", "dstip"],
    "source_port": ["source port", "src port", "source_port", "src_port", "sport"],
    "destination_port": ["destination port", "dst port", "dest port", "destination_port", "dst_port", "dport"],
    "protocol": ["protocol", "proto"],
    "timestamp": ["timestamp", "time", "date_time", "flow timestamp"],
    "label": ["label", "attack", "class"],
    "flow_duration": ["flow duration", "duration"],
    "total_fwd_packets": ["total fwd packets", "tot fwd pkts", "total fwd packet"],
    "total_bwd_packets": ["total backward packets", "total bwd packets", "tot bwd pkts"],
    "total_fwd_bytes": ["total length of fwd packets", "totlen fwd pkts", "fwd packet length total"],
    "total_bwd_bytes": ["total length of bwd packets", "totlen bwd pkts", "bwd packet length total"],
}


class DataLoader:
    def __init__(self, data_dirs: Optional[List[str]] = None):
        """
        Initialize DataLoader with fallback directories.
        """
        if data_dirs is None:
            self.data_dirs = [
                os.path.join("Datasets", "TrafficLabelling"),
                os.path.join("data", "raw"),
                os.path.join("Datasets", "MachineLearningCVE"),
                "Datasets",
            ]
        else:
            self.data_dirs = data_dirs

    def find_dataset_files(self) -> List[Dict[str, Any]]:
        """
        Locate all CSV and ZIP files across configured directories.
        Returns a list of dicts with file metadata.
        """
        found_files = []
        seen_paths = set()

        for d in self.data_dirs:
            if not os.path.exists(d):
                continue

            # Look for CSV files
            csv_pattern = os.path.join(d, "**", "*.csv")
            for f in glob.glob(csv_pattern, recursive=True):
                norm_p = os.path.normpath(f)
                if norm_p not in seen_paths:
                    seen_paths.add(norm_p)
                    found_files.append({
                        "filename": os.path.basename(f),
                        "path": norm_p,
                        "type": "csv",
                        "size_mb": round(os.path.getsize(f) / (1024 * 1024), 2),
                        "directory": os.path.dirname(norm_p),
                    })

            # Look for ZIP archives
            zip_pattern = os.path.join(d, "**", "*.zip")
            for f in glob.glob(zip_pattern, recursive=True):
                norm_p = os.path.normpath(f)
                if norm_p not in seen_paths:
                    seen_paths.add(norm_p)
                    found_files.append({
                        "filename": os.path.basename(f),
                        "path": norm_p,
                        "type": "zip",
                        "size_mb": round(os.path.getsize(f) / (1024 * 1024), 2),
                        "directory": os.path.dirname(norm_p),
                    })

        return found_files

    def inspect_file(self, file_path: str) -> Dict[str, Any]:
        """
        Inspect headers, columns, row samples, and assess SNA suitability.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        is_zip = file_path.lower().endswith(".zip")
        raw_columns = []
        sample_df = None

        if is_zip:
            with zipfile.ZipFile(file_path, "r") as z:
                csv_members = [m for m in z.namelist() if m.lower().endswith(".csv")]
                if not csv_members:
                    return {
                        "file_path": file_path,
                        "is_zip": True,
                        "suitable_for_sna": False,
                        "error": "No CSV files found inside ZIP archive",
                    }
                first_csv = csv_members[0]
                with z.open(first_csv) as f:
                    sample_df = pd.read_csv(f, nrows=5)
                    raw_columns = list(sample_df.columns)
        else:
            sample_df = pd.read_csv(file_path, nrows=5)
            raw_columns = list(sample_df.columns)

        # Standardize column strings (strip extra whitespace commonly found in CIC-IDS2017)
        cleaned_columns = [str(c).strip() for c in raw_columns]
        mapping = self._detect_column_mapping(cleaned_columns)

        has_src_ip = "source_ip" in mapping
        has_dst_ip = "destination_ip" in mapping
        has_time = "timestamp" in mapping
        has_label = "label" in mapping

        suitable = has_src_ip and has_dst_ip and has_label

        missing = []
        if not has_src_ip:
            missing.append("Source IP")
        if not has_dst_ip:
            missing.append("Destination IP")
        if not has_label:
            missing.append("Label")

        return {
            "file_path": file_path,
            "is_zip": is_zip,
            "total_columns": len(raw_columns),
            "columns": cleaned_columns,
            "detected_mapping": mapping,
            "has_source_ip": has_src_ip,
            "has_destination_ip": has_dst_ip,
            "has_timestamp": has_time,
            "has_label": has_label,
            "suitable_for_sna": suitable,
            "missing_essential_columns": missing,
            "sample_head": sample_df.to_dict(orient="records") if sample_df is not None else [],
        }

    def _detect_column_mapping(self, columns: List[str]) -> Dict[str, str]:
        """
        Map dataset column names to standardized canonical field names.
        """
        mapping = {}
        col_lower_map = {col.lower().strip(): col for col in columns}

        for internal_field, candidates in COLUMN_MAPPING_CANDIDATES.items():
            for cand in candidates:
                if cand in col_lower_map:
                    mapping[internal_field] = col_lower_map[cand]
                    break
        return mapping

    def load_chunks(
        self,
        file_path: str,
        chunksize: int = 50000,
        max_rows: Optional[int] = None,
        skip_rows: int = 0,
        use_standard_names: bool = True,
    ) -> Generator[pd.DataFrame, None, None]:
        """
        Stream CSV data in manageable chunks.
        Applies column mapping and strips whitespace from headers.
        """
        inspection = self.inspect_file(file_path)
        if not inspection["suitable_for_sna"]:
            missing_str = ", ".join(inspection["missing_essential_columns"])
            raise ValueError(
                f"Dataset file '{os.path.basename(file_path)}' is unsuitable for Social Network Analysis. "
                f"Missing essential columns: {missing_str}. "
                f"Please ensure you are loading from TrafficLabelling (with IP addresses) and not MachineLearningCVE."
            )

        col_map = inspection["detected_mapping"]
        # Invert mapping: actual_col_name -> internal_field_name
        rename_map = {actual: internal for internal, actual in col_map.items()}

        rows_read = 0
        reader = None
        skip_arg = range(1, skip_rows + 1) if skip_rows > 0 else None

        if inspection["is_zip"]:
            z = zipfile.ZipFile(file_path, "r")
            csv_members = [m for m in z.namelist() if m.lower().endswith(".csv")]
            f = z.open(csv_members[0])
            reader = pd.read_csv(f, chunksize=chunksize, skiprows=skip_arg, low_memory=False)
        else:
            reader = pd.read_csv(file_path, chunksize=chunksize, skiprows=skip_arg, low_memory=False)

        try:
            for chunk in reader:
                # Strip leading/trailing whitespaces in chunk column names
                chunk.columns = [str(c).strip() for c in chunk.columns]

                if use_standard_names:
                    # Keep mapped columns and rename to internal fields
                    keep_cols = [c for c in chunk.columns if c in rename_map]
                    chunk = chunk[keep_cols].rename(columns=rename_map)

                if max_rows is not None and rows_read + len(chunk) > max_rows:
                    remaining = max_rows - rows_read
                    if remaining > 0:
                        yield chunk.iloc[:remaining]
                    break

                rows_read += len(chunk)
                yield chunk

        finally:
            if inspection["is_zip"]:
                f.close()
                z.close()

    def load_dataframe(
        self,
        file_path: str,
        max_rows: Optional[int] = None,
        skip_rows: int = 0,
        use_standard_names: bool = True,
    ) -> pd.DataFrame:
        """
        Convenience function to load a bounded or full dataset into memory.
        """
        chunks = []
        for chunk in self.load_chunks(
            file_path,
            chunksize=50000,
            max_rows=max_rows,
            skip_rows=skip_rows,
            use_standard_names=use_standard_names,
        ):
            chunks.append(chunk)
        if not chunks:
            return pd.DataFrame()
        return pd.concat(chunks, ignore_index=True)
