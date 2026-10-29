import os
import pytest
import pandas as pd
import numpy as np
from src.data_loader import DataLoader
from src.preprocessing import (
    Preprocessor,
    is_valid_ipv4,
    normalize_attack_label,
    parse_timestamps,
)


def test_ip_validation():
    assert is_valid_ipv4("192.168.10.1") is True
    assert is_valid_ipv4("10.0.0.254") is True
    assert is_valid_ipv4("8.8.8.8") is True
    assert is_valid_ipv4("999.999.999.999") is False
    assert is_valid_ipv4("invalid-ip") is False
    assert is_valid_ipv4("") is False
    assert is_valid_ipv4(None) is False
    assert is_valid_ipv4(12345) is False


def test_label_normalization():
    # BENIGN
    clean, is_att, cat = normalize_attack_label("BENIGN")
    assert clean == "BENIGN"
    assert is_att is False
    assert cat == "BENIGN"

    # DDoS
    clean, is_att, cat = normalize_attack_label("DDoS")
    assert clean == "DDoS"
    assert is_att is True
    assert cat == "DDoS"

    # PortScan
    clean, is_att, cat = normalize_attack_label("PortScan")
    assert clean == "PortScan"
    assert is_att is True
    assert cat == "PortScan"

    # Null / Missing
    clean, is_att, cat = normalize_attack_label(None)
    assert clean == "UNKNOWN"
    assert is_att is False


def test_timestamp_parsing():
    series = pd.Series([
        "7/7/2017 3:30",
        "03/07/2017 08:55:58",
        "2017-07-07 14:22:00",
        "invalid-date"
    ])
    parsed = parse_timestamps(series)
    assert not pd.isna(parsed.iloc[0])
    assert parsed.iloc[0].year == 2017
    assert not pd.isna(parsed.iloc[1])
    assert parsed.iloc[1].day == 3
    assert not pd.isna(parsed.iloc[2])
    assert pd.isna(parsed.iloc[3])


def test_preprocessor_clean_chunk():
    data = {
        "source_ip": ["192.168.1.1", "invalid_ip", "10.0.0.1", None, "172.16.0.2"],
        "destination_ip": ["192.168.1.2", "192.168.1.3", "256.0.0.1", "10.0.0.2", "172.16.0.3"],
        "label": ["BENIGN", "DDoS", "PortScan", "BENIGN", "DDoS"],
        "timestamp": ["7/7/2017 10:00", "7/7/2017 10:01", "7/7/2017 10:02", "7/7/2017 10:03", "7/7/2017 10:04"],
        "protocol": [6, 6, 17, 6, 6],
    }
    df = pd.DataFrame(data)
    preprocessor = Preprocessor()
    clean_df, stats = preprocessor.clean_chunk(df)

    # Valid rows: row 0 ("192.168.1.1" -> "192.168.1.2") and row 4 ("172.16.0.2" -> "172.16.0.3")
    # Row 1 has invalid source_ip
    # Row 2 has invalid destination_ip (256...)
    # Row 3 has missing source_ip
    assert len(clean_df) == 2
    assert stats["loaded"] == 5
    assert stats["dropped_missing_ip"] == 1
    assert stats["dropped_invalid_ip"] == 2
    assert stats["retained"] == 2
    assert "label_clean" in clean_df.columns
    assert "is_attack" in clean_df.columns
    assert "timestamp_parsed" in clean_df.columns


def test_aggregate_flows():
    # Test aggregation of multiple repeated flows between hosts
    clean_data = {
        "source_ip": ["192.168.1.1", "192.168.1.1", "192.168.1.1", "10.0.0.1"],
        "destination_ip": ["192.168.1.2", "192.168.1.2", "192.168.1.2", "10.0.0.2"],
        "label_clean": ["BENIGN", "DDoS", "DDoS", "BENIGN"],
        "is_attack": [False, True, True, False],
        "protocol": [6, 6, 6, 17],
        "timestamp_parsed": pd.to_datetime(["2017-07-07 10:00", "2017-07-07 10:05", "2017-07-07 10:10", "2017-07-07 11:00"]),
    }
    df = pd.DataFrame(clean_data)
    preprocessor = Preprocessor()
    agg_df = preprocessor.aggregate_flows(df)

    assert len(agg_df) == 2
    pair1 = agg_df[agg_df["source_ip"] == "192.168.1.1"].iloc[0]
    assert pair1["weight"] == 3
    assert pair1["attack_flows"] == 2
    assert pair1["benign_flows"] == 1
    assert round(pair1["attack_ratio"], 2) == 0.67
    assert "DDoS" in pair1["attack_types"]
    assert "TCP" in pair1["protocols"]


def test_data_loader_inspection_real_datasets():
    loader = DataLoader()
    files = loader.find_dataset_files()
    assert len(files) > 0

    # Test inspection on TrafficLabelling file
    traffic_file = os.path.join("Datasets", "TrafficLabelling", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    if os.path.exists(traffic_file):
        info = loader.inspect_file(traffic_file)
        assert info["suitable_for_sna"] is True
        assert info["has_source_ip"] is True
        assert info["has_destination_ip"] is True
        assert info["has_label"] is True

    # Test inspection on MachineLearningCVE file
    ml_file = os.path.join("Datasets", "MachineLearningCVE", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    if os.path.exists(ml_file):
        info_ml = loader.inspect_file(ml_file)
        assert info_ml["suitable_for_sna"] is False
        assert "Source IP" in info_ml["missing_essential_columns"]
