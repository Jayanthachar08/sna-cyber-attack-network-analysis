"""
Unit and integration tests for FastAPI backend and PipelineService.
"""

import pytest
import os
from backend.pipeline_service import PipelineService
from backend.schemas import (
    HealthResponse,
    DatasetStatusResponse,
    AnalysisRunRequest,
    OverviewResponse,
    NetworkResponse,
    HostsListResponse,
    HostDetailResponse,
    CommunitiesResponse,
    CommunityDetailResponse,
    TimelineResponse,
    EvaluationResponse,
)
from backend.api import (
    get_health,
    get_dataset_status,
    run_analysis,
    get_overview,
    get_network,
    get_hosts,
    get_host_detail,
    get_communities,
    get_community_detail,
    get_timeline,
    get_evaluation,
    export_data,
)


def test_health_endpoint():
    res = get_health()
    assert isinstance(res, HealthResponse)
    assert res.status == "ok"
    assert "SNA" in res.service


def test_dataset_status_endpoint():
    status = get_dataset_status()
    assert isinstance(status, DatasetStatusResponse)
    assert len(status.available_files) > 0


def test_run_analysis_and_overview():
    req = AnalysisRunRequest(max_rows=1000, skip_rows=95000)
    run_res = run_analysis(req)
    assert run_res.success is True
    assert run_res.num_nodes > 0
    assert run_res.num_edges > 0

    overview = get_overview()
    assert isinstance(overview, OverviewResponse)
    assert overview.num_nodes == run_res.num_nodes
    assert overview.num_edges == run_res.num_edges
    assert "CRITICAL" in overview.priority_tier_counts


def test_network_endpoint():
    net = get_network(max_nodes=30)
    assert isinstance(net, NetworkResponse)
    assert len(net.nodes) > 0
    assert len(net.nodes) <= 30
    assert len(net.edges) >= 0


def test_hosts_and_detail_endpoint():
    hosts_res = get_hosts(page=1, page_size=10)
    assert isinstance(hosts_res, HostsListResponse)
    assert len(hosts_res.hosts) > 0
    assert hosts_res.page == 1

    first_host_id = hosts_res.hosts[0].host_id
    detail = get_host_detail(first_host_id)
    assert isinstance(detail, HostDetailResponse)
    assert detail.host.host_id == first_host_id


def test_communities_endpoint():
    comm_res = get_communities()
    assert isinstance(comm_res, CommunitiesResponse)
    assert comm_res.total_communities > 0

    cid = comm_res.communities[0].community_id
    c_detail = get_community_detail(cid)
    assert isinstance(c_detail, CommunityDetailResponse)
    assert c_detail.community.community_id == cid
    assert len(c_detail.members) > 0


def test_timeline_endpoint():
    timeline = get_timeline()
    assert isinstance(timeline, TimelineResponse)
    # Timeline is available if timestamps are present in the dataset slice
    if timeline.available:
        assert len(timeline.points) > 0


def test_evaluation_endpoint():
    eval_res = get_evaluation()
    assert isinstance(eval_res, EvaluationResponse)
    assert "precision_at_k" in eval_res.model_dump()


def test_export_endpoint():
    res = export_data("critical-hosts")
    assert res.status_code == 200
    assert b"host_id" in res.body
    assert b"combined_criticality" in res.body
