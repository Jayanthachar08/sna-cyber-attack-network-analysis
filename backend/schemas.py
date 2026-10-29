"""
Pydantic schemas and data transfer objects for SNA API.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    service: str = "SNA Cybersecurity Analyzer API"


class DatasetFile(BaseModel):
    filename: str
    path: str
    size_mb: float
    is_zip: bool = False
    subfile: Optional[str] = None


class DatasetStatusResponse(BaseModel):
    available_files: List[DatasetFile]
    active_file: Optional[str] = None
    is_analyzed: bool = False
    last_run_timestamp: Optional[str] = None
    cleaning_stats: Optional[Dict[str, Any]] = None
    parameters: Optional[Dict[str, Any]] = None


class AnalysisRunRequest(BaseModel):
    file_path: Optional[str] = None
    max_rows: int = Field(default=15000, ge=500, le=200000)
    skip_rows: int = Field(default=0, ge=0)
    w_deg: float = Field(default=0.35, ge=0.0, le=1.0)
    w_bet: float = Field(default=0.35, ge=0.0, le=1.0)
    w_pr: float = Field(default=0.30, ge=0.0, le=1.0)
    louvain_res: float = Field(default=1.0, ge=0.1, le=5.0)


class AnalysisRunResponse(BaseModel):
    success: bool
    message: str
    duration_seconds: float
    num_nodes: int
    num_edges: int
    num_communities: int
    active_file: str


class OverviewResponse(BaseModel):
    total_flow_volume: int
    num_nodes: int
    internal_hosts: int
    external_hosts: int
    num_edges: int
    density: float
    total_attack_flows: int
    attack_flow_proportion: float
    num_communities: int
    modularity: float
    priority_tier_counts: Dict[str, int]
    traffic_composition: List[Dict[str, Any]]
    cleaning_audit: Dict[str, Any]
    top_critical_hosts: List[Dict[str, Any]]
    top_risk_communities: List[Dict[str, Any]]


class NetworkNode(BaseModel):
    id: str
    label: str
    is_internal: bool
    priority_tier: str
    community_id: int
    degree: int
    in_degree: int
    out_degree: int
    betweenness: float
    pagerank: float
    combined_criticality: float
    attack_flows: int
    has_attack_evidence: bool
    attack_types: str


class NetworkEdge(BaseModel):
    source: str
    target: str
    weight: int
    attack_flows: int
    has_attack: bool
    attack_types: str
    protocols: str


class NetworkResponse(BaseModel):
    nodes: List[NetworkNode]
    edges: List[NetworkEdge]
    total_graph_nodes: int
    total_graph_edges: int
    is_subgraph: bool
    applied_filter: Dict[str, Any]


class HostRecord(BaseModel):
    rank: int
    host_id: str
    is_internal: bool
    priority_tier: str
    combined_criticality: float
    degree_centrality: float
    betweenness_centrality: float
    pagerank: float
    in_degree: int
    out_degree: int
    total_degree: int
    community_id: int
    attack_flows_associated: int
    observed_attack_types: str
    explanation: str
    investigation_evidence: str


class HostsListResponse(BaseModel):
    hosts: List[HostRecord]
    total_count: int
    page: int
    page_size: int
    total_pages: int


class ConnectionDetail(BaseModel):
    direction: str  # 'incoming' or 'outgoing'
    peer_ip: str
    is_peer_internal: bool
    flow_volume: int
    attack_flows: int
    attack_types: str
    protocols: str


class HostDetailResponse(BaseModel):
    host: HostRecord
    incoming_connections: List[ConnectionDetail]
    outgoing_connections: List[ConnectionDetail]
    community_info: Optional[Dict[str, Any]] = None


class CommunityRecord(BaseModel):
    community_id: int
    community_threat_category: str
    size: int
    density: float
    internal_edges: int
    external_edges: int
    attack_flows_observed: int
    attack_flow_proportion: float
    attack_associated_hosts: int
    observed_attack_types: str
    top_hosts: str
    investigation_priority_score: Optional[float] = None


class CommunitiesResponse(BaseModel):
    communities: List[CommunityRecord]
    total_communities: int
    modularity: float
    largest_community_size: int


class CommunityDetailResponse(BaseModel):
    community: CommunityRecord
    members: List[HostRecord]
    subgraph: NetworkResponse


class TimelinePoint(BaseModel):
    time_bin: str
    benign_count: int
    attack_count: int
    total_count: int
    attack_categories: Dict[str, int]


class TimelineResponse(BaseModel):
    available: bool
    message: Optional[str] = None
    points: List[TimelinePoint]
    total_time_bins: int


class EvaluationResponse(BaseModel):
    precision_at_k: Dict[str, Dict[str, float]]
    attack_host_base_rate: float
    community_modularity: float
    classification_metrics: Optional[Dict[str, Any]] = None
    figures: Dict[str, bool]
