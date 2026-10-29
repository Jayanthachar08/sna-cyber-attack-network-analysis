"""
FastAPI application for Social Network Analysis Cybersecurity Platform.
Exposes REST endpoints for dataset management, graph metrics, community detection,
temporal analytics, research evaluation, and forensic artifact export.
"""

import os
import sys
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse

# Ensure root dir in path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.schemas import (
    HealthResponse,
    DatasetStatusResponse,
    AnalysisRunRequest,
    AnalysisRunResponse,
    OverviewResponse,
    NetworkResponse,
    HostsListResponse,
    HostDetailResponse,
    CommunitiesResponse,
    CommunityDetailResponse,
    TimelineResponse,
    EvaluationResponse,
)
from backend.pipeline_service import PipelineService

app = FastAPI(
    title="SNA Cybersecurity Analyzer API",
    description="Graph-theoretic host criticality and community detection for intrusion analysis.",
    version="1.0.0",
)

# CORS configuration for Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

service = PipelineService()


@app.get("/api/health", response_model=HealthResponse)
def get_health():
    return HealthResponse()


@app.get("/api/dataset/status", response_model=DatasetStatusResponse)
def get_dataset_status():
    status = service.get_status()
    return DatasetStatusResponse(**status)


@app.post("/api/analysis/run", response_model=AnalysisRunResponse)
def run_analysis(req: AnalysisRunRequest):
    try:
        res = service.run_analysis(
            file_path=req.file_path,
            max_rows=req.max_rows,
            skip_rows=req.skip_rows,
            w_deg=req.w_deg,
            w_bet=req.w_bet,
            w_pr=req.w_pr,
            louvain_res=req.louvain_res,
        )
        return AnalysisRunResponse(**res)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/overview", response_model=OverviewResponse)
def get_overview():
    try:
        data = service.get_overview()
        return OverviewResponse(**data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/network", response_model=NetworkResponse)
def get_network(
    max_nodes: int = 100,
    focus_host: Optional[str] = None,
    community_id: Optional[int] = None,
    min_weight: int = 1,
):
    try:
        # Convert any FastAPI Query objects if invoked directly in Python
        if hasattr(max_nodes, "default"):
            max_nodes = max_nodes.default
        if hasattr(focus_host, "default"):
            focus_host = focus_host.default
        if hasattr(community_id, "default"):
            community_id = community_id.default
        if hasattr(min_weight, "default"):
            min_weight = min_weight.default

        data = service.get_network(
            max_nodes=int(max_nodes),
            focus_host=str(focus_host) if focus_host else None,
            community_id=int(community_id) if community_id is not None else None,
            min_weight=int(min_weight),
        )
        return NetworkResponse(**data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/hosts", response_model=HostsListResponse)
def get_hosts(
    page: int = 1,
    page_size: int = 25,
    sort_by: str = "combined_criticality",
    sort_dir: str = "desc",
    search: Optional[str] = None,
    priority_tier: Optional[str] = None,
    community_id: Optional[int] = None,
):
    try:
        # Convert any FastAPI Query objects if invoked directly in Python
        if hasattr(page, "default"):
            page = page.default
        if hasattr(page_size, "default"):
            page_size = page_size.default
        if hasattr(sort_by, "default"):
            sort_by = sort_by.default
        if hasattr(sort_dir, "default"):
            sort_dir = sort_dir.default
        if hasattr(search, "default"):
            search = search.default
        if hasattr(priority_tier, "default"):
            priority_tier = priority_tier.default
        if hasattr(community_id, "default"):
            community_id = community_id.default

        data = service.get_hosts(
            page=int(page),
            page_size=int(page_size),
            sort_by=str(sort_by),
            sort_dir=str(sort_dir),
            search=str(search) if search else None,
            priority_tier=str(priority_tier) if priority_tier else None,
            community_id=int(community_id) if community_id is not None else None,
        )
        return HostsListResponse(**data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/hosts/{host_id}", response_model=HostDetailResponse)
def get_host_detail(host_id: str):
    data = service.get_host_detail(host_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Host '{host_id}' not found.")
    return HostDetailResponse(**data)


@app.get("/api/communities", response_model=CommunitiesResponse)
def get_communities():
    try:
        data = service.get_communities()
        return CommunitiesResponse(**data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/communities/{community_id}", response_model=CommunityDetailResponse)
def get_community_detail(community_id: int):
    data = service.get_community_detail(community_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Community {community_id} not found.")
    return CommunityDetailResponse(**data)


@app.get("/api/timeline", response_model=TimelineResponse)
def get_timeline():
    try:
        data = service.get_timeline()
        return TimelineResponse(**data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/evaluation", response_model=EvaluationResponse)
def get_evaluation():
    try:
        data = service.get_evaluation()
        return EvaluationResponse(**data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/figures/{figure_name}")
def get_figure(figure_name: str):
    allowed = {
        "precision_at_k": "precision_at_k_comparison.png",
        "community_enrichment": "community_attack_enrichment.png",
        "precision_at_k_comparison.png": "precision_at_k_comparison.png",
        "community_attack_enrichment.png": "community_attack_enrichment.png",
    }
    if figure_name not in allowed:
        raise HTTPException(status_code=404, detail="Figure not found.")

    file_path = os.path.join(ROOT_DIR, "results", "figures", allowed[figure_name])
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Figure image has not been generated yet.")
    return FileResponse(file_path, media_type="image/png")


@app.get("/api/export/{file_type}")
def export_data(file_type: str):
    try:
        # Strip .csv if provided by frontend
        clean_type = file_type.replace(".csv", "")
        csv_data, filename = service.export_csv(clean_type)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Mount compiled frontend static assets for unified single-server deployment
from fastapi.staticfiles import StaticFiles

dist_dir = os.path.join(ROOT_DIR, "frontend", "dist")
if os.path.exists(dist_dir):
    app.mount("/", StaticFiles(directory=dist_dir, html=True), name="static")

