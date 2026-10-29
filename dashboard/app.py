"""
Main Streamlit Application:
Detection of Critical Hosts and Malicious Communities in Cyber Attack Networks Using Social Network Analysis.
"""

import os
import sys
import time
import pandas as pd
import numpy as np
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# Ensure project root is in system path
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
from dashboard.components.metrics_cards import apply_custom_css, render_metric_card
from dashboard.components.network_graph import create_plotly_network_figure

st.set_page_config(
    page_title="SNA Cybersecurity Investigation Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

apply_custom_css()


@st.cache_data(show_spinner=False)
def run_pipeline(
    file_path: str,
    max_rows: int = 15000,
    skip_rows: int = 0,
    w_deg: float = 0.35,
    w_bet: float = 0.35,
    w_pr: float = 0.30,
    louvain_res: float = 1.0,
):
    """
    Execute complete end-to-end SNA cybersecurity pipeline on selected dataset slice.
    """
    loader = DataLoader()
    raw_df = loader.load_dataframe(file_path, max_rows=max_rows, skip_rows=skip_rows)

    preprocessor = Preprocessor()
    clean_df, cleaning_stats = preprocessor.clean_chunk(raw_df)

    builder = NetworkGraphBuilder()
    G = builder.build_graph_from_flows(clean_df)
    graph_stats = builder.get_graph_statistics(G)

    # Centrality
    analyzer = CentralityAnalyzer(weight_degree=w_deg, weight_betweenness=w_bet, weight_pagerank=w_pr)
    centrality_df = analyzer.compute_all_centralities(G)

    # Community Detection
    detector = CommunityDetector(resolution=louvain_res)
    communities, modularity, UG = detector.detect_communities(G)
    membership_df = detector.build_membership_dataframe(G, communities, save_path="results/host_community_membership.csv")
    community_df = detector.summarize_communities(G, UG, communities, save_path="results/communities.csv")

    # Risk Analysis
    risk_analyzer = RiskAnalyzer()
    host_risk_df = risk_analyzer.compute_host_risk(
        centrality_df, membership_df, community_df, save_path="results/suspicious_hosts.csv"
    )
    comm_risk_df = risk_analyzer.compute_community_risk(community_df, save_path="results/community_risk.csv")

    # Evaluation
    evaluator = ModelEvaluator()
    eval_results = evaluator.evaluate_centrality_rankings(centrality_df, k_values=[5, 10, 20])
    evaluator.plot_precision_at_k(eval_results)
    evaluator.plot_community_attack_enrichment(community_df)

    return {
        "raw_df": raw_df,
        "clean_df": clean_df,
        "cleaning_stats": cleaning_stats,
        "G": G,
        "UG": UG,
        "graph_stats": graph_stats,
        "centrality_df": centrality_df,
        "host_risk_df": host_risk_df,
        "comm_risk_df": comm_risk_df,
        "communities": communities,
        "modularity": modularity,
        "eval_results": eval_results,
    }


# ==========================================
# SIDEBAR CONFIGURATION
# ==========================================
st.sidebar.title("🛡️ SNA Cyber Defense")
st.sidebar.caption("Graph-Theoretic Intrusion & Structure Analysis")

# Scan available files
data_loader = DataLoader()
found_files = data_loader.find_dataset_files()
traffic_files = [f for f in found_files if "trafficlabelling" in f["path"].lower() or "raw" in f["path"].lower()]

if not traffic_files:
    traffic_files = found_files

file_options = {f"{f['filename']} ({f['size_mb']} MB)": f["path"] for f in traffic_files}

selected_label = st.sidebar.selectbox(
    "Select Dataset File",
    options=list(file_options.keys()),
    index=0 if file_options else 0,
)
selected_file_path = file_options.get(selected_label) if file_options else None

st.sidebar.markdown("---")
st.sidebar.subheader("Analysis Parameters")

sample_size = st.sidebar.select_slider(
    "Flow Sample Limit",
    options=[5000, 10000, 15000, 25000, 50000, 100000],
    value=15000,
    help="Number of network flows to process in this run.",
)

# Attack onset offset preset
is_friday_ddos = "Friday-WorkingHours-Afternoon-DDos" in (selected_file_path or "")
default_offset = 95000 if is_friday_ddos else 0

offset_input = st.sidebar.number_input(
    "Flow Record Offset (Skiprows)",
    min_value=0,
    max_value=500000,
    value=default_offset,
    step=5000,
    help="Offset in CSV to capture specific attack windows (e.g. 95,000 for Friday DDoS attack onset).",
)

with st.sidebar.expander("⚙️ Advanced SNA Settings", expanded=False):
    st.write("**Centrality Weights for Combined Criticality:**")
    w_deg = st.slider("Degree Weight", 0.0, 1.0, 0.35, 0.05)
    w_bet = st.slider("Betweenness Weight", 0.0, 1.0, 0.35, 0.05)
    w_pr = st.slider("PageRank Weight", 0.0, 1.0, 0.30, 0.05)
    louvain_res = st.slider("Louvain Resolution", 0.5, 2.0, 1.0, 0.1)

run_btn = st.sidebar.button("🚀 Run / Recompute Analysis", use_container_width=True)

# Navigation
page = st.sidebar.radio(
    "Navigation",
    options=[
        "Overview",
        "Network Explorer",
        "Critical Hosts",
        "Community Analysis",
        "Timeline",
        "Evaluation & Benchmarks",
        "Exports & Methodology",
    ],
    index=0,
)

st.sidebar.markdown("---")
st.sidebar.caption("B.Tech Computer Science Project")
st.sidebar.caption("Academic Social Network Analysis Platform")


# ==========================================
# RUN OR LOAD PIPELINE STATE
# ==========================================
if "pipeline_results" not in st.session_state or run_btn:
    if selected_file_path and os.path.exists(selected_file_path):
        with st.spinner("Processing network graph, computing centralities, and detecting communities..."):
            st.session_state["pipeline_results"] = run_pipeline(
                file_path=selected_file_path,
                max_rows=sample_size,
                skip_rows=offset_input,
                w_deg=w_deg,
                w_bet=w_bet,
                w_pr=w_pr,
                louvain_res=louvain_res,
            )
            st.session_state["last_loaded_file"] = selected_file_path
    else:
        st.error("No valid dataset file found. Please check data directory.")
        st.stop()

res = st.session_state["pipeline_results"]
G = res["G"]
graph_stats = res["graph_stats"]
host_risk_df = res["host_risk_df"]
comm_risk_df = res["comm_risk_df"]
clean_df = res["clean_df"]
cleaning_stats = res["cleaning_stats"]
eval_res = res["eval_results"]


# ==========================================
# PAGE 1: OVERVIEW
# ==========================================
if page == "Overview":
    st.title("🌐 Network Topology & Attack Evidence Overview")
    st.markdown("""
    This platform applies **Social Network Analysis (SNA)** graph algorithms to detect structurally critical hosts
    and suspicious communication communities within cyber attack networks.
    """)

    # Top Metric Tiles
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_metric_card("Analyzed Flows", f"{graph_stats['total_flow_volume']:,}", f"Offset: {offset_input:,}")
    with c2:
        render_metric_card("Unique Hosts (Nodes)", f"{graph_stats['num_nodes']:,}", f"{graph_stats['internal_hosts']} Int / {graph_stats['external_hosts']} Ext")
    with c3:
        render_metric_card("Directed Edges", f"{graph_stats['num_edges']:,}", f"Density: {graph_stats['density']:.5f}")
    with c4:
        attack_ratio = graph_stats['attack_flow_proportion']
        render_metric_card("Observed Attack Flows", f"{graph_stats['total_attack_flows']:,}", f"{attack_ratio:.1%} of total volume")

    st.markdown("<h3 class='cyber-header'>Investigation Priority Breakdown</h3>", unsafe_allow_html=True)
    if not host_risk_df.empty:
        p_cols = st.columns(5)
        tiers = ["CRITICAL", "HIGH", "INFRASTRUCTURE_WATCH", "MEDIUM", "LOW"]
        tier_counts = host_risk_df["priority_tier"].value_counts().to_dict()
        tier_labels = {
            "CRITICAL": ("Critical Priority", "#ef4444"),
            "HIGH": ("High Priority", "#f97316"),
            "INFRASTRUCTURE_WATCH": ("Infrastructure Watch", "#3b82f6"),
            "MEDIUM": ("Medium Priority", "#eab308"),
            "LOW": ("Low Priority", "#10b981"),
        }
        for idx, t in enumerate(tiers):
            with p_cols[idx]:
                cnt = tier_counts.get(t, 0)
                name, clr = tier_labels[t]
                st.metric(name, f"{cnt} hosts")

    st.markdown("<h3 class='cyber-header'>Data Ingestion & Sanitization Audit</h3>", unsafe_allow_html=True)
    ac1, ac2 = st.columns([1, 1])
    with ac1:
        st.markdown("**Data Cleaning Telemetry:**")
        audit_data = {
            "Metric": ["Loaded Records", "Retained Records", "Dropped (Missing IP)", "Dropped (Invalid IP)", "Dropped (Missing Label)", "Unparseable Timestamps"],
            "Count": [
                cleaning_stats["loaded"],
                cleaning_stats["retained"],
                cleaning_stats["dropped_missing_ip"],
                cleaning_stats["dropped_invalid_ip"],
                cleaning_stats["dropped_missing_label"],
                cleaning_stats["dropped_unparseable_time"],
            ]
        }
        st.dataframe(pd.DataFrame(audit_data), use_container_width=True, hide_index=True)

    with ac2:
        st.markdown("**Traffic Composition in Active Slice:**")
        label_counts = clean_df["label_clean"].value_counts().reset_index()
        label_counts.columns = ["Traffic Class", "Flow Count"]
        fig_pie = px.pie(
            label_counts,
            values="Flow Count",
            names="Traffic Class",
            hole=0.4,
            color_discrete_sequence=["#10b981", "#ef4444", "#f97316", "#38bdf8"],
        )
        fig_pie.update_layout(
            margin=dict(t=10, b=10, l=10, r=10),
            paper_bgcolor="#0e1117",
            plot_bgcolor="#0e1117",
            font=dict(color="#cbd5e1"),
        )
        st.plotly_chart(fig_pie, use_container_width=True)


# ==========================================
# PAGE 2: NETWORK EXPLORER
# ==========================================
elif page == "Network Explorer":
    st.title("🕸️ Interactive Host Topology Explorer")
    st.markdown("Visualizes host-to-host communications as a directed graph. Nodes represent hosts; edges represent observed network flows.")

    # Controls
    col_c1, col_c2, col_c3, col_c4 = st.columns(4)
    with col_c1:
        color_choice = st.selectbox("Color Nodes By", ["priority_tier", "community_id"], index=0)
    with col_c2:
        size_choice = st.selectbox("Node Size By", ["degree", "pagerank"], index=0)
    with col_c3:
        max_vis_nodes = st.slider("Max Nodes in Visualization", 20, 200, 100, 10)
    with col_c4:
        layout_choice = st.selectbox("Graph Layout", ["spring", "circular"], index=0)

    # Subgraph extraction for performance
    builder = NetworkGraphBuilder()
    subG = builder.get_subgraph_for_visualization(G, max_nodes=max_vis_nodes)

    fig_net = create_plotly_network_figure(
        G=subG,
        color_by=color_choice,
        node_size_metric=size_choice,
        layout_type=layout_choice,
        host_risk_df=host_risk_df,
    )
    st.plotly_chart(fig_net, use_container_width=True)

    # Host Inspection
    st.markdown("<h3 class='cyber-header'>Host Detail Inspector</h3>", unsafe_allow_html=True)
    all_hosts = sorted(list(G.nodes()))
    selected_host = st.selectbox("Select Host IP to Inspect Neighborhood", options=all_hosts)

    if selected_host:
        h_data = G.nodes[selected_host]
        h_risk = host_risk_df[host_risk_df["host_id"] == selected_host].iloc[0] if not host_risk_df[host_risk_df["host_id"] == selected_host].empty else None

        hc1, hc2, hc3, hc4 = st.columns(4)
        hc1.metric("Host IP", selected_host, "Internal" if h_data.get("is_internal") else "External")
        hc2.metric("In-Degree / Out-Degree", f"{G.in_degree(selected_host)} in / {G.out_degree(selected_host)} out")
        hc3.metric("Attack Flows", f"{h_data.get('total_attack_flows', 0):,}")
        tier_val = h_risk["priority_tier"] if h_risk is not None else "N/A"
        hc4.metric("Priority Tier", tier_val)

        if h_risk is not None:
            st.info(f"**Evidence Summary:** {h_risk['investigation_evidence']}")

        # Show direct connections table
        preds = list(G.predecessors(selected_host))
        succs = list(G.successors(selected_host))
        neighbors_rows = []
        for p in preds:
            ed = G[p][selected_host]
            neighbors_rows.append({
                "Direction": "Incoming (From)",
                "Host IP": p,
                "Flow Volume": ed["weight"],
                "Attack Flows": ed["attack_flows"],
                "Attack Types": ed["attack_types"],
                "Protocols": ed["protocols"],
            })
        for s in succs:
            ed = G[selected_host][s]
            neighbors_rows.append({
                "Direction": "Outgoing (To)",
                "Host IP": s,
                "Flow Volume": ed["weight"],
                "Attack Flows": ed["attack_flows"],
                "Attack Types": ed["attack_types"],
                "Protocols": ed["protocols"],
            })

        if neighbors_rows:
            st.markdown(f"**Active Connections for {selected_host} ({len(neighbors_rows)} directed links):**")
            st.dataframe(pd.DataFrame(neighbors_rows), use_container_width=True)


# ==========================================
# PAGE 3: CRITICAL HOSTS
# ==========================================
elif page == "Critical Hosts":
    st.title("🎯 Critical Host Centrality & Ranking")
    st.markdown("""
    Ranks hosts based on graph centrality algorithms:
    - **In/Out Degree**: Direct communication volume and connection fan-out.
    - **Betweenness Centrality**: Bridges that connect distinct network subnets.
    - **PageRank**: Structural prestige and topological authority.
    - **Combined Criticality**: Normalized weighted synthesis of all three metrics.
    """)

    sort_col = st.selectbox(
        "Sort Hosts By",
        [
            "combined_criticality",
            "betweenness_centrality",
            "pagerank",
            "total_degree",
            "in_degree",
            "out_degree",
            "attack_flows_associated",
        ],
        index=0,
    )

    ranked_display = host_risk_df.sort_values(by=sort_col, ascending=False).copy()

    display_cols = [
        "host_id",
        "priority_tier",
        "combined_criticality",
        "degree_centrality",
        "betweenness_centrality",
        "pagerank",
        "total_degree",
        "in_degree",
        "out_degree",
        "attack_flows_associated",
        "observed_attack_types",
        "explanation",
    ]
    st.dataframe(
        ranked_display[display_cols].head(100),
        use_container_width=True,
        hide_index=True,
    )

    # Host Explanation Callout
    st.markdown("<h3 class='cyber-header'>Selected Host Analytical Explanation</h3>", unsafe_allow_html=True)
    top_host_options = list(ranked_display["host_id"].head(20))
    selected_explanation_host = st.selectbox("Select Host to View Algorithmic Rationale", top_host_options)
    if selected_explanation_host:
        h_row = ranked_display[ranked_display["host_id"] == selected_explanation_host].iloc[0]
        st.write(f"**Host:** `{selected_explanation_host}` | **Priority Tier:** `{h_row['priority_tier']}`")
        st.success(f"**Topological Explanation:** {h_row['explanation']}")
        st.info(f"**Investigation Evidence:** {h_row['investigation_evidence']}")

    # Export
    csv_bytes = ranked_display.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="📥 Download Critical Hosts CSV",
        data=csv_bytes,
        file_name="critical_hosts_analysis.csv",
        mime="text/csv",
    )


# ==========================================
# PAGE 4: COMMUNITY ANALYSIS
# ==========================================
elif page == "Community Analysis":
    st.title("👥 Network Community Structure & Risk")
    st.markdown("""
    Applies the **Louvain modularity optimization algorithm** to partition the network into densely connected structural communities.
    
    > **Methodological Note:** Louvain detects mathematical structural clusters. A dense community is not inherently malicious;
    departments, server clusters, and normal business applications naturally cluster. Suspicion is evaluated by correlating
    structural density with empirical attack flow counts.
    """)

    cm1, cm2, cm3 = st.columns(3)
    with cm1:
        render_metric_card("Detected Communities", f"{len(comm_risk_df)}", f"Modularity Q: {res['modularity']:.4f}")
    with cm2:
        mal_count = sum(comm_risk_df["community_threat_category"] == "MALICIOUS_CLUSTER")
        render_metric_card("Attack-Enriched Communities", f"{mal_count}", "Flows contain confirmed attacks")
    with cm3:
        avg_density = comm_risk_df["density"].mean() if not comm_risk_df.empty else 0
        render_metric_card("Average Community Density", f"{avg_density:.4f}", "Internal cohesion")

    # Community Overview Table
    st.markdown("<h3 class='cyber-header'>Community Risk & Structural Metrics</h3>", unsafe_allow_html=True)
    display_comm_cols = [
        "community_id",
        "community_threat_category",
        "size",
        "density",
        "internal_edges",
        "external_edges",
        "attack_flows_observed",
        "attack_flow_proportion",
        "observed_attack_types",
        "top_hosts",
    ]
    st.dataframe(comm_risk_df[display_comm_cols], use_container_width=True, hide_index=True)

    # Size vs Attack Proportion Chart
    fig_comm = px.bar(
        comm_risk_df,
        x="community_id",
        y="size",
        color="attack_flow_proportion",
        color_continuous_scale="Reds",
        title="Community Size vs Observed Attack Proportion",
        labels={"community_id": "Community ID", "size": "Member Host Count", "attack_flow_proportion": "Attack Flow %"},
    )
    fig_comm.update_layout(
        paper_bgcolor="#0e1117",
        plot_bgcolor="#0e1117",
        font=dict(color="#cbd5e1"),
    )
    st.plotly_chart(fig_comm, use_container_width=True)

    # Inspect Members of Selected Community
    st.markdown("<h3 class='cyber-header'>Inspect Specific Community Members</h3>", unsafe_allow_html=True)
    sel_cid = st.selectbox("Select Community ID", options=comm_risk_df["community_id"].tolist())
    if sel_cid is not None:
        mem_hosts = host_risk_df[host_risk_df["community_id"] == sel_cid]
        st.write(f"Showing {len(mem_hosts)} hosts belonging to **Community {sel_cid}**:")
        st.dataframe(
            mem_hosts[["host_id", "priority_tier", "total_degree", "total_flows", "attack_flows_associated", "observed_attack_types", "explanation"]],
            use_container_width=True,
            hide_index=True,
        )


# ==========================================
# PAGE 5: TIMELINE
# ==========================================
elif page == "Timeline":
    st.title("⏱️ Temporal Traffic & Attack Analysis")
    st.markdown("Examines the progression of network communications and attack occurrences over time.")

    time_df = clean_df.dropna(subset=["timestamp_parsed"]).copy()
    if time_df.empty:
        st.warning("No parseable timestamps available in this slice for temporal charting.")
    else:
        # Resample to 1-minute intervals
        time_df["time_bin"] = time_df["timestamp_parsed"].dt.floor("1min")

        ts_grouped = time_df.groupby(["time_bin", "is_attack"]).size().reset_index(name="count")
        ts_grouped["Traffic"] = ts_grouped["is_attack"].map({True: "Attack Flow", False: "Benign Flow"})

        fig_ts = px.bar(
            ts_grouped,
            x="time_bin",
            y="count",
            color="Traffic",
            color_discrete_map={"Attack Flow": "#ef4444", "Benign Flow": "#10b981"},
            title="Network Flow Activity Over Time (1-Minute Intervals)",
            labels={"time_bin": "Timestamp", "count": "Flow Volume"},
        )
        fig_ts.update_layout(
            paper_bgcolor="#0e1117",
            plot_bgcolor="#0e1117",
            font=dict(color="#cbd5e1"),
            legend=dict(orientation="h", y=1.1, x=1),
        )
        st.plotly_chart(fig_ts, use_container_width=True)

        # Attack Timeline by Category
        if time_df["is_attack"].any():
            att_time = time_df[time_df["is_attack"] == True].groupby(["time_bin", "attack_category"]).size().reset_index(name="count")
            fig_att = px.line(
                att_time,
                x="time_bin",
                y="count",
                color="attack_category",
                title="Attack Intensity by Attack Type Over Time",
            )
            fig_att.update_layout(
                paper_bgcolor="#0e1117",
                plot_bgcolor="#0e1117",
                font=dict(color="#cbd5e1"),
            )
            st.plotly_chart(fig_att, use_container_width=True)


# ==========================================
# PAGE 6: EVALUATION & BENCHMARKS
# ==========================================
elif page == "Evaluation & Benchmarks":
    st.title("📊 Empirical Evaluation & Academic Validation")
    st.markdown(r"""
    ### Benchmark Methodology
    We evaluate the structural predictive utility of SNA centrality algorithms against the observational
    ground-truth flow labels from the CIC-IDS2017 dataset.
    
    > **Methodological Disclosure & Limitations:**
    > 1. A host is marked as attack-involved ($y=1$) if observed in $\ge 1$ attack flow. This is an
    >    observational traffic proxy, not direct forensic verification of host compromise.
    > 2. Pure graph centrality algorithms (Degree, Betweenness, PageRank) are **completely unsupervised**
    >    and do not ingest attack labels during ranking, ensuring a leakage-free benchmark.
    """)

    # Display Precision@K Table
    p_dict = eval_res.get("precision_at_k", {})
    if p_dict:
        st.markdown("<h3 class='cyber-header'>Precision@K Comparison Across Centrality Measures</h3>", unsafe_allow_html=True)
        p_df = pd.DataFrame(p_dict).T
        st.dataframe(p_df, use_container_width=True)

        base_rate = eval_res.get("attack_host_base_rate", 0.0)
        st.caption(f"Uninformed Random Baseline Base Rate: {base_rate:.2%}")

    # Embed Generated Figures
    st.markdown("<h3 class='cyber-header'>Publication-Ready Research Figures</h3>", unsafe_allow_html=True)
    f1, f2 = st.columns(2)
    fig1_path = os.path.join("results", "figures", "precision_at_k_comparison.png")
    fig2_path = os.path.join("results", "figures", "community_attack_enrichment.png")

    with f1:
        if os.path.exists(fig1_path):
            st.image(fig1_path, caption="Figure 1: Precision@K Comparison Across Centrality Algorithms")
        else:
            st.info("Precision@K plot not yet generated.")
    with f2:
        if os.path.exists(fig2_path):
            st.image(fig2_path, caption="Figure 2: Community Size vs Attack Flow Concentration")
        else:
            st.info("Community enrichment plot not yet generated.")


# ==========================================
# PAGE 7: EXPORTS & METHODOLOGY
# ==========================================
elif page == "Exports & Methodology":
    st.title("📑 Artifact Exports & System Methodology")
    st.markdown("""
    Export genuine analytical result files generated by this session. Every exported metric is produced
    directly by the underlying graph analytics pipeline.
    """)

    # Download Buttons
    dc1, dc2, dc3 = st.columns(3)
    with dc1:
        st.markdown("**Critical Hosts Analysis:**")
        csv_hosts = host_risk_df.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Download Critical Hosts CSV", data=csv_hosts, file_name="critical_hosts.csv", mime="text/csv")
    with dc2:
        st.markdown("**Community Summaries:**")
        csv_comm = comm_risk_df.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Download Communities CSV", data=csv_comm, file_name="communities.csv", mime="text/csv")
    with dc3:
        st.markdown("**Suspicious Host Risk:**")
        csv_risk = host_risk_df.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Download Suspicious Hosts CSV", data=csv_risk, file_name="suspicious_hosts.csv", mime="text/csv")

    st.markdown("---")
    st.markdown("<h3 class='cyber-header'>Academic Defense Reference for B.Tech Review</h3>", unsafe_allow_html=True)
    with st.expander("🎓 1. What does a Node and an Edge represent?", expanded=True):
        st.markdown(r"""
        - **Node ($v \in V$):** A unique computing host, identified by its IPv4 address (e.g. `192.168.10.50`).
        - **Directed Edge ($(u, v) \in E$):** Host $u$ transmitted one or more network communication flows to host $v$.
        - **Edge Weight ($w_{uv}$):** The total number of observed network flows directed from $u$ to $v$.
        """)

    with st.expander("🎓 2. Why use Louvain instead of k-Means for Communities?"):
        st.markdown("""
        Network communication is relational (graph topology), not a vector in Euclidean space. Louvain optimizes
        **Newman-Girvan Modularity ($Q$)**, which compares the density of internal links in a cluster against the
        expected density in an equivalent null model with randomized links. It automatically determines the optimal
        number of communities without requiring a predetermined $k$.
        """)

    with st.expander("🎓 3. Why Betweenness Centrality is Critical for Cybersecurity"):
        st.markdown("""
        Betweenness centrality measures the frequency with which a host falls on the shortest path between all pairs
        of nodes. In enterprise topologies, hosts with high betweenness represent **chokepoints, routers, active gateways,
        or internal pivots**. If compromised or targeted, they have the highest potential for lateral movement and interception.
        """)

    with st.expander("🎓 4. Why Centrality Alone Does NOT Equal Maliciousness"):
        st.markdown("""
        A DNS server, Active Directory domain controller, or default gateway naturally possesses high degree and
        betweenness centrality. Flagging high-centrality nodes as malicious would generate massive false positives.
        Our system explicitly categorizes high-centrality benign hosts as **`INFRASTRUCTURE_WATCH`** (critical assets to protect),
        and reserves **`CRITICAL`** only for the intersection of structural centrality and confirmed attack flows.
        """)
