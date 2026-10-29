/**
 * Reports & Forensic Exports Page Component
 * Direct CSV download controls for all generated pipeline artifacts
 * and interactive B.Tech viva defense reference guide.
 */

import { api } from '../api.js';
import { store } from '../state.js';

export async function renderReportsPage(container) {
  const datasetStatus = store.get('datasetStatus');
  const activeFile = datasetStatus?.active_file || 'No dataset loaded';
  const lastRunTime = datasetStatus?.last_run_timestamp
    ? new Date(datasetStatus.last_run_timestamp).toLocaleString()
    : 'Not yet run';
  const params = datasetStatus?.parameters || {};

  container.innerHTML = `
    <!-- Forensic Export Cards -->
    <div class="heroui-card">
      <div class="card-header">
        <div class="card-title">📑 Forensic Result Exports & Artifacts</div>
        <div class="card-subtitle">Download genuine analytical data computed during this session</div>
      </div>
      <div class="card-body">
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px;">
          <div class="metric-card" style="border:1px solid var(--border-subtle);">
            <div style="font-weight: 700; font-size: 14px; margin-bottom: 4px;">🎯 Critical Hosts CSV</div>
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
              Full table of ranked hosts, in/out degrees, betweenness, PageRank, combined score, and topological explanations.
            </div>
            <a href="${api.getExportUrl('critical-hosts')}" class="btn btn-primary btn-sm" download="critical_hosts.csv" style="text-decoration:none; width:100%;">
              📥 Download critical_hosts.csv
            </a>
          </div>

          <div class="metric-card" style="border:1px solid var(--border-subtle);">
            <div style="font-weight: 700; font-size: 14px; margin-bottom: 4px;">👥 Community Summaries CSV</div>
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
              Detected Louvain clusters, member counts, internal/external link densities, and observed attack flow ratios.
            </div>
            <a href="${api.getExportUrl('communities')}" class="btn btn-secondary btn-sm" download="communities.csv" style="text-decoration:none; width:100%;">
              📥 Download communities.csv
            </a>
          </div>

          <div class="metric-card" style="border:1px solid var(--border-subtle);">
            <div style="font-weight: 700; font-size: 14px; margin-bottom: 4px;">🚨 Suspicious Hosts Triage CSV</div>
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
              Evidence-aware triage list with priority tiers (CRITICAL, HIGH, INFRASTRUCTURE_WATCH) and audit explanations.
            </div>
            <a href="${api.getExportUrl('suspicious-hosts')}" class="btn btn-secondary btn-sm" download="suspicious_hosts.csv" style="text-decoration:none; width:100%;">
              📥 Download suspicious_hosts.csv
            </a>
          </div>

          <div class="metric-card" style="border:1px solid var(--border-subtle);">
            <div style="font-weight: 700; font-size: 14px; margin-bottom: 4px;">🗺️ Host-Community Mapping CSV</div>
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
              Exact lookup mapping each unique host IP address to its corresponding Louvain partition community ID.
            </div>
            <a href="${api.getExportUrl('host-community-membership')}" class="btn btn-secondary btn-sm" download="host_community_membership.csv" style="text-decoration:none; width:100%;">
              📥 Download host_community_membership.csv
            </a>
          </div>

          <div class="metric-card" style="border:1px solid var(--border-subtle);">
            <div style="font-weight: 700; font-size: 14px; margin-bottom: 4px;">🛡️ Community Risk Triage CSV</div>
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
              Aggregated community threat tiering (MALICIOUS_CLUSTER, MIXED_SUSPICIOUS, BENIGN_INTERNAL).
            </div>
            <a href="${api.getExportUrl('community-risk')}" class="btn btn-secondary btn-sm" download="community_risk.csv" style="text-decoration:none; width:100%;">
              📥 Download community_risk.csv
            </a>
          </div>
        </div>
      </div>
      <div class="card-footer" style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px;">
        <span>Active Source File: <code>${activeFile}</code></span>
        <span>Last Computed: <b>${lastRunTime}</b></span>
      </div>
    </div>

    <!-- Academic Defense Reference Guide -->
    <div class="heroui-card">
      <div class="card-header">
        <div class="card-title">🎓 Academic Defense & Viva Voce Reference</div>
        <div class="card-subtitle">Foundational theory and methodology explanations for faculty review</div>
      </div>
      <div class="card-body" style="display: flex; flex-direction: column; gap: 12px;">
        <details style="background:var(--bg-subtle); padding:12px 16px; border-radius:var(--radius-sm); border:1px solid var(--border-subtle);" open>
          <summary style="font-weight:600; cursor:pointer; color:var(--text-primary);">
            1. What does a Node, Edge, and Edge Weight represent in this system?
          </summary>
          <div style="margin-top:8px; font-size:13px; line-height:1.6; color:var(--text-secondary);">
            • <b>Node (v ∈ V):</b> A unique computing host, identified by its IPv4 address (e.g. <code>192.168.10.50</code>). The system automatically parses IP octets to categorize nodes as <i>Internal</i> (RFC 1918 private subnets: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) or <i>External</i> (Internet WAN endpoints).<br/>
            • <b>Directed Edge ((u, v) ∈ E):</b> A directed communication link where host <i>u</i> (Source IP) transmitted one or more network flows to host <i>v</i> (Destination IP).<br/>
            • <b>Edge Weight (w<sub>uv</sub>):</b> The total aggregated volume of network communication flows directed from <i>u</i> to <i>v</i>.
          </div>
        </details>

        <details style="background:var(--bg-subtle); padding:12px 16px; border-radius:var(--radius-sm); border:1px solid var(--border-subtle);">
          <summary style="font-weight:600; cursor:pointer; color:var(--text-primary);">
            2. Why use Louvain Modularity Optimization instead of k-Means for Communities?
          </summary>
          <div style="margin-top:8px; font-size:13px; line-height:1.6; color:var(--text-secondary);">
            Network traffic is topological and relational (graph edges), not a set of independent vectors in Euclidean metric space. Traditional k-Means requires defining an arbitrary cluster count <i>k</i> and computing Euclidean centroids. In contrast, <b>Louvain</b> optimizes the Newman-Girvan Modularity index (<i>Q</i>), comparing the density of internal links against a randomized null model. It automatically determines the optimal number of organic communication clusters without subjective pre-tuning.
          </div>
        </details>

        <details style="background:var(--bg-subtle); padding:12px 16px; border-radius:var(--radius-sm); border:1px solid var(--border-subtle);">
          <summary style="font-weight:600; cursor:pointer; color:var(--text-primary);">
            3. Why is Betweenness Centrality critical in Cyber Attack Investigation?
          </summary>
          <div style="margin-top:8px; font-size:13px; line-height:1.6; color:var(--text-secondary);">
            Betweenness centrality quantifies the frequency with which a host falls on the shortest path between all pairs of nodes in the network. In an enterprise topology, hosts with high betweenness represent <b>lateral pivot points, internal routing gateways, or compromised proxy bridges</b>. If an adversary compromises a high-betweenness host, they gain the capability to intercept communications or traverse subnets effortlessly.
          </div>
        </details>

        <details style="background:var(--bg-subtle); padding:12px 16px; border-radius:var(--radius-sm); border:1px solid var(--border-subtle);">
          <summary style="font-weight:600; cursor:pointer; color:var(--text-primary);">
            4. Why does Centrality Alone NOT Equal Maliciousness?
          </summary>
          <div style="margin-top:8px; font-size:13px; line-height:1.6; color:var(--text-secondary);">
            A core DNS resolver, Active Directory domain controller, or default gateway naturally maintains high degree and betweenness centrality. Treating high centrality as evidence of maliciousness causes severe false positives. Our system strictly categorizes high-centrality benign hosts as <code>INFRASTRUCTURE_WATCH</code> (vital assets requiring hardened defense) and reserves <code>CRITICAL</code> only for hosts where structural importance directly intersects with empirical attack telemetry.
          </div>
        </details>

        <details style="background:var(--bg-subtle); padding:12px 16px; border-radius:var(--radius-sm); border:1px solid var(--border-subtle);">
          <summary style="font-weight:600; cursor:pointer; color:var(--text-primary);">
            5. What is the difference between TrafficLabelling and MachineLearningCVE?
          </summary>
          <div style="margin-top:8px; font-size:13px; line-height:1.6; color:var(--text-secondary);">
            In the official CIC-IDS2017 distribution, <code>TrafficLabelling</code> preserves real IP addresses (Source IP, Destination IP), port numbers, timestamps, and attack ground-truth labels—essential for graph construction. Conversely, <code>MachineLearningCVE</code> anonymized and stripped IP addresses and timestamps so machine learning classifiers would not overfit to specific IP strings. Social Network Analysis requires IP addresses to construct graph nodes and edges.
          </div>
        </details>
      </div>
    </div>
  `;
}
