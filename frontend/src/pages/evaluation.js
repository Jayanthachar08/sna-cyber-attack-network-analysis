/**
 * Model & Evaluation Page Component
 * Academic, leakage-free benchmark evaluation of SNA centrality algorithms
 * against observational proxy ground-truth labels.
 */

import { api } from '../api.js';

export async function renderEvaluationPage(container) {
  container.innerHTML = `
    <div class="loading-container">
      <div class="spinner"></div>
      <div>Loading academic evaluation metrics and research figures...</div>
    </div>
  `;

  try {
    const data = await api.getEvaluation();

    const pDict = data.precision_at_k || {};
    const baseRate = (data.attack_host_base_rate * 100).toFixed(2);

    // Build Precision@K Table rows
    const metricKeys = Object.keys(pDict);
    const kCols = metricKeys.length > 0 ? Object.keys(pDict[metricKeys[0]]) : [];

    container.innerHTML = `
      <!-- Academic Context Card -->
      <div class="heroui-card">
        <div class="card-header">
          <div class="card-title">📊 Empirical Evaluation & Academic Validation</div>
          <div class="card-subtitle">Benchmarking unsupervised graph algorithms against observational flow labels</div>
        </div>
        <div class="card-body">
          <div class="callout callout-info" style="margin-bottom: 16px;">
            <b>Rigorous Leakage-Free Benchmark Methodology:</b><br/>
            1. Pure graph centrality measures (Degree, Betweenness, PageRank) are <b>strictly unsupervised</b>. They evaluate only the communication graph topology and never ingest attack labels during ranking.<br/>
            2. Observational Ground-Truth Proxy: A host is labeled attack-involved ($y=1$) if observed as source or destination in $\\ge 1$ attack flow.<br/>
            3. Precision@K evaluates what fraction of the top-K topologically ranked hosts intersect with observed attack telemetry.
          </div>

          <div style="margin-bottom: 24px;">
            <div style="font-weight: 700; font-size: 14px; margin-bottom: 10px;">
              Precision@K Comparison Across Centrality Measures
            </div>
            <div class="table-container">
              <table class="heroui-table">
                <thead>
                  <tr>
                    <th>Centrality Algorithm</th>
                    ${kCols.map((k) => `<th>${k}</th>`).join('')}
                    <th>Algorithmic Interpretation</th>
                  </tr>
                </thead>
                <tbody>
                  ${metricKeys
                    .map((m) => {
                      const interpretations = {
                        degree_centrality: 'Quantifies direct fan-in / fan-out connection volume.',
                        betweenness_centrality: 'Identifies network chokepoints and lateral bridges.',
                        pagerank: 'Calculates global structural prestige and authority.',
                        combined_criticality: 'Normalized weighted synthesis of all three dimensions.',
                      };
                      return `
                      <tr>
                        <td><b>${m.replace(/_/g, ' ').toUpperCase()}</b></td>
                        ${kCols
                          .map((k) => {
                            const val = (pDict[m][k] * 100).toFixed(1);
                            return `<td><b>${val}%</b></td>`;
                          })
                          .join('')}
                        <td style="font-size:12px; color:var(--text-secondary);">${interpretations[m] || ''}</td>
                      </tr>
                    `;
                    })
                    .join('')}
                </tbody>
              </table>
            </div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:8px;">
              Uninformed Random Baseline Base Rate: <b>${baseRate}%</b> (Prior precision of randomly guessing an attack host).
            </div>
          </div>
        </div>
      </div>

      <!-- Publication-Ready Figures -->
      <div class="heroui-card">
        <div class="card-header">
          <div class="card-title">📈 Publication-Ready Research Figures</div>
          <div class="card-subtitle">Generated automatically by evaluation.py during pipeline execution</div>
        </div>
        <div class="card-body">
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 20px;">
            <div style="border:1px solid var(--border-subtle); border-radius:var(--radius-md); padding:16px; background:var(--bg-canvas);">
              <div style="font-weight:600; font-size:13px; margin-bottom:8px;">
                Figure 1: Precision@K Comparison Across Centrality Algorithms
              </div>
              <img
                src="/api/figures/precision_at_k"
                alt="Precision@K Comparison"
                style="width:100%; border-radius:var(--radius-sm); border:1px solid var(--border-subtle);"
                onerror="this.onerror=null; this.parentElement.innerHTML='<div class=\\'callout\\'>Figure not yet generated. Run analysis with test slices to generate figure.</div>';"
              />
              <div style="font-size:11.5px; color:var(--text-muted); margin-top:8px;">
                Evaluates top-5, top-10, and top-20 host rankings against attack-involved ground-truth proxy.
              </div>
            </div>

            <div style="border:1px solid var(--border-subtle); border-radius:var(--radius-md); padding:16px; background:var(--bg-canvas);">
              <div style="font-weight:600; font-size:13px; margin-bottom:8px;">
                Figure 2: Community Size vs Attack Flow Concentration
              </div>
              <img
                src="/api/figures/community_enrichment"
                alt="Community Attack Enrichment"
                style="width:100%; border-radius:var(--radius-sm); border:1px solid var(--border-subtle);"
                onerror="this.onerror=null; this.parentElement.innerHTML='<div class=\\'callout\\'>Figure not yet generated. Run analysis with test slices to generate figure.</div>';"
              />
              <div style="font-size:11.5px; color:var(--text-muted); margin-top:8px;">
                Demonstrates how attacks heavily enrich specific structural communities rather than dispersing evenly.
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Key Academic Disclosures & Viva Voce Points -->
      <div class="heroui-card">
        <div class="card-header">
          <div class="card-title">🎓 Academic Defense Disclosures & Discussion Points</div>
        </div>
        <div class="card-body" style="display: flex; flex-direction: column; gap: 12px;">
          <div class="callout callout-warning">
            <b>1. Centrality Alone Does NOT Equal Maliciousness:</b><br/>
            In a campus or enterprise network, a DNS resolver, active gateway router, or LDAP server will naturally have the highest degree and betweenness centrality. Flagging high centrality as inherently "malicious" is an error. Our framework explicitly categorizes high-centrality benign hosts as <code>INFRASTRUCTURE_WATCH</code> (vital assets that require defense), strictly separating them from attack actors.
          </div>
          <div class="callout callout-info">
            <b>2. Scalability & Approximation Bounds:</b><br/>
            Exact betweenness centrality requires Brandes algorithm with $O(V \\cdot E)$ complexity. On large graphs ($>500$ nodes), our implementation utilizes Brandes randomized $k$-node sampling ($k = 0.2N$) to guarantee bounded sub-second latency ($O(k \\cdot (V + E))$) while preserving relative ranking accuracy.
          </div>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="callout callout-critical">Failed to load evaluation: ${err.message}</div>`;
  }
}
