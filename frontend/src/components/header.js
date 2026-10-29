/**
 * Header Component with Active Page Info and Analysis Trigger Modal
 */
import { store } from '../state.js';
import { api } from '../api.js';

export function renderHeader(container) {
  const current = store.get('currentPage');
  const datasetStatus = store.get('datasetStatus');
  const isAnalyzing = store.get('isAnalyzing');

  const titles = {
    overview: 'Network Overview',
    'network-explorer': 'Network Topology Explorer',
    'critical-hosts': 'Critical Host Rankings',
    communities: 'Community Structure & Modularity',
    timeline: 'Temporal Flow Activity',
    evaluation: 'Benchmark & Model Evaluation',
    reports: 'Forensic Exports & Methodology',
  };

  const activePath = datasetStatus?.active_file || 'No dataset loaded';
  const displayFile = activePath.split(/[\\/]/).pop();

  container.innerHTML = `
    <div class="header-left">
      <button class="mobile-menu-btn" id="mobile-toggle-btn" aria-label="Toggle Navigation">☰</button>
      <div>
        <div class="page-heading">${titles[current] || 'Investigation'}</div>
      </div>
    </div>

    <div class="header-right">
      <div class="active-file-pill" title="${activePath}">
        📄 ${displayFile}
      </div>
      <button class="btn btn-primary btn-sm" id="open-config-btn" ${isAnalyzing ? 'disabled' : ''}>
        ${isAnalyzing ? '<div class="spinner" style="width:14px;height:14px;border-width:2px;"></div> Analyzing...' : '⚙️ Run / Config'}
      </button>
    </div>
  `;

  // Attach mobile toggle
  const toggleBtn = container.querySelector('#mobile-toggle-btn');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      document.querySelector('.sidebar')?.classList.toggle('mobile-open');
    });
  }

  // Attach Config modal
  const configBtn = container.querySelector('#open-config-btn');
  if (configBtn) {
    configBtn.addEventListener('click', () => {
      showAnalysisConfigModal();
    });
  }
}

export function showAnalysisConfigModal() {
  const modalId = 'analysis-config-modal';
  let modal = document.getElementById(modalId);
  if (!modal) {
    modal = document.createElement('div');
    modal.id = modalId;
    modal.className = 'drawer-backdrop';
    document.body.appendChild(modal);
  }

  const datasetStatus = store.get('datasetStatus');
  const files = datasetStatus?.available_files || [];
  const currentParams = datasetStatus?.parameters || {};
  const activeFile = datasetStatus?.active_file || '';

  modal.style.display = 'flex';
  modal.style.alignItems = 'center';
  modal.style.justifyContent = 'center';

  modal.innerHTML = `
    <div class="heroui-card" style="width: 520px; max-width: 95vw; max-height: 90vh; overflow-y: auto;">
      <div class="card-header">
        <div class="card-title">⚙️ Configure & Run Analysis</div>
        <button class="close-btn" id="close-modal-btn">✕</button>
      </div>
      <div class="card-body" style="display:flex; flex-direction:column; gap:14px;">
        <div class="form-group">
          <label class="form-label">Dataset File</label>
          <select class="select-control" id="cfg-file-select">
            ${files.map(
              (f) => `
              <option value="${f.path}" ${f.path === activeFile ? 'selected' : ''}>
                ${f.filename} (${f.size_mb} MB)
              </option>
            `
            ).join('')}
          </select>
        </div>

        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px;">
          <div class="form-group">
            <label class="form-label">Flow Sample Limit</label>
            <select class="select-control" id="cfg-sample-size">
              <option value="5000">5,000 flows (Fast)</option>
              <option value="15000" selected>15,000 flows (Recommended)</option>
              <option value="25000">25,000 flows (Detailed)</option>
              <option value="50000">50,000 flows (Deep)</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Skiprows / Offset</label>
            <input type="number" class="input-control" id="cfg-offset" value="${
              activeFile.includes('Friday-WorkingHours-Afternoon-DDos') ? '95000' : '0'
            }" step="5000" />
            <small style="font-size:10px; color:var(--text-muted);">95,000 captures DDoS onset</small>
          </div>
        </div>

        <div style="background-color: var(--bg-subtle); padding: 12px; border-radius: var(--radius-sm);">
          <div style="font-weight:600; font-size:12px; margin-bottom:8px;">Centrality Criticality Weights</div>
          <div style="display:grid; grid-template-columns: 1fr 1fr 1fr; gap:8px;">
            <div class="form-group">
              <label class="form-label">Degree</label>
              <input type="number" step="0.05" class="input-control" id="cfg-w-deg" value="0.35" min="0" max="1" />
            </div>
            <div class="form-group">
              <label class="form-label">Betweenness</label>
              <input type="number" step="0.05" class="input-control" id="cfg-w-bet" value="0.35" min="0" max="1" />
            </div>
            <div class="form-group">
              <label class="form-label">PageRank</label>
              <input type="number" step="0.05" class="input-control" id="cfg-w-pr" value="0.30" min="0" max="1" />
            </div>
          </div>
        </div>

        <div id="modal-msg" style="display:none; font-size:12px; padding:8px 12px; border-radius:4px;"></div>
      </div>
      <div class="card-footer" style="display:flex; justify-content:flex-end; gap:8px;">
        <button class="btn btn-secondary" id="cancel-modal-btn">Cancel</button>
        <button class="btn btn-primary" id="execute-run-btn">🚀 Execute Analysis</button>
      </div>
    </div>
  `;

  // Auto-fill offset if user changes file selection to Friday DDoS
  const fileSelect = modal.querySelector('#cfg-file-select');
  const offsetInput = modal.querySelector('#cfg-offset');
  fileSelect?.addEventListener('change', () => {
    if (fileSelect.value.includes('Friday-WorkingHours-Afternoon-DDos')) {
      offsetInput.value = '95000';
    } else {
      offsetInput.value = '0';
    }
  });

  const closeModal = () => {
    modal.style.display = 'none';
  };

  modal.querySelector('#close-modal-btn')?.addEventListener('click', closeModal);
  modal.querySelector('#cancel-modal-btn')?.addEventListener('click', closeModal);

  modal.querySelector('#execute-run-btn')?.addEventListener('click', async () => {
    const msgEl = modal.querySelector('#modal-msg');
    const runBtn = modal.querySelector('#execute-run-btn');

    const params = {
      file_path: fileSelect.value,
      max_rows: parseInt(modal.querySelector('#cfg-sample-size').value, 10),
      skip_rows: parseInt(offsetInput.value, 10) || 0,
      w_deg: parseFloat(modal.querySelector('#cfg-w-deg').value) || 0.35,
      w_bet: parseFloat(modal.querySelector('#cfg-w-bet').value) || 0.35,
      w_pr: parseFloat(modal.querySelector('#cfg-w-pr').value) || 0.30,
      louvain_res: 1.0,
    };

    runBtn.disabled = true;
    runBtn.innerHTML = '<div class="spinner" style="width:14px;height:14px;border-width:2px;"></div> Computing Graph...';
    msgEl.style.display = 'block';
    msgEl.style.backgroundColor = 'var(--primary-subtle)';
    msgEl.style.color = 'var(--primary)';
    msgEl.textContent = 'Preprocessing flows, computing centralities, and partitioning communities...';

    store.set('isAnalyzing', true);

    try {
      const res = await api.runAnalysis(params);
      msgEl.style.backgroundColor = 'var(--low-subtle)';
      msgEl.style.color = 'var(--low-text)';
      msgEl.textContent = `Completed in ${res.duration_seconds}s! (${res.num_nodes} nodes, ${res.num_edges} edges, ${res.num_communities} communities)`;

      setTimeout(async () => {
        closeModal();
        store.set('isAnalyzing', false);
        // Refresh status and re-render current page
        const newStatus = await api.getDatasetStatus();
        store.set('datasetStatus', newStatus);
        // Trigger page re-render
        store.set('currentPage', store.get('currentPage'));
      }, 800);
    } catch (err) {
      msgEl.style.backgroundColor = 'var(--critical-subtle)';
      msgEl.style.color = 'var(--critical-text)';
      msgEl.textContent = `Analysis failed: ${err.message}`;
      runBtn.disabled = false;
      runBtn.textContent = '🚀 Execute Analysis';
      store.set('isAnalyzing', false);
    }
  });
}
