/**
 * Timeline Page Component
 * Examines network flow progression over time and attack intensity peaks.
 */

import { api } from '../api.js';
import Plotly from 'plotly.js-dist-min';

export async function renderTimelinePage(container) {
  container.innerHTML = `
    <div class="loading-container">
      <div class="spinner"></div>
      <div>Loading temporal telemetry...</div>
    </div>
  `;

  try {
    const data = await api.getTimeline();

    if (!data.available || data.points.length === 0) {
      container.innerHTML = `
        <div class="heroui-card">
          <div class="card-header">
            <div class="card-title">⏱️ Temporal Flow Activity</div>
          </div>
          <div class="card-body">
            <div class="callout callout-warning">
              <b>Honest Scientific Disclosure:</b><br/>
              ${data.message || 'No parseable timestamps were detected in the currently active dataset slice.'}
              <br/><br/>
              The CIC-IDS2017 <code>TrafficLabelling</code> files typically contain explicit ISO timestamps. If you loaded an anonymized ML slice, timestamps may have been stripped by the authors to prevent temporal leakage.
              Please click <b>"Configure & Run Analysis"</b> in the top-right header and select a file from <code>Datasets/TrafficLabelling/</code> to view the temporal attack sequence.
            </div>
          </div>
        </div>
      `;
      return;
    }

    container.innerHTML = `
      <div class="heroui-card">
        <div class="card-header">
          <div class="card-title">⏱️ Network Flow Progression Over Time (1-Minute Intervals)</div>
          <div class="card-subtitle">${data.total_time_bins} chronological time bins analyzed</div>
        </div>
        <div class="card-body">
          <div id="timeline-flow-chart" style="width: 100%; height: 350px;"></div>
        </div>
      </div>

      <div class="heroui-card">
        <div class="card-header">
          <div class="card-title">🚨 Attack Flow Intensity by Category</div>
          <div class="card-subtitle">Identifies attack onset and peak concentration periods</div>
        </div>
        <div class="card-body">
          <div id="timeline-attack-chart" style="width: 100%; height: 320px;"></div>
        </div>
      </div>
    `;

    // Process data for Plotly
    const timeBins = data.points.map((p) => p.time_bin);
    const benignCounts = data.points.map((p) => p.benign_count);
    const attackCounts = data.points.map((p) => p.attack_count);

    // Chart 1: Benign vs Attack Stacked / Grouped Bar
    Plotly.newPlot(
      'timeline-flow-chart',
      [
        {
          x: timeBins,
          y: benignCounts,
          name: 'Benign Flow Volume',
          type: 'bar',
          marker: { color: '#10b981' },
        },
        {
          x: timeBins,
          y: attackCounts,
          name: 'Attack-Labeled Flow Volume',
          type: 'bar',
          marker: { color: '#ef4444' },
        },
      ],
      {
        barmode: 'stack',
        margin: { t: 20, b: 60, l: 50, r: 20 },
        paper_bgcolor: 'transparent',
        plot_bgcolor: 'transparent',
        font: { family: 'inherit', color: '#334155', size: 12 },
        xaxis: { title: 'Timestamp' },
        yaxis: { title: 'Flow Volume' },
        legend: { orientation: 'h', y: 1.15, x: 0.5, xanchor: 'center' },
      },
      { responsive: true, displayModeBar: false }
    );

    // Chart 2: Attack Categories breakdown
    // Collect all unique attack category names
    const catSet = new Set();
    data.points.forEach((p) => {
      Object.keys(p.attack_categories || {}).forEach((k) => catSet.add(k));
    });

    const catTraces = [];
    const colors = ['#ef4444', '#f97316', '#eab308', '#8b5cf6', '#06b6d4'];
    let cIdx = 0;

    catSet.forEach((catName) => {
      const yVals = data.points.map((p) => p.attack_categories?.[catName] || 0);
      catTraces.push({
        x: timeBins,
        y: yVals,
        name: catName,
        type: 'scatter',
        mode: 'lines+markers',
        line: { color: colors[cIdx % colors.length], width: 2 },
      });
      cIdx++;
    });

    if (catTraces.length === 0) {
      catTraces.push({
        x: timeBins,
        y: attackCounts,
        name: 'Total Attack Traffic',
        type: 'scatter',
        mode: 'lines+markers',
        line: { color: '#ef4444', width: 2 },
      });
    }

    Plotly.newPlot(
      'timeline-attack-chart',
      catTraces,
      {
        margin: { t: 20, b: 60, l: 50, r: 20 },
        paper_bgcolor: 'transparent',
        plot_bgcolor: 'transparent',
        font: { family: 'inherit', color: '#334155', size: 12 },
        xaxis: { title: 'Timestamp' },
        yaxis: { title: 'Attack Flow Count' },
        legend: { orientation: 'h', y: 1.15, x: 0.5, xanchor: 'center' },
      },
      { responsive: true, displayModeBar: false }
    );
  } catch (err) {
    container.innerHTML = `<div class="callout callout-critical">Failed to load timeline: ${err.message}</div>`;
  }
}
