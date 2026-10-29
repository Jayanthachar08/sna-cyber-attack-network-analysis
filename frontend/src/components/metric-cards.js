/**
 * Metric Card Component for Summary Statistics
 */

export function createMetricCard({ label, value, subtext, icon, trend = null }) {
  return `
    <div class="metric-card">
      <div class="metric-header">
        <span class="metric-label">${label}</span>
        ${icon ? `<span class="metric-icon-wrap">${icon}</span>` : ''}
      </div>
      <div class="metric-value">${value}</div>
      ${subtext ? `<div class="metric-footer">${subtext}</div>` : ''}
    </div>
  `;
}
