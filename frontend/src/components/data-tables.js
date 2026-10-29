/**
 * Reusable HeroUI Styled Table Component
 */

export function renderTable({
  columns,
  data,
  onRowClick = null,
  selectedRowKey = null,
  rowKeyField = 'host_id',
  emptyMessage = 'No records found matching criteria.',
}) {
  if (!data || data.length === 0) {
    return `
      <div style="padding: 36px 16px; text-align: center; color: var(--text-muted); font-size: 13px;">
        🔍 ${emptyMessage}
      </div>
    `;
  }

  return `
    <div class="table-container">
      <table class="heroui-table">
        <thead>
          <tr>
            ${columns
              .map(
                (col) => `
              <th style="${col.style || ''}" data-sort="${col.field || ''}">
                ${col.title}
              </th>
            `
              )
              .join('')}
          </tr>
        </thead>
        <tbody>
          ${data
            .map((row) => {
              const keyVal = row[rowKeyField];
              const isSelected = selectedRowKey && keyVal === selectedRowKey;
              return `
              <tr class="${isSelected ? 'selected-row' : ''}" data-row-key="${keyVal}">
                ${columns
                  .map((col) => {
                    const rawVal = row[col.field];
                    const rendered = col.render ? col.render(rawVal, row) : (rawVal ?? '-');
                    return `<td style="${col.cellStyle || ''}">${rendered}</td>`;
                  })
                  .join('')}
              </tr>
            `;
            })
            .join('')}
        </tbody>
      </table>
    </div>
  `;
}
