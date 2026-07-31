const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export function riskDistributionMarkup(items, formatNumber, readable) {
  if (!items.length) {
    return '<span class="empty-inline">No findings imported</span>';
  }
  const total = items.reduce((sum, item) => sum + Number(item.count || 0), 0) || 1;
  const counts = new Map(items.map((item) => [item.name, Number(item.count || 0)]));
  let offset = 0;
  const segments = SEVERITY_ORDER.map((severity) => {
    const count = Math.max(0, counts.get(severity) || 0);
    const percentage = Number(((count / total) * 100).toFixed(3));
    const segment = `<circle class="risk-pie-segment risk-pie-${severity}" cx="18" cy="18" r="15.9155" pathLength="100" stroke-dasharray="${percentage} ${100 - percentage}" stroke-dashoffset="${-offset}" transform="rotate(-90 18 18)"></circle>`;
    offset += percentage;
    return segment;
  }).join("");
  const legend = SEVERITY_ORDER.map((severity) => {
    const count = Math.max(0, counts.get(severity) || 0);
    const percentage = ((count / total) * 100).toFixed(1);
    return `<li><span class="risk-pie-swatch risk-pie-${severity}" aria-hidden="true"></span><span>${readable(severity)}</span><strong>${formatNumber(count)}</strong><small>${percentage}%</small></li>`;
  }).join("");
  return `<div class="risk-pie-layout">
    <svg class="risk-pie" viewBox="0 0 36 36" role="img" aria-label="Security finding severity distribution">
      <circle class="risk-pie-track" cx="18" cy="18" r="15.9155"></circle>
      ${segments}
    </svg>
    <ul class="risk-pie-legend">${legend}</ul>
  </div>`;
}