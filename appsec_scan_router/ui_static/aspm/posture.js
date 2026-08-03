const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export function riskDistributionMarkup(items, formatNumber, readable) {
  if (!items.length) {
    return '<span class="empty-inline">No findings imported</span>';
  }
  const total = items.reduce((sum, item) => sum + Number(item.count || 0), 0) || 1;
  const counts = new Map(items.map((item) => [item.name, Number(item.count || 0)]));
  let angle = -90;
  const segments = SEVERITY_ORDER.map((severity) => {
    const count = Math.max(0, counts.get(severity) || 0);
    const percentage = (count / total) * 100;
    const readableSeverity = readable(severity);
    const label = `${readableSeverity}: ${formatNumber(count)} findings (${percentage.toFixed(1)}%)`;
    const nextAngle = angle + (percentage * 3.6);
    const segment = count
      ? `<path class="risk-pie-segment risk-pie-${severity}" d="${donutSegmentPath(angle, nextAngle)}" data-risk-severity="${readableSeverity}" data-risk-count="${count}" data-risk-percent="${percentage.toFixed(1)}" tabindex="0" role="img" aria-label="${label}"><title>${label}</title></path>`
      : "";
    angle = nextAngle;
    return segment;
  }).join("");
  const legend = SEVERITY_ORDER.map((severity) => {
    const count = Math.max(0, counts.get(severity) || 0);
    const percentage = ((count / total) * 100).toFixed(1);
    return `<li><span class="risk-pie-swatch risk-pie-${severity}" aria-hidden="true"></span><span>${readable(severity)}</span><strong>${formatNumber(count)}</strong><small>${percentage}%</small></li>`;
  }).join("");
  return `<div class="risk-pie-layout">
    <svg class="risk-pie" viewBox="0 0 36 36" role="img" aria-label="Security finding severity distribution">
      <circle class="risk-pie-track" cx="18" cy="18" r="13.5"></circle>
      ${segments}
    </svg>
    <div class="risk-pie-tooltip" id="riskDistributionTooltip" role="status" aria-live="polite" hidden></div>
    <ul class="risk-pie-legend">${legend}</ul>
  </div>`;
}

function donutSegmentPath(startAngle, endAngle) {
  const outerRadius = 16;
  const innerRadius = 10.5;
  if (endAngle - startAngle >= 359.999) {
    return [
      `M 18 ${18 - outerRadius}`,
      `A ${outerRadius} ${outerRadius} 0 1 1 17.9999 ${18 - outerRadius}`,
      `L 17.9999 ${18 - innerRadius}`,
      `A ${innerRadius} ${innerRadius} 0 1 0 18 ${18 - innerRadius}`,
      "Z",
    ].join(" ");
  }
  const startOuter = pointOnCircle(outerRadius, startAngle);
  const endOuter = pointOnCircle(outerRadius, endAngle);
  const endInner = pointOnCircle(innerRadius, endAngle);
  const startInner = pointOnCircle(innerRadius, startAngle);
  const largeArc = endAngle - startAngle > 180 ? 1 : 0;
  return [
    `M ${startOuter.x} ${startOuter.y}`,
    `A ${outerRadius} ${outerRadius} 0 ${largeArc} 1 ${endOuter.x} ${endOuter.y}`,
    `L ${endInner.x} ${endInner.y}`,
    `A ${innerRadius} ${innerRadius} 0 ${largeArc} 0 ${startInner.x} ${startInner.y}`,
    "Z",
  ].join(" ");
}

function pointOnCircle(radius, angle) {
  const radians = (angle * Math.PI) / 180;
  return {
    x: (18 + (radius * Math.cos(radians))).toFixed(4),
    y: (18 + (radius * Math.sin(radians))).toFixed(4),
  };
}