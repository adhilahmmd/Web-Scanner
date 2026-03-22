/**
 * WebSecuity – Lightweight Canvas Donut Chart
 * No external dependencies. Draws a severity breakdown donut.
 */
class DonutChart {
  constructor(canvasId, legendId) {
    this.canvas = document.getElementById(canvasId);
    this.legendEl = document.getElementById(legendId);
    this.ctx = this.canvas ? this.canvas.getContext('2d') : null;
    this.animFrame = null;
  }

  draw(data) {
    if (!this.ctx) return;
    const { canvas, ctx } = this;

    // data = [{ label, value, color }]
    const total = data.reduce((s, d) => s + d.value, 0);
    if (total === 0) {
      this._drawEmpty();
      this._buildLegend(data, 0);
      return;
    }

    const W = canvas.width;
    const H = canvas.height;
    const cx = W / 2;
    const cy = H / 2;
    const outerR = Math.min(W, H) / 2 - 8;
    const innerR = outerR * 0.58;

    ctx.clearRect(0, 0, W, H);

    let startAngle = -Math.PI / 2;
    const gap = 0.025; // gap between slices

    data.forEach(slice => {
      if (slice.value === 0) return;
      const fraction = slice.value / total;
      const angle = fraction * Math.PI * 2 - gap;

      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, outerR, startAngle, startAngle + angle);
      ctx.closePath();
      ctx.fillStyle = slice.color;
      ctx.fill();

      // Inner hole
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, innerR, startAngle, startAngle + angle);
      ctx.closePath();
      ctx.fillStyle = '#07091a';
      ctx.fill();

      startAngle += fraction * Math.PI * 2;
    });

    // Center text
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#e8eaf0';
    ctx.font = 'bold 28px Inter, sans-serif';
    ctx.fillText(total, cx, cy - 8);
    ctx.font = '11px Inter, sans-serif';
    ctx.fillStyle = '#636e7b';
    ctx.fillText('FINDINGS', cx, cy + 14);

    this._buildLegend(data, total);
  }

  _drawEmpty() {
    const { canvas, ctx } = this;
    const cx = canvas.width / 2;
    const cy = canvas.height / 2;
    const r = Math.min(canvas.width, canvas.height) / 2 - 8;

    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.strokeStyle = 'rgba(255,255,255,0.06)';
    ctx.lineWidth = 28;
    ctx.stroke();

    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#636e7b';
    ctx.font = '12px Inter, sans-serif';
    ctx.fillText('No data', cx, cy);
  }

  _buildLegend(data, total) {
    if (!this.legendEl) return;
    this.legendEl.innerHTML = data.map(slice => `
      <div class="legend-item">
        <div class="legend-dot" style="background:${slice.color}"></div>
        <span style="color:var(--text-secondary)">${slice.label}</span>
        <span class="legend-count" style="color:${slice.color}">${slice.value}</span>
      </div>
    `).join('');
  }
}

window.DonutChart = DonutChart;
