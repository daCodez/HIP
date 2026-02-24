window.hipCharts = (() => {
  const charts = {};

  function destroy(id) {
    if (charts[id]) {
      charts[id].destroy();
      delete charts[id];
    }
  }

  function mk(id, cfg) {
    const el = document.getElementById(id);
    if (!el || !window.Chart) return;
    destroy(id);
    charts[id] = new Chart(el.getContext('2d'), cfg);
  }

  function axisColor() { return '#8f8f8f'; }
  function gridColor() { return '#e5e5e5'; }
  function legendColor() { return '#7b7b7b'; }

  function renderAll(model) {
    mk('hipTrendChart', {
      type: 'line',
      data: {
        labels: model.trend.labels,
        datasets: [
          { label: 'Replay', data: model.trend.replay, borderColor: '#f59e0b', tension: .25 },
          { label: 'Expired', data: model.trend.expired, borderColor: '#ef4444', tension: .25 },
          { label: 'Blocked', data: model.trend.blocked, borderColor: '#8b5cf6', tension: .25 }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: legendColor(), boxWidth: 22, boxHeight: 10 } } },
        scales: {
          x: { ticks: { color: axisColor() }, grid: { color: gridColor() } },
          y: { ticks: { color: axisColor() }, grid: { color: gridColor() }, beginAtZero: true }
        }
      }
    });

    mk('hipReasonChart', {
      type: 'bar',
      data: {
        labels: model.reasons.labels,
        datasets: [{ label: 'Count', data: model.reasons.values, backgroundColor: '#3b82f6' }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: legendColor(), boxWidth: 22, boxHeight: 10 } } },
        scales: {
          x: { ticks: { color: axisColor() }, grid: { color: gridColor() } },
          y: { ticks: { color: axisColor() }, grid: { color: gridColor() }, beginAtZero: true }
        }
      }
    });

    mk('hipTrustChart', {
      type: 'doughnut',
      data: {
        labels: model.trust.labels,
        datasets: [{ data: model.trust.values, backgroundColor: ['#16a34a', '#f59e0b', '#ef4444'] }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: legendColor(), boxWidth: 18, boxHeight: 8 } } }
      }
    });
  }

  return { renderAll };
})();
