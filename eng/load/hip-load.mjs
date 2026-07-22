import { randomUUID } from 'node:crypto';

const baseUrl = (process.env.HIP_LOAD_BASE_URL ?? 'http://localhost:5260').replace(/\/$/, '');
const durationSeconds = boundedInt('HIP_LOAD_DURATION_SECONDS', 30, 5, 900);
const concurrency = boundedInt('HIP_LOAD_CONCURRENCY', 8, 1, 100);
const domain = process.env.HIP_LOAD_DOMAIN ?? 'example.com';
const enableWrites = process.env.HIP_LOAD_ENABLE_WRITES === '1';
const adminRole = process.env.HIP_LOAD_ADMIN_ROLE;
const adminUser = process.env.HIP_LOAD_ADMIN_USER;
const deadline = Date.now() + durationSeconds * 1000;

const scenarios = [
  scenario('public-lookup-cached', 'GET', `/api/v1/public/lookup/${encodeURIComponent(domain)}`, null, 150),
  scenario('browser-fast-score', 'POST', '/api/v1/browser/score-site', () => ({ url: `https://${domain}/`, domain }), 750),
];

if (adminRole && adminUser) {
  scenarios.push(scenario('admin-paged-list', 'GET', '/api/v1/licenses?page=1&pageSize=25', null, 750, {
    'X-HIP-Admin-Role': adminRole,
    'X-HIP-Admin-User': adminUser,
  }));
}

if (enableWrites) {
  scenarios.push(scenario('public-feedback-write', 'POST', '/api/v1/public/feedback', () => ({
    targetType: 'Domain',
    targetId: `load-${randomUUID()}.invalid`,
    eventType: 'SuspiciousReport',
    severity: 'Low',
    reporterTrustLevel: 'Anonymous',
    reason: 'bounded-load-test-signal',
    platform: 'HIPLoadHarness',
  }), 250));
}

const results = new Map(scenarios.map(item => [item.name, []]));
await Promise.all(Array.from({ length: concurrency }, (_, worker) => runWorker(worker)));

let failed = false;
const report = scenarios.map(item => {
  const samples = results.get(item.name);
  const durations = samples.map(sample => sample.durationMs).sort((a, b) => a - b);
  const errors = samples.filter(sample => !sample.ok).length;
  const p95 = percentile(durations, 0.95);
  const errorRate = samples.length === 0 ? 1 : errors / samples.length;
  const passed = samples.length > 0 && p95 <= item.p95TargetMs && errorRate <= 0.01;
  failed ||= !passed;
  return { scenario: item.name, requests: samples.length, errors, errorRate, p95Ms: p95, targetP95Ms: item.p95TargetMs, passed };
});

process.stdout.write(`${JSON.stringify({ baseUrl, durationSeconds, concurrency, writesEnabled: enableWrites, report }, null, 2)}\n`);
process.exitCode = failed ? 1 : 0;

async function runWorker(worker) {
  let index = worker % scenarios.length;
  while (Date.now() < deadline) {
    const item = scenarios[index++ % scenarios.length];
    const started = performance.now();
    let ok = false;
    try {
      const body = item.bodyFactory?.();
      const response = await fetch(`${baseUrl}${item.path}`, {
        method: item.method,
        headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...item.headers },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(5000),
      });
      ok = response.ok;
      await response.body?.cancel();
    } catch {
      ok = false;
    }
    results.get(item.name).push({ durationMs: performance.now() - started, ok });
  }
}

function scenario(name, method, path, bodyFactory, p95TargetMs, headers = {}) {
  return { name, method, path, bodyFactory, p95TargetMs, headers };
}

function boundedInt(name, fallback, minimum, maximum) {
  const value = Number.parseInt(process.env[name] ?? `${fallback}`, 10);
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`${name} must be between ${minimum} and ${maximum}.`);
  return value;
}

function percentile(sorted, quantile) {
  if (sorted.length === 0) return null;
  return Math.round(sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * quantile) - 1)] * 100) / 100;
}
