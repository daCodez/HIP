import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';

const baseUrl = (process.env.HIP_LOAD_BASE_URL ?? 'http://localhost:5260').replace(/\/$/, '');
const durationSeconds = boundedInt('HIP_LOAD_DURATION_SECONDS', 30, 5, 900);
const concurrency = boundedInt('HIP_LOAD_CONCURRENCY', 8, 1, 100);
const requestsPerSecond = boundedInt('HIP_LOAD_REQUESTS_PER_SECOND', 0, 0, 10_000);
const domain = process.env.HIP_LOAD_DOMAIN ?? 'example.com';
const enableWrites = process.env.HIP_LOAD_ENABLE_WRITES === '1';
const adminRole = process.env.HIP_LOAD_ADMIN_ROLE;
const adminUser = process.env.HIP_LOAD_ADMIN_USER;
const adminCookieFile = process.env.HIP_LOAD_AUTH_COOKIE_FILE;
const deadline = Date.now() + durationSeconds * 1000;

const availableScenarios = [
  scenario('public-lookup-cached', 'GET', `/api/v1/public/lookup/${encodeURIComponent(domain)}`, null, 150),
  scenario('browser-fast-score', 'POST', '/api/v1/browser/score-site', () => ({ url: `https://${domain}/`, domain }), 750),
];

const adminHeaders = loadAdminHeaders();
if (adminHeaders) {
  availableScenarios.push(scenario(
    'admin-paged-list',
    'GET',
    '/api/v1/licenses?page=1&pageSize=25',
    null,
    750,
    adminHeaders));
}

if (enableWrites) {
  availableScenarios.push(scenario('public-feedback-write', 'POST', '/api/v1/public/feedback', () => ({
    targetType: 'Domain',
    targetId: `load-${randomUUID()}.invalid`,
    eventType: 'SuspiciousReport',
    severity: 'Low',
    reporterTrustLevel: 'Anonymous',
    reason: 'bounded-load-test-signal',
    platform: 'HIPLoadHarness',
  }), 250));
}

const requestedScenarioNames = new Set(
  (process.env.HIP_LOAD_SCENARIOS ?? '')
    .split(',')
    .map(value => value.trim())
    .filter(Boolean));
const unknownScenarioNames = [...requestedScenarioNames]
  .filter(name => !availableScenarios.some(item => item.name === name));
if (unknownScenarioNames.length > 0) {
  throw new Error(`HIP_LOAD_SCENARIOS contains unavailable scenarios: ${unknownScenarioNames.join(', ')}`);
}
const scenarios = requestedScenarioNames.size === 0
  ? availableScenarios
  : availableScenarios.filter(item => requestedScenarioNames.has(item.name));
if (scenarios.length === 0) throw new Error('At least one load scenario must be selected.');

const results = new Map(scenarios.map(item => [item.name, []]));
const requestIntervalMs = requestsPerSecond > 0 ? 1000 / requestsPerSecond : 0;
let nextRequestAt = Date.now();
await Promise.all(Array.from({ length: concurrency }, (_, worker) => runWorker(worker)));

let failed = false;
const report = scenarios.map(item => {
  const samples = results.get(item.name);
  const durations = samples.map(sample => sample.durationMs).sort((a, b) => a - b);
  const errors = samples.filter(sample => !sample.ok).length;
  const networkErrors = samples.filter(sample => sample.statusCode === null).length;
  const statusCodes = Object.fromEntries([...new Set(samples
    .map(sample => sample.statusCode)
    .filter(statusCode => statusCode !== null))]
    .sort((left, right) => left - right)
    .map(statusCode => [statusCode, samples.filter(sample => sample.statusCode === statusCode).length]));
  const p95 = percentile(durations, 0.95);
  const errorRate = samples.length === 0 ? 1 : errors / samples.length;
  const passed = samples.length > 0 && p95 <= item.p95TargetMs && errorRate <= 0.01;
  failed ||= !passed;
  return {
    scenario: item.name,
    requests: samples.length,
    requestsPerSecond: Math.round(samples.length / durationSeconds * 100) / 100,
    errors,
    networkErrors,
    statusCodes,
    errorRate,
    p95Ms: p95,
    targetP95Ms: item.p95TargetMs,
    passed,
  };
});

process.stdout.write(`${JSON.stringify({
  baseUrl,
  durationSeconds,
  concurrency,
  requestRateLimit: requestsPerSecond || null,
  writesEnabled: enableWrites,
  report,
}, null, 2)}\n`);
process.exitCode = failed ? 1 : 0;

async function runWorker(worker) {
  let index = worker % scenarios.length;
  while (Date.now() < deadline) {
    if (!await waitForRateSlot()) break;
    const item = scenarios[index++ % scenarios.length];
    const started = performance.now();
    let ok = false;
    let statusCode = null;
    try {
      const body = item.bodyFactory?.();
      const response = await fetch(`${baseUrl}${item.path}`, {
        method: item.method,
        headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...item.headers },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(5000),
      });
      statusCode = response.status;
      ok = response.ok;
      await response.body?.cancel();
    } catch {
      ok = false;
    }
    results.get(item.name).push({ durationMs: performance.now() - started, ok, statusCode });
  }
}

async function waitForRateSlot() {
  if (requestIntervalMs === 0) return Date.now() < deadline;
  const scheduledAt = Math.max(Date.now(), nextRequestAt);
  if (scheduledAt >= deadline) return false;
  nextRequestAt = scheduledAt + requestIntervalMs;
  const delayMs = scheduledAt - Date.now();
  if (delayMs > 0) await new Promise(resolve => setTimeout(resolve, delayMs));
  return true;
}

function scenario(name, method, path, bodyFactory, p95TargetMs, headers = {}) {
  return { name, method, path, bodyFactory, p95TargetMs, headers };
}

function boundedInt(name, fallback, minimum, maximum) {
  const value = Number.parseInt(process.env[name] ?? `${fallback}`, 10);
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`${name} must be between ${minimum} and ${maximum}.`);
  return value;
}

/** Loads exactly one supported admin authentication mechanism without logging its secret material. */
function loadAdminHeaders() {
  if (adminCookieFile) {
    if (adminRole || adminUser) {
      throw new Error('HIP_LOAD_AUTH_COOKIE_FILE cannot be combined with development admin headers.');
    }

    let cookie;
    try {
      cookie = readFileSync(adminCookieFile, 'utf8').trim();
    } catch {
      throw new Error('Unable to read HIP_LOAD_AUTH_COOKIE_FILE.');
    }
    if (cookie.length === 0 || cookie.length > 8192 || /[\r\n\0]/u.test(cookie)) {
      throw new Error('HIP_LOAD_AUTH_COOKIE_FILE must contain one bounded Cookie header value.');
    }

    return { Cookie: cookie };
  }

  if (adminRole || adminUser) {
    if (!adminRole || !adminUser) {
      throw new Error('HIP_LOAD_ADMIN_ROLE and HIP_LOAD_ADMIN_USER must be supplied together.');
    }
    if (!isLoopbackBaseUrl()) {
      throw new Error('Development admin headers are allowed only for a loopback load target.');
    }
    return {
      'X-HIP-Admin-Role': adminRole,
      'X-HIP-Admin-User': adminUser,
    };
  }

  return null;
}

/** Returns true only for hostnames that cannot route development identity headers off-device. */
function isLoopbackBaseUrl() {
  const hostname = new URL(baseUrl).hostname.toLowerCase();
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}

function percentile(sorted, quantile) {
  if (sorted.length === 0) return null;
  return Math.round(sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * quantile) - 1)] * 100) / 100;
}
