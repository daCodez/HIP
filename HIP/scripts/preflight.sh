#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

warn() {
  echo "[WARN] $1"
}

pass() {
  echo "[OK] $1"
}

echo "HIP preflight check"
echo "Repo: $ROOT_DIR"

command -v dotnet >/dev/null 2>&1 || fail "dotnet is not installed or not on PATH"
pass "dotnet is available"

[[ -f "HIP.sln" ]] || fail "HIP.sln not found (run from HIP repo root)"
[[ -f "HIP.ApiService/Program.cs" ]] || fail "HIP.ApiService/Program.cs not found"
pass "required project files found"

ENV_NAME="${ASPNETCORE_ENVIRONMENT:-Production}"
ALLOW_UNSECURED="${ASPIRE_ALLOW_UNSECURED_TRANSPORT:-false}"

if [[ "$ENV_NAME" != "Development" && "$ALLOW_UNSECURED" == "true" ]]; then
  fail "ASPIRE_ALLOW_UNSECURED_TRANSPORT=true is not allowed outside Development"
fi
pass "transport env guard looks safe"

POLICY_VERSION="${HIP__Policy__Version:-}"
if [[ -z "$POLICY_VERSION" ]]; then
  warn "HIP__Policy__Version not set; app default (default-v1) will be used"
else
  pass "policy version set: $POLICY_VERSION"
fi

PLUGIN_LIST="${HIP__Plugins__Enabled__0:-} ${HIP__Plugins__Enabled__1:-} ${HIP__Plugins__Enabled__2:-}"
if echo "$PLUGIN_LIST" | grep -qi "core.policy.strict"; then
  warn "core.policy.strict is enabled (stricter thresholds)"
else
  pass "default policy thresholds active"
fi

echo "Running build sanity check..."
dotnet build HIP.sln -c Debug >/dev/null
pass "solution builds"

echo "Preflight complete."
