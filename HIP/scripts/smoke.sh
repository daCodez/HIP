#!/usr/bin/env bash
set -euo pipefail

check() {
  local name="$1"
  local url="$2"
  local expected="${3:-200}"

  local code
  code=$(curl -s -o /tmp/hip_smoke_body -w "%{http_code}" "$url" || true)

  if [[ "$code" == "$expected" ]]; then
    echo "[PASS] $name ($url) -> $code"
  else
    echo "[FAIL] $name ($url) -> got $code expected $expected"
    return 1
  fi
}

fail=0
check "HIP health forward" "http://127.0.0.1:5101/health" 200 || fail=1
check "Swagger" "http://127.0.0.1:44985/swagger/index.html" 200 || fail=1
check "HIP web" "http://127.0.0.1:45727/" 200 || fail=1

if [[ $fail -ne 0 ]]; then
  echo "SMOKE_FAILED"
  exit 1
fi

echo "SMOKE_OK"
