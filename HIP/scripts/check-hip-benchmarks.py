#!/usr/bin/env python3
import json, glob, sys, os

# Simple guardrail checker for BenchmarkDotNet full JSON exports.
# Usage: python3 scripts/check-hip-benchmarks.py [artifacts_dir]

artifacts = sys.argv[1] if len(sys.argv) > 1 else "HIP.Protocol.Benchmarks/BenchmarkDotNet.Artifacts/results"
files = glob.glob(os.path.join(artifacts, "*.full.json")) + glob.glob(os.path.join(artifacts, "*report-full-compressed.json"))
if not files:
    print(f"No benchmark JSON files found in {artifacts}")
    sys.exit(2)

max_mean_ns = {
    "Envelope_Verify_Hmac": 5_000_000,       # 5 ms
    "Receipt_Issue_Hmac": 5_000_000,
    "Receipt_Verify_Hmac": 5_000_000,
}

violations = []
for f in files:
    try:
        data = json.load(open(f))
    except Exception:
        continue
    benches = data.get("Benchmarks", []) if isinstance(data, dict) else []
    for b in benches:
        name = b.get("DisplayInfo") or b.get("FullName") or ""
        stats = b.get("Statistics") or {}
        mean = stats.get("Mean")
        if mean is None:
            continue
        for key, limit in max_mean_ns.items():
            if key in name and mean > limit:
                violations.append((key, mean, limit, f))

if violations:
    print("HIP benchmark threshold violations:")
    for v in violations:
        print(f"- {v[0]} mean={v[1]:,.0f}ns limit={v[2]:,.0f}ns file={v[3]}")
    sys.exit(1)

print("HIP benchmark thresholds passed.")
sys.exit(0)
