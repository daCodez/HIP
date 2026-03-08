# HIP Protocol Benchmarks — Example Output Format

Example (illustrative):

| Benchmark | PayloadBytes | Mean | Median | P95 | Allocated |
|---|---:|---:|---:|---:|---:|
| CanonicalSerializeEnvelope | 128 | 2.1 us | 2.0 us | 2.8 us | 1.2 KB |
| VerifySignature | 1024 | 6.8 us | 6.6 us | 8.2 us | 1.8 KB |
| FullEnvelopeValidationFlow | 1024 | 24.5 us | 24.1 us | 30.0 us | 5.6 KB |
| Validate1000EnvelopesParallel | n/a | 15.4 ms | 15.1 ms | 19.0 ms | 320 KB |

BenchmarkDotNet artifacts are written under `BenchmarkDotNet.Artifacts/` and include markdown + JSON files for CI processing.
