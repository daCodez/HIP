using BenchmarkDotNet.Running;
using HIP.Protocol.Benchmarks.Benchmarks;

BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
