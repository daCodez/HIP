using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Exporters.Json;
using BenchmarkDotNet.Jobs;

namespace HIP.Protocol.Benchmarks.Config;

public sealed class HipBenchmarkConfig : ManualConfig
{
    public HipBenchmarkConfig()
    {
        AddJob(Job.Default.WithId("Default"));
        AddDiagnoser(MemoryDiagnoser.Default);
        AddExporter(MarkdownExporter.GitHub, JsonExporter.Full);
        AddColumnProvider(DefaultColumnProviders.Instance);
        AddColumn(StatisticColumn.Mean, StatisticColumn.Median, StatisticColumn.P95, StatisticColumn.StdDev, StatisticColumn.Min, StatisticColumn.Max);
    }
}
