using System.Linq;
using HIP.ApiService.Infrastructure.Plugins;
using NUnit.Framework;

namespace HIP.Tests.Plugins;

public sealed class SystemMetricsStoreTests
{
    [Test]
    public void Add_And_GetRecent_ReturnsOnlyRequestedTail()
    {
        var store = new SystemMetricsStore();
        var now = DateTimeOffset.UtcNow;

        for (var i = 0; i < 10; i++)
        {
            store.Add(new SystemMetricSample(now.AddSeconds(i), i, i));
        }

        var recent = store.GetRecent(3);
        Assert.That(recent.Count, Is.EqualTo(3));
        Assert.That(recent[0].CpuPercent, Is.EqualTo(7));
        Assert.That(recent[2].CpuPercent, Is.EqualTo(9));
    }

    [Test]
    public void Add_OverMax_KeepsRollingWindow()
    {
        var store = new SystemMetricsStore();
        var now = DateTimeOffset.UtcNow;

        for (var i = 0; i < 200; i++)
        {
            store.Add(new SystemMetricSample(now.AddSeconds(i), i, i));
        }

        var recent = store.GetRecent(200);
        Assert.That(recent.Count, Is.EqualTo(120));
        Assert.That(recent.First().CpuPercent, Is.EqualTo(80));
        Assert.That(recent.Last().CpuPercent, Is.EqualTo(199));
    }
}
