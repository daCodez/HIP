using System.Reflection;
using HIP.Application.SiteSafety;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Security;

/// <summary>
/// Protects public request paths from attacker-controlled memory growth and unthrottled DNS work.
/// </summary>
public sealed class ResourceBoundSecurityTests
{
    [Test]
    public async Task Provider_setting_scopes_evict_oldest_entries_at_the_configured_limit()
    {
        var store = new InMemoryExternalSiteEvidenceSettingsStore();
        var options = new ExternalSiteEvidenceOptions();

        for (var index = 0; index <= InMemoryExternalSiteEvidenceSettingsStore.MaxScopes; index++)
        {
            await store.SaveAsync($"instance:{index}", options, CancellationToken.None);
        }

        var oldest = await store.GetAsync("instance:0", CancellationToken.None);
        var newest = await store.GetAsync($"instance:{InMemoryExternalSiteEvidenceSettingsStore.MaxScopes}", CancellationToken.None);
        Assert.Multiple(() =>
        {
            Assert.That(store.Count, Is.EqualTo(InMemoryExternalSiteEvidenceSettingsStore.MaxScopes));
            Assert.That(oldest, Is.Null);
            Assert.That(newest, Is.Not.Null);
        });
    }

    [Test]
    public void Site_scan_cache_has_a_global_bound_and_expired_entry_sweep()
    {
        var cacheLimit = typeof(SiteSafetyScanner).GetField("MaxRecentScans", BindingFlags.NonPublic | BindingFlags.Static);
        var expirySweep = typeof(SiteSafetyScanner).GetMethod("TrimRecentScans", BindingFlags.NonPublic | BindingFlags.Static);

        Assert.Multiple(() =>
        {
            Assert.That(cacheLimit, Is.Not.Null);
            Assert.That(cacheLimit!.GetRawConstantValue(), Is.EqualTo(1024));
            Assert.That(expirySweep, Is.Not.Null);
        });
    }

    [Test]
    public async Task Every_public_dns_verification_operation_is_rate_limited()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints;
        var dnsEndpoints = endpoints
            .Where(endpoint => endpoint.DisplayName?.Contains("domain-verification", StringComparison.OrdinalIgnoreCase) is true)
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(dnsEndpoints, Has.Length.GreaterThanOrEqualTo(2));
            Assert.That(dnsEndpoints.All(endpoint => endpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>() is not null), Is.True);
        });
    }
}
