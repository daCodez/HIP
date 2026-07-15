using System.Net;
using HIP.Application.Review;
using HIP.Domain.Audit;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Api;

public sealed class AdminAuditNavigationRegressionTests
{
    /// <summary>
    /// Verifies audit-page prerendering awaits asynchronous persistence instead of blocking the Blazor renderer.
    /// </summary>
    [Test]
    public async Task Audit_trail_page_does_not_block_on_async_repository()
    {
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IAuditLogRepository>();
                services.AddScoped<IAuditLogRepository, DelayedAuditLogRepository>();
            }));
        using var client = factory.CreateClient();
        client.Timeout = TimeSpan.FromSeconds(3);
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "audit-navigation-regression");

        var response = await client.GetAsync("/admin/audit-logs");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    private sealed class DelayedAuditLogRepository : IAuditLogRepository
    {
        public async Task SaveAsync(AuditLogEntry entry, CancellationToken cancellationToken)
        {
            await Task.Yield();
        }

        public async Task<IReadOnlyCollection<AuditLogEntry>> ListAsync(CancellationToken cancellationToken)
        {
            await Task.Delay(25, cancellationToken);
            return Array.Empty<AuditLogEntry>();
        }
    }
}
