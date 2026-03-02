using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class AuditExportEndpointTests
{
    [Test]
    public async Task ExportAudit_WithFilters_ReturnsOk()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        await client.GetAsync("/api/identity/hip-system");
        var response = await client.GetAsync("/api/admin/audit/export?take=20&eventType=identity.read&format=json");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(body, Does.Contain("items"));
    }

    [Test]
    public async Task ExportAudit_AsCsv_ReturnsCsvContentType()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/api/admin/audit/export?take=10&format=csv");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("text/csv"));
    }
}
