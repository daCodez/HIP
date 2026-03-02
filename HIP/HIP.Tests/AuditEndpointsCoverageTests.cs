using System.Net;
using System.Net.Http.Json;
using HIP.Audit.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class AuditEndpointsCoverageTests
{
    [Test]
    public async Task AuditList_WithFilters_ReturnsOk()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        // Seed a couple audit events via normal API calls
        await client.GetAsync("/api/identity/hip-system");
        await client.GetAsync("/api/reputation/hip-system");

        var response = await client.GetAsync("/api/admin/audit?take=20&eventType=identity.read&outcome=success");
        var payload = await response.Content.ReadFromJsonAsync<List<AuditEvent>>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
    }

    [Test]
    public async Task AuditExport_DefaultJson_ReturnsOk()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/api/admin/audit/export?take=50");
        var body = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(body, Does.Contain("items"));
    }
}
