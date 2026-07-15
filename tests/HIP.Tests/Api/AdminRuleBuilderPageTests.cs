using System.Net;
using HIP.Application.SecondLife;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Api;

public sealed class AdminRuleBuilderPageTests
{
    [Test]
    public async Task Rule_builder_page_loads_for_admin()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);

        var response = await client.GetAsync("/admin/rules");
        var html = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(html, Does.Contain("Admin Rule Builder"));
        Assert.That(html, Does.Contain("Live JSON Preview"));
        Assert.That(html, Does.Contain("Site Safety Rule Simulation"));
    }

    [Test]
    public async Task Rule_builder_new_route_loads_for_admin()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);

        var response = await client.GetAsync("/admin/rules/new");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Rule_builder_id_route_loads_for_admin()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);

        var response = await client.GetAsync("/admin/rules/new-domain-shortener-high-risk");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Admin_rule_builder_route_is_protected()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var response = await client.GetAsync("/admin/rules");

        Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Admin_settings_page_loads_external_provider_controls()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);

        var response = await client.GetAsync("/admin/settings");
        var html = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(html, Does.Contain("External Safety Evidence"));
        Assert.That(html, Does.Contain("SSL Labs / Qualys TLS"));
        Assert.That(html, Does.Contain("Google Web Risk / Safe Browsing"));
        Assert.That(html, Does.Contain("VirusTotal"));
    }

    [Test]
    public async Task Alert_center_loads_operational_filter_and_refresh_controls()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);

        var response = await client.GetAsync("/admin/alerts");
        var html = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(html, Does.Contain("Alert Center"));
        Assert.That(html, Does.Contain("Search alerts"));
        Assert.That(html, Does.Contain("Refresh alerts"));
        Assert.That(html, Does.Contain("role=\"tablist\""));
        Assert.That(html, Does.Contain("aria-live=\"polite\""));
        Assert.That(html, Does.Contain("alert-center-list"));
    }

    [Test]
    public async Task License_pages_use_plain_English_management_workflows()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var scope = factory.Services.CreateScope();
        var licenseService = scope.ServiceProvider.GetRequiredService<ISetupCodeLicenseService>();
        var license = licenseService.CreateSetupCode(new CreateSetupCodeRequest(1, "page-test", "Normal"));
        using var client = factory.CreateClient();
        AddAdmin(client);

        var listHtml = await client.GetStringAsync("/admin/licenses");
        var detailHtml = await client.GetStringAsync($"/admin/licenses/{license.LicenseId}");
        var createHtml = await client.GetStringAsync("/admin/licenses/new");

        Assert.That(listHtml, Does.Contain("Find a license"));
        Assert.That(listHtml, Does.Contain("license-sort-button"));
        Assert.That(listHtml, Does.Contain("Manage"));
        Assert.That(listHtml, Does.Not.Contain("MVP"));
        Assert.That(detailHtml, Does.Contain("Manage license"));
        Assert.That(detailHtml, Does.Contain("Allow a new device"));
        Assert.That(detailHtml, Does.Contain("Cancel this license"));
        Assert.That(createHtml, Does.Contain("Create a license"));
        Assert.That(createHtml, Does.Contain("Copy this code before leaving this page"));
        Assert.That(createHtml, Does.Not.Contain("raw setup code"));
    }

    [Test]
    public async Task License_navigation_uses_a_direct_full_page_link()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);

        var html = await client.GetStringAsync("/admin");

        Assert.Multiple(() =>
        {
            Assert.That(html, Does.Contain("href=\"/admin/licenses\""));
            Assert.That(html, Does.Contain("data-enhance-nav=\"false\""));
        });
    }

    [Test]
    public async Task License_page_uses_async_storage_operation()
    {
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<ISetupCodeLicenseService>();
                services.AddScoped<ISetupCodeLicenseService, AsyncOnlyLicenseService>();
            }));
        using var client = factory.CreateClient();
        AddAdmin(client);

        var response = await client.GetAsync("/admin/licenses");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Admin_domain_verification_page_loads_for_admin()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);

        var response = await client.GetAsync("/admin/identity/websites");
        var html = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(html, Does.Contain("Domain Verification"));
        Assert.That(html, Does.Contain("Registered Domains"));
        Assert.That(html, Does.Contain("Search domains"));
        Assert.That(html, Does.Contain("Start Verification"));
        Assert.That(html, Does.Contain("DNS TXT"));
        Assert.That(html, Does.Contain("Last checked UTC"));
        Assert.That(html, Does.Contain("Actions"));
        Assert.That(html, Does.Contain("verification-sort-button"));
        Assert.That(html.Split("verification-sort-button", StringSplitOptions.None).Length - 1, Is.EqualTo(6));
        Assert.That(html, Does.Contain("aria-sort=\"descending\""));
        Assert.That(html, Does.Not.Contain("Order by"));
        Assert.That(html, Does.Not.Contain("verification-order-button"));
        Assert.That(html, Does.Not.Contain("CoreDNS"));
        Assert.That(html, Does.Not.Contain(".well-known/hip.json"));
        Assert.That(html, Does.Not.Contain("Verification method"));
        Assert.That(html, Does.Contain("Verification proves control of the domain"));
        Assert.That(html.IndexOf("Start Verification", StringComparison.Ordinal),
            Is.LessThan(html.IndexOf("Registered Domains", StringComparison.Ordinal)));
    }

    [Test]
    public async Task Admin_website_registration_page_is_protected()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var response = await client.GetAsync("/admin/identity/websites");

        Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.OK));
    }

    private static void AddAdmin(HttpClient client)
    {
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "admin-rule-builder-test");
    }

    private sealed class AsyncOnlyLicenseService : ISetupCodeLicenseService
    {
        private readonly InMemorySetupCodeLicenseService inner = new();

        public CreateSetupCodeResponse CreateSetupCode(CreateSetupCodeRequest request) => inner.CreateSetupCode(request);

        public IReadOnlyCollection<LicenseSummary> ListLicenses() =>
            throw new InvalidOperationException("The Licenses page must not block on synchronous persistent storage.");

        public Task<IReadOnlyCollection<LicenseSummary>> ListLicensesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyCollection<LicenseSummary>>([]);

        public LicenseSummary? GetLicense(string licenseId) => inner.GetLicense(licenseId);

        public LicenseActivationResult ActivateHud(
            string setupCode,
            string? hudDeviceId,
            string? avatarIdHash,
            string? hudVersion) =>
            inner.ActivateHud(setupCode, hudDeviceId, avatarIdHash, hudVersion);

        public LicenseSummary? ResetActivation(string licenseId) => inner.ResetActivation(licenseId);

        public LicenseSummary? SetStatus(string licenseId, LicenseStatus status) => inner.SetStatus(licenseId, status);

        public LicenseHudSettings GetSettingsForDevice(string deviceId) => inner.GetSettingsForDevice(deviceId);

        public (bool Saved, string Message, LicenseHudSettings Settings) SaveSettingsForDevice(
            string deviceId,
            LicenseHudSettings settings) =>
            inner.SaveSettingsForDevice(deviceId, settings);
    }
}
