using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Review;
using HIP.Application.SiteSafety;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies external-provider configuration changes require recent authorization and never disclose provider secrets.
/// </summary>
[TestFixture]
public sealed class ExternalProviderSettingsSecurityTests
{
    private const string ProviderSettingsRoute = "/api/v1/admin/site-safety/external-providers";

    /// <summary>
    /// Confirms the provider-settings write route requires both rule management and recent privileged authentication.
    /// </summary>
    [Test]
    public async Task Provider_settings_write_route_requires_management_and_recent_authentication()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var endpoint = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Single(candidate =>
                string.Equals(candidate.RoutePattern.RawText, ProviderSettingsRoute, StringComparison.Ordinal) &&
                candidate.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Contains(HttpMethods.Post) is true);

        var policies = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>()
            .Select(metadata => metadata.Policy)
            .Where(policy => !string.IsNullOrWhiteSpace(policy))
            .Cast<string>()
            .ToArray();

        Assert.That(
            policies,
            Is.EquivalentTo(new[]
            {
                AdminPolicies.CanManageRules,
                AdminPolicies.RecentPrivilegedAuthentication
            }));
    }

    /// <summary>
    /// Confirms the interactive-server save path reauthorizes the active circuit before changing runtime settings.
    /// </summary>
    [Test]
    public void Provider_settings_page_reauthorizes_the_current_circuit_before_mutation()
    {
        var page = ReadSettingsPage();
        var save = Section(page, "private async Task Save()", "private void ApplySettings()");

        Assert.Multiple(() =>
        {
            Assert.That(page, Does.Contain("@inject IAuthorizationService AuthorizationService"));
            Assert.That(page, Does.Contain("@inject AuthenticationStateProvider AuthenticationStateProvider"));
            Assert.That(save, Does.Contain("AdminPolicies.CanManageRules"));
            Assert.That(save, Does.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
            Assert.That(save, Does.Contain("HipAdminPageAccess.ExecuteAuthorizedAsync"));
            Assert.That(save, Does.Contain("Confirm your identity again before saving external provider settings."));
            AssertGateBeforeMutation(save, "AdminPolicies.CanManageRules", "ApplySettings()");
            AssertGateBeforeMutation(save, "AdminPolicies.RecentPrivilegedAuthentication", "ApplySettings()");
        });
    }

    /// <summary>
    /// Confirms configured provider keys are represented only as presence state and replacement input is cleared after use.
    /// </summary>
    [Test]
    public void Provider_settings_page_never_rehydrates_raw_api_keys_into_bound_form_state()
    {
        var page = ReadSettingsPage();
        var apply = Section(page, "private static void Apply", "private RenderFragment ProviderCard");

        Assert.Multiple(() =>
        {
            Assert.That(page, Does.Not.Contain("ApiKey = options.ApiKey"));
            Assert.That(page, Does.Contain("HasConfiguredApiKey = !string.IsNullOrWhiteSpace(options.ApiKey)"));
            Assert.That(page, Does.Contain("type=\"password\""));
            Assert.That(page, Does.Contain("autocomplete=\"new-password\""));
            Assert.That(apply, Does.Contain("if (!string.IsNullOrWhiteSpace(state.ApiKey))"));
            Assert.That(apply, Does.Contain("state.ApiKey = null;"));
        });
    }

    /// <summary>
    /// Confirms neither update nor read responses echo a submitted provider API key.
    /// </summary>
    [Test]
    public async Task Provider_settings_api_never_echoes_submitted_api_keys()
    {
        const string secret = "hip-provider-secret-never-echo";
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, AdminRoles.Owner);
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.UserHeaderName, "provider-settings-owner");

        using var update = await client.PostAsJsonAsync(ProviderSettingsRoute, new
        {
            ExternalProvidersEnabled = true,
            AllowFullUrlChecks = false,
            ProviderTimeout = "00:00:02",
            DefaultCacheDuration = "06:00:00",
            SslLabs = new { Enabled = true, Endpoint = "", ApiKey = "", AllowFullUrl = false, CacheDuration = "06:00:00" },
            GoogleWebRisk = new { Enabled = false, Endpoint = "", ApiKey = "", AllowFullUrl = false, CacheDuration = (string?)null },
            VirusTotal = new { Enabled = true, Endpoint = "https://example.invalid/vt", ApiKey = secret, AllowFullUrl = false, CacheDuration = "03:00:00" }
        });
        var updateBody = await update.Content.ReadAsStringAsync();

        using var read = await client.GetAsync(ProviderSettingsRoute);
        var readBody = await read.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(update.IsSuccessStatusCode, Is.True, updateBody);
            Assert.That(read.IsSuccessStatusCode, Is.True, readBody);
            Assert.That(updateBody, Does.Not.Contain(secret));
            Assert.That(readBody, Does.Not.Contain(secret));
        });
    }

    /// <summary>
    /// Confirms a masked-form update keeps a configured key unless an administrator supplies a replacement.
    /// </summary>
    [Test]
    public async Task Provider_settings_api_preserves_the_existing_key_when_replacement_is_blank()
    {
        const string secret = "hip-existing-provider-secret";
        var settingsStore = new RecordingSettingsStore();
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = baseFactory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IExternalSiteEvidenceSettingsStore>();
            services.AddSingleton<IExternalSiteEvidenceSettingsStore>(settingsStore);
        }));
        using var client = OwnerClient(factory, "provider-key-rotation-owner");

        using var initial = await client.PostAsJsonAsync(ProviderSettingsRoute, ProviderPayload(secret));
        using var maskedRoundTrip = await client.PostAsJsonAsync(ProviderSettingsRoute, ProviderPayload(string.Empty));

        Assert.Multiple(() =>
        {
            Assert.That(initial.IsSuccessStatusCode, Is.True, initial.Content.ReadAsStringAsync().GetAwaiter().GetResult());
            Assert.That(maskedRoundTrip.IsSuccessStatusCode, Is.True, maskedRoundTrip.Content.ReadAsStringAsync().GetAwaiter().GetResult());
            Assert.That(settingsStore.LastSaved?.VirusTotal.ApiKey, Is.EqualTo(secret));
        });
    }

    /// <summary>
    /// Confirms successful provider-setting writes audit the authenticated actor without recording keys or endpoints.
    /// </summary>
    [Test]
    public async Task Provider_settings_api_audits_the_authenticated_actor_without_secret_metadata()
    {
        const string actor = "provider-settings-audit-owner";
        const string secret = "hip-provider-audit-secret";
        const string endpoint = "https://credential-bearing-endpoint.invalid/provider";
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = OwnerClient(factory, actor);

        using var response = await client.PostAsJsonAsync(ProviderSettingsRoute, ProviderPayload(secret, endpoint));
        await using var scope = factory.Services.CreateAsyncScope();
        var auditLog = scope.ServiceProvider.GetRequiredService<IAuditLogService>();
        var entries = await auditLog.ListAsync(CancellationToken.None);
        var entry = entries.Single(item =>
            string.Equals(item.Action, "ExternalProviderSettings.Updated", StringComparison.Ordinal));
        var serialized = JsonSerializer.Serialize(entry);

        Assert.Multiple(() =>
        {
            Assert.That(response.IsSuccessStatusCode, Is.True, response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
            Assert.That(entry.ActorId, Is.EqualTo(actor));
            Assert.That(serialized, Does.Not.Contain(secret));
            Assert.That(serialized, Does.Not.Contain(endpoint));
        });
    }

    private static HttpClient OwnerClient(WebApplicationFactory<Program> factory, string actor)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, AdminRoles.Owner);
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.UserHeaderName, actor);
        return client;
    }

    private static object ProviderPayload(string apiKey, string endpoint = "https://example.invalid/vt") => new
    {
        ExternalProvidersEnabled = true,
        AllowFullUrlChecks = false,
        ProviderTimeout = "00:00:02",
        DefaultCacheDuration = "06:00:00",
        SslLabs = new { Enabled = true, Endpoint = "", ApiKey = "", AllowFullUrl = false, CacheDuration = "06:00:00" },
        GoogleWebRisk = new { Enabled = false, Endpoint = "", ApiKey = "", AllowFullUrl = false, CacheDuration = (string?)null },
        VirusTotal = new { Enabled = true, Endpoint = endpoint, ApiKey = apiKey, AllowFullUrl = false, CacheDuration = "03:00:00" }
    };

    private static string ReadSettingsPage() => File.ReadAllText(Path.Combine(
        RepositoryRoot(),
        "src",
        "HIP.Web",
        "Components",
        "Pages",
        "AdminSettings.razor"));

    private static void AssertGateBeforeMutation(string source, string gate, string mutation)
    {
        var gateIndex = source.IndexOf(gate, StringComparison.Ordinal);
        var mutationIndex = source.IndexOf(mutation, StringComparison.Ordinal);
        Assert.That(gateIndex, Is.GreaterThanOrEqualTo(0), $"Expected gate '{gate}'.");
        Assert.That(mutationIndex, Is.GreaterThan(gateIndex), $"Expected '{gate}' before '{mutation}'.");
    }

    private static string Section(string source, string startMarker, string endMarker)
    {
        var start = source.IndexOf(startMarker, StringComparison.Ordinal);
        Assert.That(start, Is.GreaterThanOrEqualTo(0), $"Could not find '{startMarker}'.");
        var end = source.IndexOf(endMarker, start + startMarker.Length, StringComparison.Ordinal);
        Assert.That(end, Is.GreaterThan(start), $"Could not find '{endMarker}' after '{startMarker}'.");
        return source[start..end];
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Could not locate the HIP repository root.");
    }

    private sealed class RecordingSettingsStore : IExternalSiteEvidenceSettingsStore
    {
        private readonly Dictionary<string, ExternalSiteEvidenceOptions> settings = new(StringComparer.Ordinal);

        public ExternalSiteEvidenceOptions? LastSaved { get; private set; }

        public Task<ExternalSiteEvidenceOptions?> GetAsync(
            string scopeKey,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(settings.TryGetValue(scopeKey, out var options) ? options.Clone() : null);
        }

        public Task<ExternalSiteEvidenceOptions> SaveAsync(
            string scopeKey,
            ExternalSiteEvidenceOptions options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastSaved = options.Clone();
            settings[scopeKey] = LastSaved.Clone();
            return Task.FromResult(LastSaved.Clone());
        }
    }
}
