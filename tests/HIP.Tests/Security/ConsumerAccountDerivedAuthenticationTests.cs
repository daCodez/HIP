using System.Net;
using System.Security.Claims;
using System.Text.RegularExpressions;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies local browser accounts receive an isolated, opaque consumer identity on consumer routes.
/// </summary>
public sealed class ConsumerAccountDerivedAuthenticationTests
{
    /// <summary>
    /// Confirms anonymous consumer navigation starts the normal account sign-in flow instead of rendering a concealed 404.
    /// </summary>
    [Test]
    public async Task Anonymous_devices_navigation_redirects_to_normal_login()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = Client(factory);

        using var response = await client.GetAsync("/consumer/devices");

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(
                response.Headers.Location?.ToString(),
                Is.EqualTo("/login?returnUrl=%2Fconsumer%2Fdevices"));
        });
    }

    /// <summary>
    /// Confirms one normal local account sign-in opens Devices without asking for a second identifier.
    /// </summary>
    [Test]
    public async Task Normal_account_login_opens_devices_without_consumer_id_prompt()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = Client(factory);

        using var login = await SubmitAdminLoginAsync(client, "/consumer/devices");
        var devicesHtml = await client.GetStringAsync("/consumer/devices");

        Assert.Multiple(() =>
        {
            Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(login.Headers.Location?.ToString(), Is.EqualTo("/consumer/devices"));
            Assert.That(devicesHtml, Does.Contain(">Devices</h1>"));
            Assert.That(devicesHtml, Does.Contain("aria-label=\"HIP consumer navigation\""));
            Assert.That(devicesHtml, Does.Contain("Your HIP account"));
            Assert.That(devicesHtml, Does.Not.Contain("Local consumer ID"));
            Assert.That(devicesHtml, Does.Not.Contain("aria-label=\"HIP admin navigation\""));
        });
    }

    /// <summary>
    /// Confirms the same authenticated account receives consumer permissions only on consumer routes.
    /// </summary>
    [Test]
    public async Task Account_identity_is_scoped_by_portal_route()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = Client(factory);
        using var login = await SubmitAdminLoginAsync(client, "/admin");

        using var consumerApi = await client.GetAsync("/api/v1/consumer/devices");
        var consumerHtml = await client.GetStringAsync("/consumer/devices");
        var adminHtml = await client.GetStringAsync("/admin");

        Assert.Multiple(() =>
        {
            Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(consumerApi.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(consumerHtml, Does.Contain("aria-label=\"HIP consumer navigation\""));
            Assert.That(consumerHtml, Does.Not.Contain("aria-label=\"HIP admin navigation\""));
            Assert.That(adminHtml, Does.Contain("aria-label=\"HIP admin navigation\""));
            Assert.That(adminHtml, Does.Not.Contain("aria-label=\"HIP consumer navigation\""));
        });
    }

    /// <summary>
    /// Confirms anonymous API clients still receive an authentication failure rather than a browser redirect.
    /// </summary>
    [Test]
    public async Task Anonymous_consumer_api_remains_unauthorized()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = Client(factory);

        using var response = await client.GetAsync("/api/v1/consumer/devices");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    /// <summary>
    /// Confirms Blazor framework requests retain both account claims even though their URL is outside either portal.
    /// </summary>
    [TestCase("/_blazor")]
    [TestCase("/_blazor/negotiate")]
    public async Task Local_account_cookie_keeps_consumer_identity_on_blazor_circuit_routes(string path)
    {
        using var provider = DevelopmentAuthenticationProvider();
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        context.Request.Host = new HostString("localhost");
        context.Request.Path = path;
        context.Request.Headers.Cookie =
            $"{HipDevHeaderAuthenticationHandler.DevAdminRoleCookieName}={AdminRoles.Owner}; " +
            $"{HipDevHeaderAuthenticationHandler.DevAdminUserCookieName}=owner@hip.test";

        var result = await context.AuthenticateAsync(HipDevHeaderAuthenticationHandler.SchemeName);
        var principal = result.Principal;

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(principal, Is.Not.Null);
            Assert.That(principal!.FindAll(HipAuthenticationClaimTypes.ActorId).Count(), Is.EqualTo(1));
            Assert.That(
                principal.FindFirstValue(HipAuthenticationClaimTypes.ActorId),
                Does.Match("^hip-user:v1:[0-9a-f]{64}$").And.Not.Contain("@"));
            Assert.That(principal.FindAll(HipAuthenticationClaimTypes.ConsumerId).Count(), Is.EqualTo(1));
            Assert.That(
                principal.FindFirstValue(HipAuthenticationClaimTypes.AccountContactVerified),
                Is.EqualTo("true"));
            Assert.That(principal.IsInRole(AdminRoles.Owner), Is.True);
            Assert.That(
                principal.FindFirstValue(HipAuthenticationClaimTypes.ConsumerId),
                Does.StartWith("local-account-").And.Not.EqualTo("local-owner-subject"));
        });
    }

    private static ServiceProvider DevelopmentAuthenticationProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IWebHostEnvironment>(new TestWebHostEnvironment());
        services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = HipDevHeaderAuthenticationHandler.SchemeName;
                options.DefaultChallengeScheme = HipDevHeaderAuthenticationHandler.SchemeName;
            })
            .AddScheme<AuthenticationSchemeOptions, HipDevHeaderAuthenticationHandler>(
                HipDevHeaderAuthenticationHandler.SchemeName,
                _ => { });
        return services.BuildServiceProvider();
    }

    private static HttpClient Client(WebApplicationFactory<Program> factory) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = true
        });

    private static async Task<HttpResponseMessage> SubmitAdminLoginAsync(HttpClient client, string returnUrl)
    {
        var html = await client.GetStringAsync($"/login?returnUrl={Uri.EscapeDataString(returnUrl)}");
        var tokenMatch = Regex.Match(
            html,
            "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"",
            RegexOptions.CultureInvariant);
        Assert.That(tokenMatch.Success, Is.True, "The account login form must include an anti-forgery token.");

        return await client.PostAsync("/auth/login", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["email"] = HipWebApplicationFactory<Program>.TestAdminEmail,
                ["password"] = HipWebApplicationFactory<Program>.TestAdminPassword,
                ["returnUrl"] = returnUrl,
                ["__RequestVerificationToken"] = tokenMatch.Groups[1].Value
            }));
    }

    private sealed class TestWebHostEnvironment : IWebHostEnvironment
    {
        public string ApplicationName { get; set; } = "HIP.Tests";
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string WebRootPath { get; set; } = string.Empty;
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ContentRootPath { get; set; } = string.Empty;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
