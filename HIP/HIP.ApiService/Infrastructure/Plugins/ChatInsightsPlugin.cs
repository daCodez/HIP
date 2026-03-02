using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using HIP.ApiService.Infrastructure.Persistence;
using HIP.Plugins.Abstractions.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// Plugin exposing AI chat over HIP data using mock/api/oauth provider modes.
/// </summary>
public sealed class ChatInsightsPlugin : IHipPlugin
{
    /// <inheritdoc />
    public HipPluginManifest Manifest { get; } = new(
        Id: "core.chat.insights",
        Version: "1.0.0",
        Capabilities: ["chat.query"],
        Description: "Chat over HIP audit/risk data with configurable provider auth mode.",
        NavItems:
        [
            new HipPluginNavItem("AI Chat", "/chat", "fa-comments", 34, "chat.query", "page")
        ]);

    /// <inheritdoc />
    public void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        services.AddHttpClient();
        services.AddSingleton<ChatOAuthStateStore>();
        services.AddSingleton<ChatOAuthTokenStore>();
        services.AddScoped<InsightsChatService>();
    }

    /// <inheritdoc />
    public void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment)
    {
        endpoints.MapGet("/api/plugins/chat/providers", () =>
            Results.Ok(new
            {
                mode = configuration["HIP:Chat:Mode"] ?? "mock",
                supports = new[] { "mock", "api", "oauth" }
            }))
            .WithName("GetChatProviders")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status200OK);

        endpoints.MapGet("/api/plugins/chat/oauth/status", (ChatOAuthTokenStore tokenStore) =>
            {
                var (token, expires) = tokenStore.Get();
                return Results.Ok(new { connected = !string.IsNullOrWhiteSpace(token), expiresAtUtc = expires });
            })
            .WithName("GetChatOAuthStatus")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status200OK);

        endpoints.MapGet("/api/plugins/chat/oauth/start", (IConfiguration cfg, ChatOAuthStateStore stateStore) =>
            {
                var authUrl = cfg["HIP:Chat:OAuthAuthorizeUrl"];
                var clientId = cfg["HIP:Chat:OAuthClientId"];
                var redirectUri = cfg["HIP:Chat:OAuthRedirectUri"];
                var scope = cfg["HIP:Chat:OAuthScope"] ?? "";

                if (string.IsNullOrWhiteSpace(authUrl) || string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri))
                {
                    return Results.BadRequest(new { code = "chat.oauth.notConfigured" });
                }

                var state = stateStore.Create();
                var url = $"{authUrl}?response_type=code&client_id={Uri.EscapeDataString(clientId)}&redirect_uri={Uri.EscapeDataString(redirectUri)}&scope={Uri.EscapeDataString(scope)}&state={Uri.EscapeDataString(state)}";
                return Results.Ok(new { authorizeUrl = url, state });
            })
            .WithName("StartChatOAuth")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest);

        endpoints.MapGet("/api/plugins/chat/oauth/callback", async (
                string? code,
                string? state,
                IConfiguration cfg,
                IHttpClientFactory httpFactory,
                ChatOAuthStateStore stateStore,
                ChatOAuthTokenStore tokenStore,
                CancellationToken ct) =>
            {
                if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(state) || !stateStore.Consume(state))
                {
                    return Results.BadRequest(new { code = "chat.oauth.invalidCallback" });
                }

                var tokenUrl = cfg["HIP:Chat:OAuthTokenUrl"];
                var clientId = cfg["HIP:Chat:OAuthClientId"];
                var clientSecret = cfg["HIP:Chat:OAuthClientSecret"];
                var redirectUri = cfg["HIP:Chat:OAuthRedirectUri"];
                var successRedirect = cfg["HIP:Chat:OAuthSuccessRedirect"] ?? "/chat";

                if (string.IsNullOrWhiteSpace(tokenUrl) || string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret) || string.IsNullOrWhiteSpace(redirectUri))
                {
                    return Results.BadRequest(new { code = "chat.oauth.notConfigured" });
                }

                var client = httpFactory.CreateClient();
                using var form = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code",
                    ["code"] = code,
                    ["redirect_uri"] = redirectUri,
                    ["client_id"] = clientId,
                    ["client_secret"] = clientSecret
                });

                using var resp = await client.PostAsync(tokenUrl, form, ct);
                var body = await resp.Content.ReadAsStringAsync(ct);
                if (!resp.IsSuccessStatusCode)
                {
                    return Results.BadRequest(new { code = "chat.oauth.exchangeFailed", providerBody = body });
                }

                using var doc = JsonDocument.Parse(body);
                var accessToken = doc.RootElement.TryGetProperty("access_token", out var t) ? t.GetString() : null;
                var expiresIn = doc.RootElement.TryGetProperty("expires_in", out var e) && e.TryGetInt32(out var secs) ? secs : 3600;
                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    return Results.BadRequest(new { code = "chat.oauth.noAccessToken" });
                }

                tokenStore.Set(accessToken, DateTimeOffset.UtcNow.AddSeconds(expiresIn));
                return Results.Redirect(successRedirect);
            })
            .WithName("ChatOAuthCallback")
            .WithTags("Plugins");

        endpoints.MapPost("/api/plugins/chat/query", async (ChatQueryRequest request, InsightsChatService service, CancellationToken ct) =>
            {
                if (string.IsNullOrWhiteSpace(request.Question))
                {
                    return Results.BadRequest(new { code = "chat.questionRequired" });
                }

                var result = await service.QueryAsync(request.Question, ct);
                return Results.Ok(result);
            })
            .WithName("QueryChatInsights")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest);
    }

    /// <summary>Chat query payload.</summary>
    public sealed record ChatQueryRequest(string Question);

    private sealed class InsightsChatService(HipDbContext db, IConfiguration config, IHttpClientFactory httpFactory, ChatOAuthTokenStore tokenStore)
    {
        public async Task<object> QueryAsync(string question, CancellationToken cancellationToken)
        {
            var recentRows = await db.AuditEvents.AsNoTracking()
                .Select(x => new { x.CreatedAtUtc, x.EventType, x.Subject, x.Outcome, x.ReasonCode })
                .ToListAsync(cancellationToken);

            var recent = recentRows
                .OrderByDescending(x => x.CreatedAtUtc)
                .Take(25)
                .ToList();

            var context = new
            {
                summary = new
                {
                    totalEvents = recent.Count,
                    blocked = recent.Count(x => string.Equals(x.Outcome, "block", StringComparison.OrdinalIgnoreCase)),
                    review = recent.Count(x => string.Equals(x.Outcome, "review", StringComparison.OrdinalIgnoreCase))
                },
                recent
            };

            var mode = (config["HIP:Chat:Mode"] ?? "mock").ToLowerInvariant();
            if (mode == "mock")
            {
                return new
                {
                    mode,
                    answer = $"From the latest {recent.Count} events: {context.summary.blocked} blocked, {context.summary.review} review. Ask a narrower question for deeper analysis.",
                    context
                };
            }

            var endpoint = config["HIP:Chat:Endpoint"];
            if (string.IsNullOrWhiteSpace(endpoint))
            {
                return new { mode, answer = "Chat endpoint is not configured (HIP:Chat:Endpoint).", context };
            }

            var client = httpFactory.CreateClient();
            var storedOAuth = tokenStore.Get().AccessToken;
            var token = mode == "oauth"
                ? (string.IsNullOrWhiteSpace(storedOAuth) ? config["HIP:Chat:OAuthAccessToken"] : storedOAuth)
                : config["HIP:Chat:ApiKey"];

            if (!string.IsNullOrWhiteSpace(token))
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }

            var payload = JsonSerializer.Serialize(new { question, context });
            using var response = await client.PostAsync(endpoint, new StringContent(payload, Encoding.UTF8, "application/json"), cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                return new { mode, answer = $"Provider call failed ({(int)response.StatusCode}).", providerBody = body, context };
            }

            var answer = ExtractAnswer(body);
            return new { mode, answer, context };
        }

        private static string ExtractAnswer(string json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("answer", out var a)) return a.GetString() ?? json;
                if (doc.RootElement.TryGetProperty("content", out var c)) return c.GetString() ?? json;
            }
            catch
            {
            }

            return json;
        }
    }
}
