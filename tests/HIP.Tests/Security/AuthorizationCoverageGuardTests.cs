extern alias ApiServiceAlias;

using System.Text;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests.Security;

[TestFixture]
public sealed class AuthorizationCoverageGuardTests
{
    [Test]
    public async Task Every_routable_web_surface_has_one_explicit_named_access_classification()
    {
        var assembly = typeof(Program).Assembly;
        var razorComponents = assembly.GetTypes()
            .Where(type => typeof(IComponent).IsAssignableFrom(type))
            .Select(type => new RazorSurface(
                type,
                type.GetCustomAttributes(typeof(RouteAttribute), inherit: false)
                    .Cast<RouteAttribute>()
                    .Select(attribute => NormalizeRoute(attribute.Template))
                    .OrderBy(route => route, StringComparer.Ordinal)
                    .ToArray(),
                type.GetCustomAttributes(typeof(AuthorizeAttribute), inherit: false)
                    .Cast<IAuthorizeData>()
                    .ToArray(),
                type.GetCustomAttributes(inherit: false)
                    .OfType<IAllowAnonymous>()
                    .Any()))
            .Where(component => component.Routes.Length > 0)
            .OrderBy(component => component.Type.FullName, StringComparer.Ordinal)
            .ToArray();

        await using var factory = new HipWebApplicationFactory<Program>();
        var httpEndpoints = InspectHttpEndpoints(
            factory.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>());

        var categories = new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal)
        {
            ["Razor routes missing classification"] = razorComponents
                .Where(component => component.Authorization.Length == 0 && !component.AllowsAnonymous)
                .Select(Describe)
                .ToArray(),
            ["Razor routes combining authorization and AllowAnonymous"] = razorComponents
                .Where(component => component.Authorization.Length > 0 && component.AllowsAnonymous)
                .Select(Describe)
                .ToArray(),
            ["Razor routes using unnamed authorization"] = razorComponents
                .Where(component => component.Authorization.Any(IsUnnamed))
                .Select(Describe)
                .ToArray(),
            ["HTTP endpoints missing classification"] = httpEndpoints
                .Where(item => item.Authorization.Length == 0 && !item.AllowsAnonymous)
                .Select(item => Describe(item.Endpoint))
                .ToArray(),
            ["HTTP endpoints combining authorization and AllowAnonymous"] = httpEndpoints
                .Where(item => item.Authorization.Length > 0 && item.AllowsAnonymous)
                .Select(item => Describe(item.Endpoint))
                .ToArray(),
            ["HTTP endpoints using unnamed authorization"] = httpEndpoints
                .Where(item => item.Authorization.Any(IsUnnamed))
                .Select(item => Describe(item.Endpoint))
                .ToArray()
        };

        var violationCount = categories.Sum(category => category.Value.Count);
        Assert.That(
            violationCount,
            Is.Zero,
            BuildReport(razorComponents.Length, httpEndpoints.Length, categories));
    }

    /// <summary>
    /// Prevents the standalone Aspire API host from adding an endpoint without an explicit public or named-policy boundary.
    /// </summary>
    [Test]
    public async Task Every_api_service_http_endpoint_has_an_explicit_named_access_classification()
    {
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        var httpEndpoints = InspectHttpEndpoints(
            factory.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>());

        var categories = new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal)
        {
            ["API service endpoints missing classification"] = httpEndpoints
                .Where(item => item.Authorization.Length == 0 && !item.AllowsAnonymous)
                .Select(item => Describe(item.Endpoint))
                .ToArray(),
            ["API service endpoints combining authorization and AllowAnonymous"] = httpEndpoints
                .Where(item => item.Authorization.Length > 0 && item.AllowsAnonymous)
                .Select(item => Describe(item.Endpoint))
                .ToArray(),
            ["API service endpoints using unnamed authorization"] = httpEndpoints
                .Where(item => item.Authorization.Any(IsUnnamed))
                .Select(item => Describe(item.Endpoint))
                .ToArray()
        };

        Assert.That(
            categories.Sum(category => category.Value.Count),
            Is.Zero,
            BuildApiServiceReport(httpEndpoints.Length, categories));
    }

    /// <summary>
    /// Proves an application endpoint cannot bypass the guard merely by using a route outside legacy prefixes.
    /// </summary>
    [Test]
    public void Unmarked_http_endpoint_outside_legacy_prefix_is_reported()
    {
        var endpoint = CreateSyntheticEndpoint("/outside-prefix");

        var missing = InspectHttpEndpoints([endpoint])
            .Where(item => item.Authorization.Length == 0 && !item.AllowsAnonymous)
            .Select(item => Describe(item.Endpoint))
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(missing, Has.Length.EqualTo(1));
            Assert.That(missing[0], Does.Contain("/outside-prefix"));
        });
    }

    /// <summary>
    /// Proves only an explicitly typed framework-generated endpoint is excluded from HTTP authorization inventory.
    /// </summary>
    [Test]
    public void Typed_framework_generated_endpoint_is_excluded()
    {
        var endpoint = CreateSyntheticEndpoint(
            "/framework-generated",
            HipFrameworkGeneratedEndpointMetadata.StaticAssets);

        var inspected = InspectHttpEndpoints([endpoint]);

        Assert.That(inspected, Is.Empty);
    }

    private static HttpSurface[] InspectHttpEndpoints(IEnumerable<RouteEndpoint> endpoints) =>
        endpoints
            .Where(endpoint => !IsFrameworkGeneratedEndpoint(endpoint))
            .Select(endpoint => new HttpSurface(
                endpoint,
                // Endpoint metadata includes conventions inherited from route groups and endpoint builders.
                endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>().ToArray(),
                endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null))
            .OrderBy(item => NormalizeRoute(item.Endpoint.RoutePattern.RawText), StringComparer.Ordinal)
            .ThenBy(item => HttpMethods(item.Endpoint), StringComparer.Ordinal)
            .ToArray();

    private static bool IsFrameworkGeneratedEndpoint(RouteEndpoint endpoint)
    {
        if (endpoint.Metadata.GetMetadata<HipFrameworkGeneratedEndpointMetadata>() is not null)
        {
            return true;
        }

        // .NET's static-web-assets data source adds this single file fallback outside the
        // convention builder returned by MapStaticAssets, so custom metadata cannot reach it.
        // Keep the exception exact; an application fallback at any other route still fails closed.
        return endpoint.Metadata.Any(item => string.Equals(
                   item.GetType().FullName,
                   "Microsoft.AspNetCore.Routing.FallbackMetadata",
                   StringComparison.Ordinal)) &&
               string.Equals(NormalizeRoute(endpoint.RoutePattern.RawText), "/{**path:file}", StringComparison.Ordinal) &&
               string.Equals(endpoint.DisplayName, "Fallback {**path:file}", StringComparison.Ordinal) &&
               string.Equals(HttpMethods(endpoint), "GET,HEAD", StringComparison.Ordinal);
    }

    private static RouteEndpoint CreateSyntheticEndpoint(string route, params object[] metadata)
    {
        var builder = new RouteEndpointBuilder(
            _ => Task.CompletedTask,
            RoutePatternFactory.Parse(route),
            order: 0)
        {
            DisplayName = $"Synthetic endpoint {route}"
        };
        builder.Metadata.Add(new HttpMethodMetadata([Microsoft.AspNetCore.Http.HttpMethods.Get]));
        foreach (var item in metadata)
        {
            builder.Metadata.Add(item);
        }

        return (RouteEndpoint)builder.Build();
    }

    private static bool IsUnnamed(IAuthorizeData authorization) =>
        string.IsNullOrWhiteSpace(authorization.Policy);

    private static string NormalizeRoute(string? route)
    {
        if (string.IsNullOrWhiteSpace(route))
        {
            return "/";
        }

        return route.StartsWith('/') ? route : $"/{route}";
    }

    private static string Describe(RazorSurface component) =>
        $"{component.Type.FullName}: {string.Join(", ", component.Routes)}";

    private static string Describe(RouteEndpoint endpoint) =>
        $"{HttpMethods(endpoint)} {NormalizeRoute(endpoint.RoutePattern.RawText)} ({endpoint.DisplayName}; " +
        $"metadata: {string.Join(", ", endpoint.Metadata.Select(item => item.GetType().FullName).Distinct())})";

    private static string HttpMethods(RouteEndpoint endpoint) =>
        endpoint.Metadata.GetMetadata<HttpMethodMetadata>() is { HttpMethods.Count: > 0 } methods
            ? string.Join(',', methods.HttpMethods.OrderBy(method => method, StringComparer.Ordinal))
            : "*";

    private static string BuildReport(
        int razorRouteCount,
        int httpEndpointCount,
        IReadOnlyDictionary<string, IReadOnlyCollection<string>> categories)
    {
        var report = new StringBuilder()
            .AppendLine($"Routable Razor components inspected: {razorRouteCount}")
            .AppendLine($"App-owned HTTP endpoints inspected: {httpEndpointCount}");

        foreach (var category in categories)
        {
            report.AppendLine().AppendLine($"{category.Key} ({category.Value.Count}):");
            if (category.Value.Count == 0)
            {
                report.AppendLine("  <none>");
                continue;
            }

            foreach (var item in category.Value)
            {
                report.Append("  - ").AppendLine(item);
            }
        }

        return report.ToString();
    }

    private static string BuildApiServiceReport(
        int httpEndpointCount,
        IReadOnlyDictionary<string, IReadOnlyCollection<string>> categories)
    {
        var report = new StringBuilder()
            .AppendLine($"API service HTTP endpoints inspected: {httpEndpointCount}");

        foreach (var category in categories)
        {
            report.AppendLine().AppendLine($"{category.Key} ({category.Value.Count}):");
            if (category.Value.Count == 0)
            {
                report.AppendLine("  <none>");
                continue;
            }

            foreach (var item in category.Value)
            {
                report.Append("  - ").AppendLine(item);
            }
        }

        return report.ToString();
    }

    private sealed record RazorSurface(
        Type Type,
        string[] Routes,
        IAuthorizeData[] Authorization,
        bool AllowsAnonymous);

    private sealed record HttpSurface(
        RouteEndpoint Endpoint,
        IAuthorizeData[] Authorization,
        bool AllowsAnonymous);
}
