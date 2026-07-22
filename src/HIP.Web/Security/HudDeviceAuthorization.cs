using System.Text.Json;
using HIP.Application.SecondLife;
using Microsoft.AspNetCore.Authorization;

namespace HIP.Web.Security;

/// <summary>
/// Named authorization policies used by Second Life HUD device endpoints.
/// </summary>
public static class HudPolicies
{
    public const string CanUseActiveDevice = nameof(CanUseActiveDevice);
    public const string DeviceCredentialHeader = "X-HIP-HUD-Credential";
}

/// <summary>
/// Carries the validated license/device binding from authorization into the endpoint without trusting request data again.
/// </summary>
public static class HudDeviceAuthorizationContext
{
    private static readonly object ValidatedBindingKey = new();

    internal static void SetValidatedBinding(HttpContext httpContext, string licenseId, string deviceId) =>
        httpContext.Items[ValidatedBindingKey] = new ValidatedHudDeviceBinding(licenseId, deviceId);

    public static string GetRequiredLicenseId(HttpContext httpContext) =>
        httpContext.Items.TryGetValue(ValidatedBindingKey, out var value) && value is ValidatedHudDeviceBinding binding
            ? binding.LicenseId
            : throw new InvalidOperationException("The HUD device binding was not authorized.");

    private sealed record ValidatedHudDeviceBinding(string LicenseId, string DeviceId);
}

/// <summary>
/// Identifies where an endpoint carries the HUD device ID that its credential must authorize.
/// </summary>
public enum HudDeviceIdentifierLocation
{
    Route,
    JsonBody
}

/// <summary>
/// Describes how the HUD authorization handler resolves an endpoint's device ID.
/// </summary>
/// <param name="Location">Request location containing the identifier.</param>
/// <param name="Name">Route value or top-level JSON property name.</param>
public sealed record HudDeviceAuthorizationMetadata(
    HudDeviceIdentifierLocation Location,
    string Name);

/// <summary>
/// Requires a valid device-bound credential whose linked license remains active.
/// </summary>
public sealed class ActiveHudDeviceRequirement : IAuthorizationRequirement
{
}

/// <summary>
/// Authorizes HUD calls without treating a public device ID as identity or trusting client body fields alone.
/// </summary>
public sealed class ActiveHudDeviceRequirementHandler(
    IHudDeviceCredentialService credentialService,
    ISetupCodeLicenseService licenseService)
    : AuthorizationHandler<ActiveHudDeviceRequirement>
{
    private const int MaximumAuthorizationBodyBytes = 64 * 1024;
    private const int MemoryBufferThresholdBytes = 16 * 1024;

    /// <inheritdoc />
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ActiveHudDeviceRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requirement);

        if (context.Resource is not HttpContext httpContext ||
            httpContext.GetEndpoint()?.Metadata.GetMetadata<HudDeviceAuthorizationMetadata>() is not { } metadata)
        {
            return;
        }

        var credential = httpContext.Request.Headers[HudPolicies.DeviceCredentialHeader].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(credential) || credential.Length > 256)
        {
            return;
        }

        var deviceId = metadata.Location switch
        {
            HudDeviceIdentifierLocation.Route => ResolveRouteDeviceId(httpContext, metadata.Name),
            HudDeviceIdentifierLocation.JsonBody => await ResolveBodyDeviceIdAsync(httpContext, metadata.Name),
            _ => null
        };

        if (string.IsNullOrWhiteSpace(deviceId) || deviceId.Length > 128)
        {
            return;
        }

        try
        {
            var licenseId = credentialService.ValidateAndGetLicenseId(deviceId, credential);
            if (licenseId is not null &&
                await licenseService.IsActiveDeviceAsync(licenseId, deviceId, httpContext.RequestAborted))
            {
                HudDeviceAuthorizationContext.SetValidatedBinding(httpContext, licenseId, deviceId);
                context.Succeed(requirement);
            }
        }
        catch (ArgumentException)
        {
            // Malformed untrusted identifiers fail authorization without reaching the endpoint.
        }
    }

    private static string? ResolveRouteDeviceId(HttpContext httpContext, string routeValueName) =>
        httpContext.Request.RouteValues.TryGetValue(routeValueName, out var routeValue)
            ? Convert.ToString(routeValue)
            : null;

    private static async Task<string?> ResolveBodyDeviceIdAsync(HttpContext httpContext, string propertyName)
    {
        var request = httpContext.Request;
        if (request.ContentLength is > MaximumAuthorizationBodyBytes)
        {
            return null;
        }

        try
        {
            request.EnableBuffering(MemoryBufferThresholdBytes, MaximumAuthorizationBodyBytes);
            using var document = await JsonDocument.ParseAsync(
                request.Body,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 8
                },
                httpContext.RequestAborted);

            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            string? deviceId = null;
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (!string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (deviceId is not null || property.Value.ValueKind != JsonValueKind.String)
                {
                    return null;
                }

                deviceId = property.Value.GetString();
            }

            return deviceId;
        }
        catch (JsonException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
        finally
        {
            if (request.Body.CanSeek)
            {
                request.Body.Position = 0;
            }
        }
    }
}
