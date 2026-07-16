using System.Net;

namespace HIP.Web.Security;

/// <summary>
/// Centralizes HIP's local-development trust boundary for dev-only authentication and crypto endpoints.
/// </summary>
public static class LocalDevelopmentRequestGuard
{
    private static readonly string[] ForwardingHeaderNames =
    [
        "Forwarded",
        "X-Forwarded-For",
        "X-Real-IP"
    ];

    /// <summary>
    /// Determines whether a request is running under Development and originated entirely on loopback.
    /// </summary>
    /// <param name="request">Current HTTP request.</param>
    /// <param name="environment">Hosting environment.</param>
    /// <returns>True only for direct loopback Development requests.</returns>
    /// <remarks>
    /// Dev headers and dev cookies are intentionally powerful during local testing. They must never work for
    /// a non-local peer, a non-local host, or a forwarded request, even if a deployment is accidentally started
    /// with ASPNETCORE_ENVIRONMENT=Development.
    /// </remarks>
    public static bool IsLocalDevelopmentRequest(HttpRequest request, IWebHostEnvironment environment)
    {
        if (!environment.IsDevelopment() ||
            !IsLocalHost(request.Host.Host) ||
            HasForwardingHeaders(request))
        {
            return false;
        }

        var remoteAddress = request.HttpContext.Connection.RemoteIpAddress;
        return remoteAddress is not null && IPAddress.IsLoopback(remoteAddress);
    }

    /// <summary>
    /// Checks whether the supplied host value is a loopback hostname or loopback IP address.
    /// </summary>
    /// <param name="host">Request host without the port.</param>
    /// <returns>True for localhost, 127.0.0.1, and ::1-style loopback hosts.</returns>
    public static bool IsLocalHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        var normalized = host.Trim().Trim('[', ']');
        if (normalized.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            normalized.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
            normalized.Equals("::1", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IPAddress.TryParse(normalized, out var address) && IPAddress.IsLoopback(address);
    }

    private static bool HasForwardingHeaders(HttpRequest request) =>
        ForwardingHeaderNames.Any(request.Headers.ContainsKey);
}
