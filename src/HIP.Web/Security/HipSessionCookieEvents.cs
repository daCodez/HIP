using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace HIP.Web.Security;

/// <summary>Enforces HIP's idle and hard absolute session bounds and API-safe cookie responses.</summary>
public sealed class HipSessionCookieEvents(
    IOptions<HipProductionAuthenticationOptions> configuredOptions,
    TimeProvider timeProvider) : CookieAuthenticationEvents
{
    private readonly HipProductionAuthenticationOptions options =
        configuredOptions?.Value ?? throw new ArgumentNullException(nameof(configuredOptions));
    private readonly TimeProvider timeProvider =
        timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <inheritdoc />
    public override Task ValidatePrincipal(CookieValidatePrincipalContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var now = timeProvider.GetUtcNow();
        if (!HipSessionAuthenticationProperties.TryGetAbsoluteExpiry(context.Properties, out var absoluteExpiry) ||
            absoluteExpiry <= now ||
            context.Properties.IssuedUtc is not { } issuedUtc ||
            context.Properties.ExpiresUtc is not { } expiresUtc ||
            expiresUtc <= now)
        {
            context.RejectPrincipal();
            return Task.CompletedTask;
        }

        var renewalDue = now - issuedUtc >= TimeSpan.FromTicks(options.IdleSessionLifetime.Ticks / 2);
        var exceedsAbsoluteExpiry = expiresUtc > absoluteExpiry;
        if (renewalDue || exceedsAbsoluteExpiry)
        {
            var idleExpiry = now.Add(options.IdleSessionLifetime);
            var renewedExpiry = idleExpiry < absoluteExpiry ? idleExpiry : absoluteExpiry;
            if (renewedExpiry <= now)
            {
                context.RejectPrincipal();
                return Task.CompletedTask;
            }

            context.Properties.IssuedUtc = now;
            context.Properties.ExpiresUtc = renewedExpiry;
            context.ShouldRenew = true;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public override Task RedirectToLogin(RedirectContext<CookieAuthenticationOptions> context) =>
        ApiStatusOrRedirect(context, StatusCodes.Status401Unauthorized, base.RedirectToLogin);

    /// <inheritdoc />
    public override Task RedirectToAccessDenied(RedirectContext<CookieAuthenticationOptions> context) =>
        ApiStatusOrRedirect(context, StatusCodes.Status403Forbidden, base.RedirectToAccessDenied);

    private static Task ApiStatusOrRedirect(
        RedirectContext<CookieAuthenticationOptions> context,
        int apiStatusCode,
        Func<RedirectContext<CookieAuthenticationOptions>, Task> redirect)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = apiStatusCode;
            return Task.CompletedTask;
        }

        return redirect(context);
    }
}

/// <summary>Stores the encrypted hard session expiry inside cookie authentication properties.</summary>
internal static class HipSessionAuthenticationProperties
{
    private const string AbsoluteExpiryKey = ".hip.absolute_expires_utc_ticks";

    public static void SetAbsoluteExpiry(AuthenticationProperties properties, DateTimeOffset absoluteExpiry) =>
        properties.Items[AbsoluteExpiryKey] = absoluteExpiry.UtcTicks.ToString(CultureInfo.InvariantCulture);

    public static bool TryGetAbsoluteExpiry(
        AuthenticationProperties properties,
        out DateTimeOffset absoluteExpiry)
    {
        if (properties.Items.TryGetValue(AbsoluteExpiryKey, out var rawValue) &&
            long.TryParse(rawValue, NumberStyles.None, CultureInfo.InvariantCulture, out var ticks) &&
            ticks >= DateTimeOffset.MinValue.Ticks &&
            ticks <= DateTimeOffset.MaxValue.Ticks)
        {
            absoluteExpiry = new DateTimeOffset(ticks, TimeSpan.Zero);
            return true;
        }

        absoluteExpiry = default;
        return false;
    }
}
