using System.Security.Claims;
using HIP.Admin.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace HIP.Admin.Services;

/// <summary>
/// Normalizes provider-specific role/group claims into stable app claims.
/// </summary>
public sealed class AdminClaimsTransformation(IOptions<AdminAuthOptions> optionsAccessor) : IClaimsTransformation
{
    private const string AppRoleClaim = "app:role";
    private readonly AdminAuthOptions _options = optionsAccessor.Value;

    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity is not ClaimsIdentity identity || !identity.IsAuthenticated)
        {
            return Task.FromResult(principal);
        }

        var existing = identity.FindAll(AppRoleClaim).Select(c => c.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var source in _options.RoleClaimSources.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            foreach (var claim in identity.FindAll(source))
            {
                foreach (var value in ExpandClaimValues(claim.Value))
                {
                    var normalized = NormalizeRole(value);
                    if (string.IsNullOrWhiteSpace(normalized) || existing.Contains(normalized))
                    {
                        continue;
                    }

                    identity.AddClaim(new Claim(AppRoleClaim, normalized));
                    existing.Add(normalized);
                }
            }
        }

        return Task.FromResult(principal);
    }

    private static IEnumerable<string> ExpandClaimValues(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            yield break;
        }

        foreach (var split in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            yield return split;
        }
    }

    private static string? NormalizeRole(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var value = raw.Trim();
        if (value.Equals("admin", StringComparison.OrdinalIgnoreCase) || value.Equals("hip_admin", StringComparison.OrdinalIgnoreCase))
        {
            return "Admin";
        }

        if (value.Equals("support", StringComparison.OrdinalIgnoreCase) || value.Equals("helpdesk", StringComparison.OrdinalIgnoreCase))
        {
            return "Support";
        }

        if (value.Equals("analyst", StringComparison.OrdinalIgnoreCase) || value.Equals("security_analyst", StringComparison.OrdinalIgnoreCase))
        {
            return "Analyst";
        }

        return value;
    }
}
