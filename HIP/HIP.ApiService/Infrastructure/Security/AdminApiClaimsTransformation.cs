using System.Security.Claims;
using HIP.ApiService.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace HIP.ApiService.Infrastructure.Security;

/// <summary>
/// Normalizes provider role/group claims into stable app:role claims for authorization policies.
/// </summary>
public sealed class AdminApiClaimsTransformation(IOptions<AdminApiAuthOptions> optionsAccessor) : IClaimsTransformation
{
    private readonly AdminApiAuthOptions _options = optionsAccessor.Value;

    /// <summary>
    /// Adds normalized app:role claims based on provider role/group claims.
    /// </summary>
    /// <param name="principal">Authenticated principal to normalize.</param>
    /// <returns>The same principal with normalized app claims.</returns>
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity is not ClaimsIdentity identity || !identity.IsAuthenticated)
        {
            return Task.FromResult(principal);
        }

        var existing = identity.FindAll("app:role").Select(c => c.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var source in _options.RoleClaimSources.Where(s => !string.IsNullOrWhiteSpace(s)))
        {
            foreach (var claim in identity.FindAll(source))
            {
                foreach (var raw in claim.Value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    var normalized = Normalize(raw);
                    if (string.IsNullOrWhiteSpace(normalized) || existing.Contains(normalized))
                    {
                        continue;
                    }

                    identity.AddClaim(new Claim("app:role", normalized));
                    existing.Add(normalized);
                }
            }
        }

        return Task.FromResult(principal);
    }

    private static string? Normalize(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (value.Equals("admin", StringComparison.OrdinalIgnoreCase) || value.Equals("hip_admin", StringComparison.OrdinalIgnoreCase)) return "Admin";
        if (value.Equals("support", StringComparison.OrdinalIgnoreCase) || value.Equals("helpdesk", StringComparison.OrdinalIgnoreCase)) return "Support";
        if (value.Equals("analyst", StringComparison.OrdinalIgnoreCase) || value.Equals("security_analyst", StringComparison.OrdinalIgnoreCase)) return "Analyst";
        return value.Trim();
    }
}
