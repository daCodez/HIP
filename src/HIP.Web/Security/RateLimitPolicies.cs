namespace HIP.Web.Security;

/// <summary>
/// Names HIP's baseline ASP.NET Core rate-limit policies for public write-heavy endpoints.
/// </summary>
public static class RateLimitPolicies
{
    /// <summary>
    /// Limits unauthenticated browser and site-safety scan writes until signed client trust is implemented.
    /// </summary>
    public const string PublicScanPolicy = "PublicScanPolicy";

    /// <summary>
    /// Limits public feedback and report writes to reduce spam, abuse, and review-queue flooding.
    /// </summary>
    public const string PublicFeedbackPolicy = "PublicFeedbackPolicy";

    /// <summary>
    /// Limits development-only identity and admin-login helpers so local testing cannot accidentally flood key creation.
    /// </summary>
    public const string IdentityDevPolicy = "IdentityDevPolicy";

    /// <summary>
    /// Limits local administrator password attempts independently from other development tools.
    /// </summary>
    public const string AdminLoginPolicy = "AdminLoginPolicy";
}
