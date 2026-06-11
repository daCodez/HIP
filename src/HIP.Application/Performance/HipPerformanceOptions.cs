namespace HIP.Application.Performance;

/// <summary>
/// Configures HIP's framework-level performance protections for public hot-path endpoints.
/// </summary>
/// <remarks>
/// These values intentionally control infrastructure behavior such as output-cache duration and public
/// request limits. They do not change trust scoring decisions, which remain in dedicated scoring and
/// evidence services.
/// </remarks>
public sealed class HipPerformanceOptions
{
    /// <summary>
    /// Configuration section name used by hosts to bind HIP performance options.
    /// </summary>
    public const string SectionName = "HipPerformance";

    /// <summary>
    /// Gets or sets whether HIP should use Aspire-provided Redis for output caching when a Redis connection exists.
    /// </summary>
    public bool UseRedisOutputCacheWhenAvailable { get; set; } = true;

    /// <summary>
    /// Gets or sets the public lookup cache lifetime in seconds.
    /// </summary>
    public int PublicLookupCacheSeconds { get; set; } = 30;

    /// <summary>
    /// Gets or sets the live badge data and script cache lifetime in seconds.
    /// </summary>
    public int BadgeCacheSeconds { get; set; } = 60;

    /// <summary>
    /// Gets or sets the safety evaluation cache lifetime in seconds for future idempotent safety reads.
    /// </summary>
    public int SafetyCacheSeconds { get; set; } = 10;

    /// <summary>
    /// Gets or sets the site-safety read cache lifetime in seconds for future GET-style score endpoints.
    /// </summary>
    public int SiteSafetyCacheSeconds { get; set; } = 15;

    /// <summary>
    /// Gets or sets the maximum public scan submissions accepted per partition per minute.
    /// </summary>
    public int PublicScanRequestsPerMinute { get; set; } = 60;

    /// <summary>
    /// Gets or sets the maximum public feedback/report submissions accepted per partition per minute.
    /// </summary>
    public int PublicFeedbackRequestsPerMinute { get; set; } = 30;

    /// <summary>
    /// Gets or sets the maximum development identity helper submissions accepted per partition per minute.
    /// </summary>
    public int IdentityRequestsPerMinute { get; set; } = 10;
}

/// <summary>
/// Names HIP output-cache policies so public endpoints can opt into Redis-backed caching consistently.
/// </summary>
public static class HipOutputCachePolicies
{
    /// <summary>
    /// Cache policy for public domain lookup responses.
    /// </summary>
    public const string PublicLookup = "HipPublicLookup";

    /// <summary>
    /// Cache policy for live trust badge data and badge scripts.
    /// </summary>
    public const string Badge = "HipBadge";

    /// <summary>
    /// Cache policy reserved for future idempotent safety evaluation responses.
    /// </summary>
    public const string Safety = "HipSafety";

    /// <summary>
    /// Cache policy reserved for future idempotent site-safety score responses.
    /// </summary>
    public const string SiteSafety = "HipSiteSafety";
}
