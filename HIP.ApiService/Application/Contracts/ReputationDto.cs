namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Reputation payload returned by HIP reputation endpoints.
/// </summary>
/// <param name="IdentityId">Identity identifier for this score.</param>
/// <param name="Score">Current computed reputation score.</param>
/// <param name="UtcTimestamp">UTC timestamp when score snapshot was produced.</param>
public sealed record ReputationDto(string IdentityId, int Score, DateTimeOffset UtcTimestamp);
