using System.Text.RegularExpressions;
using HIP.Domain.Risk;
using Microsoft.Extensions.Logging;

namespace HIP.Application.Explanations;

/// <summary>Redacted, structured facts an optional explanation provider may receive.</summary>
public sealed record TrustExplanationRequest(
    int FinalTrustScore,
    int DomainTrustScore,
    int PageTrustScore,
    int ContentRiskScore,
    RiskStatus Status,
    IReadOnlyCollection<string> SignalCodes);

/// <summary>Untrusted text returned by an optional AI or rules-based explanation provider.</summary>
public sealed record TrustExplanationProviderResult(string Explanation, string ProviderName);

public interface ITrustExplanationProvider
{
    Task<TrustExplanationProviderResult?> ExplainAsync(TrustExplanationRequest request, CancellationToken cancellationToken);
}

public interface ITrustExplanationAssistant
{
    Task<TrustExplanationProviderResult?> TryExplainAsync(TrustExplanationRequest request, CancellationToken cancellationToken);
}

/// <summary>Default provider that keeps external explanation assistance disabled.</summary>
public sealed class DisabledTrustExplanationProvider : ITrustExplanationProvider
{
    public Task<TrustExplanationProviderResult?> ExplainAsync(TrustExplanationRequest request, CancellationToken cancellationToken) =>
        Task.FromResult<TrustExplanationProviderResult?>(null);
}

/// <summary>Validates optional provider output and fails back to deterministic HIP explanations.</summary>
public sealed class TrustExplanationAssistant(
    ITrustExplanationProvider provider,
    ILogger<TrustExplanationAssistant>? logger = null) : ITrustExplanationAssistant
{
    private static readonly Regex UrlLikeText = new(@"(?:https?://|www\.)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public async Task<TrustExplanationProviderResult?> TryExplainAsync(TrustExplanationRequest request, CancellationToken cancellationToken)
    {
        ValidateRequest(request);
        try
        {
            var result = await provider.ExplainAsync(request, cancellationToken).ConfigureAwait(false);
            if (result is null) return null;
            if (!IsSafeOutput(result))
            {
                logger?.LogWarning("Rejected unsafe optional trust explanation output from provider {ProviderName}.", SafeProviderName(result.ProviderName));
                return null;
            }

            return result with { Explanation = result.Explanation.Trim(), ProviderName = result.ProviderName.Trim() };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger?.LogWarning(exception, "Optional trust explanation provider failed; HIP retained its deterministic explanation.");
            return null;
        }
    }

    private static void ValidateRequest(TrustExplanationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.FinalTrustScore is < 0 or > 100 || request.DomainTrustScore is < 0 or > 100 ||
            request.PageTrustScore is < 0 or > 100 || request.ContentRiskScore is < 0 or > 100 ||
            request.SignalCodes.Count > 16 || request.SignalCodes.Any(code =>
                string.IsNullOrWhiteSpace(code) || code.Length > 64 ||
                code.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_'))))
        {
            throw new ArgumentException("Trust explanation input must use bounded structured evidence only.", nameof(request));
        }
    }

    private static bool IsSafeOutput(TrustExplanationProviderResult result) =>
        !string.IsNullOrWhiteSpace(result.Explanation) && result.Explanation.Length <= 500 &&
        !result.Explanation.Any(char.IsControl) && !UrlLikeText.IsMatch(result.Explanation) &&
        !string.IsNullOrWhiteSpace(result.ProviderName) && result.ProviderName.Length <= 80 &&
        !result.ProviderName.Any(char.IsControl);

    private static string SafeProviderName(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? "unknown"
            : new string(value.Take(80).Select(character => char.IsControl(character) ? '?' : character).ToArray());
}
