using FluentValidation;

namespace HIP.Application.SiteSafety;

/// <summary>
/// Validates Site Safety Scan input before any network or scoring work is attempted.
/// </summary>
public sealed class SiteSafetyScanValidator : AbstractValidator<SiteSafetyScanRequest>
{
    /// <summary>
    /// Creates URL and signal validation rules that block unsafe targets by default.
    /// </summary>
    public SiteSafetyScanValidator()
    {
        RuleFor(request => request.Url)
            .NotEmpty()
            .MaximumLength(2048)
            .Must(BeSafeHttpUrl)
            .WithMessage("A public HTTP or HTTPS URL is required.");

        RuleFor(request => request.ObservedSignals!.InlineScriptCount)
            .GreaterThanOrEqualTo(0)
            .When(request => request.ObservedSignals is not null);

        RuleFor(request => request.ObservedSignals!.SuspiciousScriptPatternCount)
            .GreaterThanOrEqualTo(0)
            .When(request => request.ObservedSignals is not null);

        RuleFor(request => request.ObservedSignals!.KnownAbuseReports)
            .GreaterThanOrEqualTo(0)
            .When(request => request.ObservedSignals is not null);

        RuleForEach(request => request.ObservedSignals!.DownloadLinks)
            .MaximumLength(2048)
            .Must(SiteSafetyObservedSignalSanitizer.IsSafePublicHttpUrl)
            .WithMessage("Observed download URLs must be public HTTP or HTTPS URLs.")
            .When(request => request.ObservedSignals?.DownloadLinks is not null);

        RuleForEach(request => request.ObservedSignals!.RedirectChain)
            .MaximumLength(2048)
            .Must(SiteSafetyObservedSignalSanitizer.IsSafePublicHttpUrl)
            .WithMessage("Observed redirect URLs must be public HTTP or HTTPS URLs.")
            .When(request => request.ObservedSignals?.RedirectChain is not null);

        RuleForEach(request => request.ObservedSignals!.ExternalScriptUrls)
            .MaximumLength(2048)
            .Must(SiteSafetyObservedSignalSanitizer.IsSafePublicHttpUrl)
            .WithMessage("Observed script URLs must be public HTTP or HTTPS URLs.")
            .When(request => request.ObservedSignals?.ExternalScriptUrls is not null);
    }

    /// <summary>
    /// Rejects non-web URLs and internal hosts so the scanner cannot be used as an SSRF probe.
    /// </summary>
    /// <param name="value">URL text.</param>
    /// <returns>True when the URL is a public HTTP or HTTPS URL.</returns>
    private static bool BeSafeHttpUrl(string? value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https") ||
            string.IsNullOrWhiteSpace(uri.Host))
        {
            return false;
        }

        return !IsInternalHost(uri.Host);
    }

    /// <summary>
    /// Blocks localhost, loopback, private network, and link-local hosts by default.
    /// </summary>
    /// <param name="host">Host extracted from a URL.</param>
    /// <returns>True when the host is internal or local-only.</returns>
    private static bool IsInternalHost(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!System.Net.IPAddress.TryParse(host, out var address))
        {
            return false;
        }

        if (System.Net.IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal)
        {
            return true;
        }

        var bytes = address.GetAddressBytes();
        return bytes.Length == 4 &&
            (bytes[0] == 10 ||
             bytes[0] == 127 ||
             bytes[0] == 169 && bytes[1] == 254 ||
             bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
             bytes[0] == 192 && bytes[1] == 168);
    }
}
