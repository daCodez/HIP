using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using HIP.Application.Identity;
using HIP.Application.PublicLookup;
using HIP.Domain.Identity;
using HIP.Infrastructure.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace HIP.Infrastructure.Identity;

/// <summary>
/// Retrieves only fixed HTTPS verification locations through a DNS-pinned, redirect-free client and
/// reduces the bounded response to a token match without retaining or exposing page content.
/// </summary>
public sealed partial class SafeHtmlDomainVerificationEvidenceProvider(
    WellKnownHipDocumentFetchOptions? options = null,
    IWellKnownHostAddressResolver? addressResolver = null,
    IWellKnownHttpMessageHandlerFactory? handlerFactory = null,
    ILogger<SafeHtmlDomainVerificationEvidenceProvider>? logger = null)
    : IHtmlDomainVerificationEvidenceProvider
{
    private const string FilePrefix = "hip-verification=";
    private readonly WellKnownHipDocumentFetchOptions fetchOptions =
        (options ?? WellKnownHipDocumentFetchOptions.Default).Validate();
    private readonly IWellKnownHostAddressResolver resolver =
        addressResolver ?? new SystemWellKnownHostAddressResolver();
    private readonly IWellKnownHttpMessageHandlerFactory handlers =
        handlerFactory ?? new PinnedWellKnownHttpMessageHandlerFactory();
    private readonly ILogger<SafeHtmlDomainVerificationEvidenceProvider> log =
        logger ?? NullLogger<SafeHtmlDomainVerificationEvidenceProvider>.Instance;

    /// <inheritdoc />
    public async Task<DomainVerificationCheckResult> CheckAsync(
        string domain,
        VerificationMethod method,
        string expectedToken,
        CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        Validate(method, expectedToken);
        var path = method == VerificationMethod.HtmlFile ? "/hip-verification.txt" : "/";
        var location = $"https://{normalized}{path}";
        var checkedAt = DateTimeOffset.UtcNow;
        try
        {
            var addresses = (await resolver.ResolveAsync(normalized, cancellationToken).ConfigureAwait(false)).ToArray();
            if (addresses.Length == 0 || addresses.Any(address => !PublicNetworkAddressPolicy.IsPublic(address)))
            {
                return Pending(normalized, location, checkedAt, "HIP rejected an unsafe or empty address result.");
            }

            using var handler = handlers.Create(addresses, fetchOptions.Timeout);
            using var client = new HttpClient(handler) { Timeout = fetchOptions.Timeout };
            using var request = new HttpRequestMessage(HttpMethod.Get, new UriBuilder(Uri.UriSchemeHttps, normalized, -1, path).Uri);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(
                method == VerificationMethod.HtmlFile ? "text/plain" : "text/html"));
            request.Headers.UserAgent.ParseAdd("HIP-Domain-Verification/1.0");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentLength > fetchOptions.MaximumResponseBytes)
            {
                return NotConfigured(normalized, location, checkedAt);
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            var bytes = await ReadBoundedAsync(stream, fetchOptions.MaximumResponseBytes, cancellationToken).ConfigureAwait(false);
            if (bytes is null)
            {
                return Pending(normalized, location, checkedAt, "The verification response exceeded HIP's safe size limit.");
            }

            var body = Encoding.UTF8.GetString(bytes);
            var matched = method == VerificationMethod.HtmlFile
                ? FileMatches(body, expectedToken)
                : MetaMatches(body, expectedToken);
            return new DomainVerificationCheckResult(
                normalized,
                location,
                matched ? DomainVerificationCheckStatus.Verified : DomainVerificationCheckStatus.Invalid,
                checkedAt,
                matched ? "HIP found the expected domain verification evidence." : "The verification evidence did not match the active challenge.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            log.LogWarning(exception, "HIP HTML verification could not complete for {Domain}; challenge content was not logged.", normalized);
            return Pending(normalized, location, checkedAt, "HIP could not retrieve the verification evidence yet.");
        }
    }

    private static void Validate(VerificationMethod method, string token)
    {
        if (method is not (VerificationMethod.HtmlFile or VerificationMethod.MetaTag))
        {
            throw new ArgumentException("The HTML evidence provider supports HTML file and meta-tag verification only.", nameof(method));
        }
        if (string.IsNullOrWhiteSpace(token) || token.Length > 256 || token.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("A bounded non-whitespace verification token is required.", nameof(token));
        }
    }

    private static bool FileMatches(string body, string token)
    {
        var candidate = body.Trim();
        if (candidate.StartsWith(FilePrefix, StringComparison.OrdinalIgnoreCase))
        {
            candidate = candidate[FilePrefix.Length..].Trim();
        }
        return Matches(candidate, token);
    }

    private static bool MetaMatches(string body, string token)
    {
        foreach (Match tag in MetaTagRegex().Matches(body))
        {
            string? name = null;
            string? content = null;
            foreach (Match attribute in AttributeRegex().Matches(tag.Value))
            {
                var key = attribute.Groups["name"].Value;
                var value = WebUtility.HtmlDecode(attribute.Groups["value"].Value);
                if (key.Equals("name", StringComparison.OrdinalIgnoreCase)) name = value;
                if (key.Equals("content", StringComparison.OrdinalIgnoreCase)) content = value;
            }
            if (name?.Equals("hip-verification", StringComparison.OrdinalIgnoreCase) == true &&
                content is not null && Matches(content.Trim(), token))
            {
                return true;
            }
        }
        return false;
    }

    private static bool Matches(string candidate, string expected)
    {
        if (candidate.Length != expected.Length) return false;
        return CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(Encoding.UTF8.GetBytes(candidate)),
            SHA256.HashData(Encoding.UTF8.GetBytes(expected)));
    }

    private static async Task<byte[]?> ReadBoundedAsync(Stream stream, int maximumBytes, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream(Math.Min(maximumBytes, 16 * 1024));
        var block = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(block.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0) return buffer.ToArray();
            if (buffer.Length + read > maximumBytes) return null;
            buffer.Write(block, 0, read);
        }
    }

    private static DomainVerificationCheckResult Pending(string domain, string location, DateTimeOffset checkedAt, string message) =>
        new(domain, location, DomainVerificationCheckStatus.PendingVerification, checkedAt, message);
    private static DomainVerificationCheckResult NotConfigured(string domain, string location, DateTimeOffset checkedAt) =>
        new(domain, location, DomainVerificationCheckStatus.NotConfigured, checkedAt, "HIP did not find domain verification evidence at the required location.");

    [GeneratedRegex(@"<meta\b[^>]*>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex MetaTagRegex();

    [GeneratedRegex("(?<name>[A-Za-z_:][-A-Za-z0-9_:.]*)\\s*=\\s*(?:\"(?<value>[^\"]*)\"|'(?<value>[^']*)')", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex AttributeRegex();
}
