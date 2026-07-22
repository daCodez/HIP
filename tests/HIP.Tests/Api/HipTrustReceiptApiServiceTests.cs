extern alias ApiServiceAlias;

using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HIP.Application.Protocol;
using HIP.Application.SiteSafety;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;
using HIP.Domain.Risk;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Api;

/// <summary>
/// Verifies the standalone HIP API service issues, retrieves, and verifies immutable trust receipts.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class HipTrustReceiptApiServiceTests
{
    /// <summary>
    /// Proves receipt issuance evaluates the supplied URL on the server and returns the exact signed wire document.
    /// </summary>
    [Test]
    public async Task Issue_receipt_uses_server_evaluation_and_returns_exact_wire_json()
    {
        var receipt = ValidReceipt();
        var issuance = new StubIssuanceService(HipTrustReceiptIssueStatus.Issued, receipt);
        await using var baseFactory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        await using var factory = WithService<IHipTrustReceiptIssuanceService>(baseFactory, issuance);
        using var client = factory.CreateClient();
        using var content = JsonContent.Create(new
        {
            url = "https://example.com/account?private=not-for-the-receipt",
            pluginVersion = "api-test",
            scanId = "client-forged-scan",
            domainTrustScore = 999,
            finalHipScore = 999,
            privateKey = "client-private-key"
        });

        var response = await client.PostAsync("/api/v1/protocol/issue-receipt", content);
        var body = await response.Content.ReadAsStringAsync();

        Assert.That(issuance.LastEvaluation, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created));
            Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/json"));
            Assert.That(response.Headers.Location?.OriginalString,
                Is.EqualTo($"/api/v1/protocol/receipts/{Uri.EscapeDataString(receipt.ReceiptId)}"));
            Assert.That(body, Is.EqualTo(HipTrustReceiptJson.Serialize(receipt)));
            Assert.That(body, Does.Not.Contain("client-private-key"));
            Assert.That(issuance.LastEvaluation!.ScanId, Is.Not.EqualTo("client-forged-scan"));
            Assert.That(issuance.LastEvaluation.DomainTrustScore, Is.InRange(0, 100));
            Assert.That(issuance.LastEvaluation.DomainTrustScore, Is.Not.EqualTo(999));
            Assert.That(issuance.LastEvaluation.FinalHipScore, Is.InRange(0, 100));
        });
    }

    /// <summary>
    /// Proves receipt issuance ignores forged browser evidence and client-scoped provider switches before evaluation.
    /// </summary>
    [Test]
    public async Task Issue_receipt_strips_forged_client_evidence_and_does_not_load_client_provider_settings()
    {
        var receipt = ValidReceipt();
        var evaluation = AuthoritativeEvaluation();
        var scanner = new RecordingSiteSafetyScanner(evaluation);
        var issuance = new StubIssuanceService(HipTrustReceiptIssueStatus.Issued, receipt);
        var settingsStore = new RecordingExternalSiteEvidenceSettingsStore();
        await using var baseFactory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        await using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<ISiteSafetyScanner>();
                services.RemoveAll<IHipTrustReceiptIssuanceService>();
                services.RemoveAll<IExternalSiteEvidenceSettingsStore>();
                services.AddSingleton<ISiteSafetyScanner>(scanner);
                services.AddSingleton<IHipTrustReceiptIssuanceService>(issuance);
                services.AddSingleton<IExternalSiteEvidenceSettingsStore>(settingsStore);
            }));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Client-Id", "attacker-provider-scope");

        var response = await client.PostAsJsonAsync(
            "/api/v1/protocol/issue-receipt",
            new SiteSafetyScanRequest(
                "https://example.com/account",
                ForgedSignals(),
                "forged-plugin-version"));

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created));
            Assert.That(scanner.LastRequest?.Url, Is.EqualTo("https://example.com/account"));
            Assert.That(scanner.LastRequest?.ObservedSignals, Is.Null);
            Assert.That(scanner.LastRequest?.PluginVersion, Is.Null);
            Assert.That(issuance.LastEvaluation, Is.SameAs(evaluation));
            Assert.That(settingsStore.GetCallCount, Is.Zero);
        });
    }

    /// <summary>
    /// Verifies issuance failures are expressed through stable client, conflict, and availability status codes.
    /// </summary>
    [TestCase(HipTrustReceiptIssueStatus.InvalidEvaluation, HttpStatusCode.BadRequest)]
    [TestCase(HipTrustReceiptIssueStatus.Conflict, HttpStatusCode.Conflict)]
    [TestCase(HipTrustReceiptIssueStatus.SignerUnavailable, HttpStatusCode.ServiceUnavailable)]
    [TestCase(HipTrustReceiptIssueStatus.SignerNotAuthorized, HttpStatusCode.ServiceUnavailable)]
    [TestCase(HipTrustReceiptIssueStatus.VerificationFailed, HttpStatusCode.ServiceUnavailable)]
    [TestCase(HipTrustReceiptIssueStatus.PersistenceUnavailable, HttpStatusCode.ServiceUnavailable)]
    [TestCase(HipTrustReceiptIssueStatus.Unspecified, HttpStatusCode.ServiceUnavailable)]
    public async Task Issue_receipt_maps_typed_failure_status(
        HipTrustReceiptIssueStatus issueStatus,
        HttpStatusCode expectedStatus)
    {
        var issuance = new StubIssuanceService(issueStatus);
        await using var baseFactory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        await using var factory = WithService<IHipTrustReceiptIssuanceService>(baseFactory, issuance);
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/v1/protocol/issue-receipt",
            new SiteSafetyScanRequest("https://example.com"));

        Assert.That(response.StatusCode, Is.EqualTo(expectedStatus));
    }

    /// <summary>Ensures scanner validation and infrastructure failures cannot disclose request or provider details.</summary>
    [TestCase(true, HttpStatusCode.BadRequest, "HIP could not evaluate the supplied site safety request.")]
    [TestCase(false, HttpStatusCode.ServiceUnavailable, "HIP site safety evaluation is unavailable.")]
    public async Task Issue_receipt_maps_scanner_failures_without_disclosing_exception_details(
        bool validationFailure,
        HttpStatusCode expectedStatus,
        string expectedError)
    {
        const string sensitiveMarker = "private-provider-detail-must-not-escape";
        var scanner = new ThrowingSiteSafetyScanner(validationFailure
            ? new ArgumentException(sensitiveMarker)
            : new InvalidOperationException(sensitiveMarker));
        await using var baseFactory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        await using var factory = WithService<ISiteSafetyScanner>(baseFactory, scanner);
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/v1/protocol/issue-receipt",
            new SiteSafetyScanRequest("https://example.com/private"));
        var body = await response.Content.ReadFromJsonAsync<ApiErrorBody>();
        var rawBody = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(expectedStatus));
            Assert.That(body?.Error, Is.EqualTo(expectedError));
            Assert.That(rawBody, Does.Not.Contain(sensitiveMarker));
        });
    }

    /// <summary>
    /// Proves retrieval returns the immutable stored bytes and distinguishes an unknown receipt.
    /// </summary>
    [Test]
    public async Task Get_receipt_returns_exact_stored_json_or_not_found()
    {
        var receipt = ValidReceipt();
        var stored = StoredReceipt(receipt);
        var repository = new StubReceiptRepository(stored);
        await using var baseFactory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        await using var factory = WithService<IHipTrustReceiptRepository>(baseFactory, repository);
        using var client = factory.CreateClient();

        var found = await client.GetAsync($"/api/v1/protocol/receipts/{Uri.EscapeDataString(receipt.ReceiptId)}");
        var missing = await client.GetAsync("/api/v1/protocol/receipts/receipt:missing");

        Assert.Multiple(() =>
        {
            Assert.That(found.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(found.Content.ReadAsStringAsync().Result, Is.EqualTo(stored.ReceiptJson));
            Assert.That(missing.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
        });
    }

    /// <summary>
    /// Proves verification receives the exact submitted document and does not equate signature validity with safety.
    /// </summary>
    [Test]
    public async Task Verify_receipt_passes_exact_body_and_returns_origin_integrity_semantics()
    {
        var receipt = ValidReceipt();
        var verifier = new StubVerificationService(new HipTrustReceiptVerificationResult(
            HipTrustReceiptVerificationStatus.Verified,
            receipt,
            receipt.Issuer.Id,
            receipt.Signature.KeyId));
        await using var baseFactory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        await using var factory = WithService<IHipTrustReceiptVerificationService>(baseFactory, verifier);
        using var client = factory.CreateClient();
        var submitted = $"\n{HipTrustReceiptJson.Serialize(receipt)}\n";
        using var content = new StringContent(submitted, Encoding.UTF8, "application/json");

        var response = await client.PostAsync("/api/v1/protocol/receipts/verify", content);
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(Encoding.UTF8.GetString(verifier.LastReceipt.Span), Is.EqualTo(submitted));
            Assert.That(json.RootElement.GetProperty("status").GetString(), Is.EqualTo("Verified"));
            Assert.That(json.RootElement.GetProperty("isVerified").GetBoolean(), Is.True);
            Assert.That(json.RootElement.GetProperty("establishesSafetyOrReputationBySignatureAlone").GetBoolean(), Is.False);
            Assert.That(json.RootElement.GetProperty("verifiedIssuerId").GetString(), Is.EqualTo(receipt.Issuer.Id));
            Assert.That(json.RootElement.GetProperty("verifiedKeyId").GetString(), Is.EqualTo(receipt.Signature.KeyId));
        });
    }

    /// <summary>
    /// Verifies receipt verification statuses distinguish invalid documents from unavailable verification state.
    /// </summary>
    [TestCase(HipTrustReceiptVerificationStatus.MalformedReceipt, HttpStatusCode.BadRequest)]
    [TestCase(HipTrustReceiptVerificationStatus.UnsupportedVersion, HttpStatusCode.BadRequest)]
    [TestCase(HipTrustReceiptVerificationStatus.WrongDocumentType, HttpStatusCode.BadRequest)]
    [TestCase(HipTrustReceiptVerificationStatus.Expired, HttpStatusCode.UnprocessableEntity)]
    [TestCase(HipTrustReceiptVerificationStatus.TimestampOutsideTolerance, HttpStatusCode.UnprocessableEntity)]
    [TestCase(HipTrustReceiptVerificationStatus.ValidityWindowExceeded, HttpStatusCode.UnprocessableEntity)]
    [TestCase(HipTrustReceiptVerificationStatus.IssuerNotAuthorized, HttpStatusCode.UnprocessableEntity)]
    [TestCase(HipTrustReceiptVerificationStatus.IssuerRevoked, HttpStatusCode.UnprocessableEntity)]
    [TestCase(HipTrustReceiptVerificationStatus.KeyRevoked, HttpStatusCode.UnprocessableEntity)]
    [TestCase(HipTrustReceiptVerificationStatus.InvalidSignature, HttpStatusCode.UnprocessableEntity)]
    [TestCase(HipTrustReceiptVerificationStatus.ProviderUnavailable, HttpStatusCode.ServiceUnavailable)]
    [TestCase(HipTrustReceiptVerificationStatus.VerificationStateUnavailable, HttpStatusCode.ServiceUnavailable)]
    [TestCase(HipTrustReceiptVerificationStatus.Unspecified, HttpStatusCode.ServiceUnavailable)]
    public async Task Verify_receipt_maps_typed_status(
        HipTrustReceiptVerificationStatus verificationStatus,
        HttpStatusCode expectedStatus)
    {
        var verifier = new StubVerificationService(new HipTrustReceiptVerificationResult(verificationStatus));
        await using var baseFactory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        await using var factory = WithService<IHipTrustReceiptVerificationService>(baseFactory, verifier);
        using var client = factory.CreateClient();
        using var content = new StringContent("{}", Encoding.UTF8, "application/json");

        var response = await client.PostAsync("/api/v1/protocol/receipts/verify", content);
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(expectedStatus));
            Assert.That(json.RootElement.GetProperty("status").GetString(), Is.EqualTo(verificationStatus.ToString()));
        });
    }

    /// <summary>
    /// Proves oversized attacker input is rejected before cryptographic verification is attempted.
    /// </summary>
    [Test]
    public async Task Verify_receipt_rejects_oversized_body_before_verification()
    {
        var verifier = new StubVerificationService(new HipTrustReceiptVerificationResult(
            HipTrustReceiptVerificationStatus.Verified));
        await using var baseFactory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        await using var factory = WithService<IHipTrustReceiptVerificationService>(baseFactory, verifier);
        using var client = factory.CreateClient();
        using var content = new StringContent(
            new string('a', HipTrustReceiptJson.MaximumReceiptBytes + 1),
            Encoding.UTF8,
            "application/json");

        var response = await client.PostAsync("/api/v1/protocol/receipts/verify", content);

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.RequestEntityTooLarge));
            Assert.That(verifier.CallCount, Is.Zero);
        });
    }

    /// <summary>
    /// Proves public issuance and cryptographic verification routes carry explicit rate-limit metadata.
    /// </summary>
    [Test]
    public async Task Receipt_issuance_and_verification_routes_are_rate_limited()
    {
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.RoutePattern.RawText is
                "/api/v1/protocol/issue-receipt" or "/api/v1/protocol/receipts/verify")
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(endpoints, Has.Length.EqualTo(2));
            Assert.That(endpoints.All(endpoint =>
                endpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>() is not null), Is.True);
            Assert.That(
                endpoints.Single(endpoint => endpoint.RoutePattern.RawText ==
                    "/api/v1/protocol/issue-receipt")
                    .Metadata
                    .GetMetadata<Microsoft.AspNetCore.Http.Metadata.IRequestSizeLimitMetadata>()
                    ?.MaxRequestBodySize,
                Is.EqualTo(HipTrustReceiptIssueRequest.MaximumRequestBodyBytes));
        });
    }

    private static Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<ApiServiceAlias::ApiServiceProgram> WithService<TService>(
        HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram> baseFactory,
        TService implementation)
        where TService : class =>
        baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<TService>();
                services.AddSingleton(implementation);
            }));

    private static HipTrustReceipt ValidReceipt() => new(
        HipTrustReceipt.TrustReceiptDocumentType,
        HipProtocolVersion.Current,
        "receipt:api-test-0001",
        "scan:api-test-0001",
        new HipProtocolSubject(IdentitySubjectType.Website, "example.com"),
        new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 7, 19, 12, 0, 1, TimeSpan.Zero),
        new DateTimeOffset(2026, 7, 20, 12, 0, 1, TimeSpan.Zero),
        new HipTrustReceiptScores(82, 74, 61, 39),
        RiskStatus.ProbablySafe,
        HipTrustConfidence.High,
        ["domain-verified", "tls-valid"],
        ["limited-content-evidence"],
        "policy-2026.07",
        "site-safety-2026.07",
        HipContentDigest.FromPrefixedString($"sha256:{new string('d', 64)}"),
        new HipProtocolIssuer("hip:domain:issuer.example"),
        new HipProtocolSignature(
            HipProtocolSignature.OriginAndIntegrityScope,
            "dev-key-1",
            "PQ-Placeholder-Development-Only",
            SignatureAlgorithmFamily.Unknown,
            HipProtocolSignature.Rfc8785Canonicalization,
            $"devsig:{new string('e', 64)}"));

    private static SiteSafetyObservedSignals ForgedSignals() => new(
        RedirectChain: ["http://127.0.0.1/private"],
        ExternalScriptUrls: ["http://localhost/forged.js"],
        InlineScriptCount: -1,
        SuspiciousScriptPatternCount: int.MaxValue,
        DownloadLinks: ["http://169.254.169.254/metadata"],
        HasLoginForm: true,
        HasPasswordField: true,
        HasPaymentField: true,
        ContainsScamWording: true,
        ContainsUrgencyWording: true,
        ContainsImpersonationWording: true,
        KnownPhishingPattern: true,
        KnownMalwareIndicator: true,
        KnownAbuseReports: int.MaxValue,
        DomainReputationScore: 100,
        PageReputationScore: 100,
        TrustDataAvailable: true,
        ShortenedLinkCount: int.MaxValue,
        ObfuscatedLinkCount: int.MaxValue,
        MatchedRiskTerms: ["forged-risk-term"]);

    private static SiteSafetyScanResult AuthoritativeEvaluation() => new(
        "site-safety-authoritative-api-test",
        "https://example.com/account",
        "example.com",
        DateTimeOffset.UtcNow,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        SiteSafetyScanStatus.LimitedData,
        "Limited server evidence.",
        [],
        [],
        [],
        [],
        "Low",
        58,
        58,
        58,
        58,
        [],
        new SiteSafetyScoreImpact(58, 58, 58, 58, []),
        []);

    private static HipStoredTrustReceipt StoredReceipt(HipTrustReceipt receipt)
    {
        var json = HipTrustReceiptJson.Serialize(receipt);
        var canonical = new Rfc8785CanonicalJsonService().Canonicalize(Encoding.UTF8.GetBytes(json));
        var digest = $"sha256:{Convert.ToHexString(SHA256.HashData(canonical)).ToLowerInvariant()}";
        return new HipStoredTrustReceipt(receipt, json, digest, receipt.EvidenceDigest.ToPrefixedString());
    }

    private sealed class StubIssuanceService(
        HipTrustReceiptIssueStatus status,
        HipTrustReceipt? receipt = null) : IHipTrustReceiptIssuanceService
    {
        public SiteSafetyScanResult? LastEvaluation { get; private set; }

        public Task<HipTrustReceiptIssueResult> IssueAsync(
            SiteSafetyScanResult authoritativeEvaluation,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastEvaluation = authoritativeEvaluation;
            return Task.FromResult(new HipTrustReceiptIssueResult(status, receipt));
        }
    }

    private sealed class StubVerificationService(
        HipTrustReceiptVerificationResult result) : IHipTrustReceiptVerificationService
    {
        public int CallCount { get; private set; }

        public ReadOnlyMemory<byte> LastReceipt { get; private set; }

        public Task<HipTrustReceiptVerificationResult> VerifyAsync(
            ReadOnlyMemory<byte> utf8Receipt,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            LastReceipt = utf8Receipt.ToArray();
            return Task.FromResult(result);
        }
    }

    private sealed class StubReceiptRepository(HipStoredTrustReceipt stored) : IHipTrustReceiptRepository
    {
        public Task<HipStoredTrustReceipt?> GetByIdAsync(
            string receiptId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<HipStoredTrustReceipt?>(
                string.Equals(stored.Receipt.ReceiptId, receiptId, StringComparison.Ordinal) ? stored : null);
        }

        public Task<HipStoredTrustReceipt?> GetByRelatedEvaluationIdAsync(
            string relatedEvaluationId,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<HipTrustReceiptRepositoryWriteResult> TryCreateAsync(
            HipStoredTrustReceipt receipt,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class ThrowingSiteSafetyScanner(Exception exception) : ISiteSafetyScanner
    {
        public Task<SiteSafetyScanResult> ScanAsync(
            SiteSafetyScanRequest request,
            CancellationToken cancellationToken) =>
            Task.FromException<SiteSafetyScanResult>(exception);
    }

    private sealed class RecordingSiteSafetyScanner(SiteSafetyScanResult result) : ISiteSafetyScanner
    {
        public SiteSafetyScanRequest? LastRequest { get; private set; }

        public Task<SiteSafetyScanResult> ScanAsync(
            SiteSafetyScanRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastRequest = request;
            return Task.FromResult(result);
        }
    }

    private sealed class RecordingExternalSiteEvidenceSettingsStore : IExternalSiteEvidenceSettingsStore
    {
        public int GetCallCount { get; private set; }

        public Task<ExternalSiteEvidenceOptions?> GetAsync(
            string scopeKey,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            GetCallCount++;
            return Task.FromResult<ExternalSiteEvidenceOptions?>(new ExternalSiteEvidenceOptions());
        }

        public Task<ExternalSiteEvidenceOptions> SaveAsync(
            string scopeKey,
            ExternalSiteEvidenceOptions options,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed record ApiErrorBody(string Error);
}
