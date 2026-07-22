using System.Net;
using System.Net.Http.Json;
using System.Text;
using HIP.Application.Protocol;
using HIP.Application.SiteSafety;
using HIP.Domain.Protocol;
using HIP.Web.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Api;

/// <summary>Focused contract tests for HIP.Web's signed trust receipt endpoints.</summary>
[TestFixture]
public sealed class HipTrustReceiptWebApiTests
{
    /// <summary>Issuance evaluates the caller's URL server-side and returns the exact signed receipt bytes.</summary>
    [Test]
    public async Task Issue_receipt_returns_exact_json_and_created_location()
    {
        var receiptJson = ReadReceiptFixture();
        var doubles = new ProtocolDoubles(receiptJson);
        await using var rootFactory = new HipWebApplicationFactory<Program>();
        await using var factory = Configure(rootFactory, doubles);
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/v1/protocol/issue-receipt",
            new SiteSafetyScanRequest("https://example.com"));

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Created));
            Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/json"));
            Assert.That(
                response.Headers.Location?.OriginalString,
                Is.EqualTo($"/api/v1/protocol/receipts/{Uri.EscapeDataString(doubles.Receipt.ReceiptId)}"));
            Assert.That(doubles.LastEvaluation?.Domain, Is.EqualTo("example.com"));
        });
        Assert.That(await response.Content.ReadAsStringAsync(), Is.EqualTo(receiptJson));
    }

    /// <summary>
    /// Proves HIP.Web strips forged browser evidence and never applies client-scoped provider switches to a receipt.
    /// </summary>
    [Test]
    public async Task Issue_receipt_strips_forged_client_evidence_and_does_not_load_client_provider_settings()
    {
        var doubles = new ProtocolDoubles(ReadReceiptFixture());
        var evaluation = AuthoritativeEvaluation();
        var scanner = new RecordingSiteSafetyScanner(evaluation);
        var settingsStore = new RecordingExternalSiteEvidenceSettingsStore();
        await using var rootFactory = new HipWebApplicationFactory<Program>();
        await using var factory = Configure(rootFactory, doubles, scanner, settingsStore);
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
            Assert.That(doubles.LastEvaluation, Is.SameAs(evaluation));
            Assert.That(settingsStore.GetCallCount, Is.Zero);
        });
    }

    /// <summary>Issue failures use stable typed outcomes and do not expose signer or persistence details.</summary>
    [TestCase(
        HipTrustReceiptIssueStatus.InvalidEvaluation,
        HttpStatusCode.BadRequest,
        "HIP could not issue a receipt from the authoritative site safety evaluation.")]
    [TestCase(
        HipTrustReceiptIssueStatus.Conflict,
        HttpStatusCode.Conflict,
        "A different trust receipt already exists for this authoritative evaluation.")]
    [TestCase(
        HipTrustReceiptIssueStatus.SignerUnavailable,
        HttpStatusCode.ServiceUnavailable,
        "HIP trust receipt signing is unavailable.")]
    [TestCase(
        HipTrustReceiptIssueStatus.SignerNotAuthorized,
        HttpStatusCode.ServiceUnavailable,
        "HIP trust receipt signing is unavailable.")]
    [TestCase(
        HipTrustReceiptIssueStatus.VerificationFailed,
        HttpStatusCode.ServiceUnavailable,
        "HIP could not verify the newly signed trust receipt.")]
    [TestCase(
        HipTrustReceiptIssueStatus.PersistenceUnavailable,
        HttpStatusCode.ServiceUnavailable,
        "HIP trust receipt storage is unavailable.")]
    public async Task Issue_receipt_maps_safe_failure_response(
        HipTrustReceiptIssueStatus issueStatus,
        HttpStatusCode expectedStatus,
        string expectedError)
    {
        var doubles = new ProtocolDoubles(ReadReceiptFixture())
        {
            IssueResult = new HipTrustReceiptIssueResult(issueStatus)
        };
        await using var rootFactory = new HipWebApplicationFactory<Program>();
        await using var factory = Configure(rootFactory, doubles);
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/v1/protocol/issue-receipt",
            new SiteSafetyScanRequest("https://example.com"));
        var body = await response.Content.ReadFromJsonAsync<ErrorResponse>();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(expectedStatus));
            Assert.That(body?.Error, Is.EqualTo(expectedError));
        });
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
        await using var rootFactory = new HipWebApplicationFactory<Program>();
        await using var factory = rootFactory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<ISiteSafetyScanner>();
            services.AddSingleton<ISiteSafetyScanner>(new ThrowingSiteSafetyScanner(validationFailure
                ? new ArgumentException(sensitiveMarker)
                : new InvalidOperationException(sensitiveMarker)));
        }));
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/v1/protocol/issue-receipt",
            new SiteSafetyScanRequest("https://example.com/private"));
        var body = await response.Content.ReadFromJsonAsync<ErrorResponse>();
        var rawBody = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(expectedStatus));
            Assert.That(body?.Error, Is.EqualTo(expectedError));
            Assert.That(rawBody, Does.Not.Contain(sensitiveMarker));
        });
    }

    /// <summary>Lookup returns the immutable stored representation and rejects malformed identifiers before storage.</summary>
    [Test]
    public async Task Receipt_lookup_returns_exact_stored_json_and_validates_identifier()
    {
        var receiptJson = ReadReceiptFixture();
        var doubles = new ProtocolDoubles(receiptJson);
        await using var rootFactory = new HipWebApplicationFactory<Program>();
        await using var factory = Configure(rootFactory, doubles);
        using var client = factory.CreateClient();

        var found = await client.GetAsync(
            $"/api/v1/protocol/receipts/{Uri.EscapeDataString(doubles.Receipt.ReceiptId)}");
        var invalid = await client.GetAsync("/api/v1/protocol/receipts/not%20valid");
        var missing = await client.GetAsync("/api/v1/protocol/receipts/receipt:missing");

        Assert.Multiple(() =>
        {
            Assert.That(found.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(found.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/json"));
            Assert.That(invalid.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(missing.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            Assert.That(doubles.LookupIds, Is.EqualTo(new[]
            {
                doubles.Receipt.ReceiptId,
                "receipt:missing"
            }));
        });
        Assert.That(await found.Content.ReadAsStringAsync(), Is.EqualTo(receiptJson));
    }

    /// <summary>Verification preserves the raw receipt, exposes only typed public fields, and maps trust failures.</summary>
    [Test]
    public async Task Verify_receipt_maps_typed_statuses_and_bounds_request_body()
    {
        var receiptJson = ReadReceiptFixture();
        var doubles = new ProtocolDoubles(receiptJson);
        await using var rootFactory = new HipWebApplicationFactory<Program>();
        await using var factory = Configure(rootFactory, doubles);
        using var client = factory.CreateClient();

        var verified = await PostReceiptAsync(client, receiptJson);
        var verifiedBody = await verified.Content.ReadFromJsonAsync<VerificationResponse>();

        doubles.VerificationStatus = HipTrustReceiptVerificationStatus.MalformedReceipt;
        var malformed = await PostReceiptAsync(client, receiptJson);
        doubles.VerificationStatus = HipTrustReceiptVerificationStatus.Expired;
        var expired = await PostReceiptAsync(client, receiptJson);
        doubles.VerificationStatus = HipTrustReceiptVerificationStatus.TimestampOutsideTolerance;
        var futureIssued = await PostReceiptAsync(client, receiptJson);
        doubles.VerificationStatus = HipTrustReceiptVerificationStatus.ValidityWindowExceeded;
        var overlong = await PostReceiptAsync(client, receiptJson);
        doubles.VerificationStatus = HipTrustReceiptVerificationStatus.IssuerNotAuthorized;
        var unauthorizedIssuer = await PostReceiptAsync(client, receiptJson);
        doubles.VerificationStatus = HipTrustReceiptVerificationStatus.ProviderUnavailable;
        var unavailable = await PostReceiptAsync(client, receiptJson);
        var verificationCallsBeforeOversize = doubles.VerificationBodies.Count;
        var oversized = await PostReceiptAsync(
            client,
            new string('x', HipTrustReceiptJson.MaximumReceiptBytes + 1));

        Assert.Multiple(() =>
        {
            Assert.That(verified.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(verifiedBody?.Status, Is.EqualTo(HipTrustReceiptVerificationStatus.Verified.ToString()));
            Assert.That(verifiedBody?.IsVerified, Is.True);
            Assert.That(verifiedBody?.EstablishesSafetyOrReputationBySignatureAlone, Is.False);
            Assert.That(verifiedBody?.VerifiedIssuerId, Is.EqualTo(doubles.Receipt.Issuer.Id));
            Assert.That(verifiedBody?.VerifiedKeyId, Is.EqualTo(doubles.Receipt.Signature.KeyId));
            Assert.That(doubles.VerificationBodies[0], Is.EqualTo(receiptJson));
            Assert.That(malformed.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(expired.StatusCode, Is.EqualTo(HttpStatusCode.UnprocessableEntity));
            Assert.That(futureIssued.StatusCode, Is.EqualTo(HttpStatusCode.UnprocessableEntity));
            Assert.That(overlong.StatusCode, Is.EqualTo(HttpStatusCode.UnprocessableEntity));
            Assert.That(unauthorizedIssuer.StatusCode, Is.EqualTo(HttpStatusCode.UnprocessableEntity));
            Assert.That(unavailable.StatusCode, Is.EqualTo(HttpStatusCode.ServiceUnavailable));
            Assert.That(oversized.StatusCode, Is.EqualTo(HttpStatusCode.RequestEntityTooLarge));
            Assert.That(doubles.VerificationBodies, Has.Count.EqualTo(verificationCallsBeforeOversize));
        });
    }

    /// <summary>Cryptographic issuance and verification endpoints carry the public scan rate-limit policy.</summary>
    [Test]
    public async Task Receipt_crypto_endpoints_are_rate_limited()
    {
        var doubles = new ProtocolDoubles(ReadReceiptFixture());
        await using var rootFactory = new HipWebApplicationFactory<Program>();
        await using var factory = Configure(rootFactory, doubles);
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.RoutePattern.RawText is
                "/api/v1/protocol/issue-receipt" or "/api/v1/protocol/receipts/verify")
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(endpoints, Has.Length.EqualTo(2));
            Assert.That(
                endpoints.All(endpoint =>
                    endpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName ==
                    RateLimitPolicies.PublicScanPolicy),
                Is.True);
            Assert.That(
                endpoints.Single(endpoint => endpoint.RoutePattern.RawText ==
                    "/api/v1/protocol/issue-receipt")
                    .Metadata
                    .GetMetadata<Microsoft.AspNetCore.Http.Metadata.IRequestSizeLimitMetadata>()
                    ?.MaxRequestBodySize,
                Is.EqualTo(HipTrustReceiptIssueRequest.MaximumRequestBodyBytes));
        });
    }

    private static Task<HttpResponseMessage> PostReceiptAsync(HttpClient client, string receiptJson) =>
        client.PostAsync(
            "/api/v1/protocol/receipts/verify",
            new StringContent(receiptJson, Encoding.UTF8, "application/json"));

    private static WebApplicationFactory<Program> Configure(
        HipWebApplicationFactory<Program> rootFactory,
        ProtocolDoubles doubles,
        ISiteSafetyScanner? scanner = null,
        IExternalSiteEvidenceSettingsStore? settingsStore = null) =>
        rootFactory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IHipTrustReceiptIssuanceService>();
            services.RemoveAll<IHipTrustReceiptRepository>();
            services.RemoveAll<IHipTrustReceiptVerificationService>();
            services.AddSingleton<IHipTrustReceiptIssuanceService>(doubles);
            services.AddSingleton<IHipTrustReceiptRepository>(doubles);
            services.AddSingleton<IHipTrustReceiptVerificationService>(doubles);

            if (scanner is not null)
            {
                services.RemoveAll<ISiteSafetyScanner>();
                services.AddSingleton(scanner);
            }

            if (settingsStore is not null)
            {
                services.RemoveAll<IExternalSiteEvidenceSettingsStore>();
                services.AddSingleton(settingsStore);
            }
        }));

    private static string ReadReceiptFixture() => File.ReadAllText(Path.Combine(
        RepositoryRoot(),
        "tests",
        "HIP.Tests",
        "Protocol",
        "Fixtures",
        "hip-trust-receipt-v1.json")).TrimEnd();

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }

    private sealed record ErrorResponse(string Error);

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
        "site-safety-authoritative-web-test",
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

    private sealed record VerificationResponse(
        string Status,
        bool IsVerified,
        bool EstablishesSafetyOrReputationBySignatureAlone,
        string? VerifiedIssuerId,
        string? VerifiedKeyId);

    private sealed class ProtocolDoubles :
        IHipTrustReceiptIssuanceService,
        IHipTrustReceiptRepository,
        IHipTrustReceiptVerificationService
    {
        private readonly HipStoredTrustReceipt storedReceipt;

        public ProtocolDoubles(string receiptJson)
        {
            Receipt = HipTrustReceiptJson.Deserialize(receiptJson);
            storedReceipt = new HipStoredTrustReceipt(
                Receipt,
                receiptJson,
                $"sha256:{new string('a', 64)}",
                Receipt.EvidenceDigest.ToPrefixedString());
            IssueResult = new HipTrustReceiptIssueResult(HipTrustReceiptIssueStatus.Issued, Receipt);
        }

        public HipTrustReceipt Receipt { get; }

        public HipTrustReceiptIssueResult IssueResult { get; set; }

        public HipTrustReceiptVerificationStatus VerificationStatus { get; set; } =
            HipTrustReceiptVerificationStatus.Verified;

        public SiteSafetyScanResult? LastEvaluation { get; private set; }

        public List<string> LookupIds { get; } = [];

        public List<string> VerificationBodies { get; } = [];

        public Task<HipTrustReceiptIssueResult> IssueAsync(
            SiteSafetyScanResult authoritativeEvaluation,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastEvaluation = authoritativeEvaluation;
            return Task.FromResult(IssueResult);
        }

        public Task<HipStoredTrustReceipt?> GetByIdAsync(
            string receiptId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LookupIds.Add(receiptId);
            return Task.FromResult<HipStoredTrustReceipt?>(
                string.Equals(receiptId, Receipt.ReceiptId, StringComparison.Ordinal)
                    ? storedReceipt
                    : null);
        }

        public Task<HipStoredTrustReceipt?> GetByRelatedEvaluationIdAsync(
            string relatedEvaluationId,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<HipTrustReceiptRepositoryWriteResult> TryCreateAsync(
            HipStoredTrustReceipt receipt,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<HipTrustReceiptVerificationResult> VerifyAsync(
            ReadOnlyMemory<byte> utf8Receipt,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            VerificationBodies.Add(Encoding.UTF8.GetString(utf8Receipt.Span));
            return Task.FromResult(VerificationStatus == HipTrustReceiptVerificationStatus.Verified
                ? new HipTrustReceiptVerificationResult(
                    VerificationStatus,
                    Receipt,
                    Receipt.Issuer.Id,
                    Receipt.Signature.KeyId)
                : new HipTrustReceiptVerificationResult(VerificationStatus));
        }
    }
}
