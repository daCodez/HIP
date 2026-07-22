using System.Net;
using System.Net.Http.Json;
using HIP.Application.Reporting;
using HIP.Application.Security;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.SelfHealing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies anonymous public risk findings cannot forge trusted provenance.
/// </summary>
[TestFixture]
public sealed class AnonymousRiskFindingTrustBoundaryTests
{
    /// <summary>
    /// Confirms the public endpoint replaces every caller-owned provenance field before abuse checks and ingestion.
    /// </summary>
    [Test]
    public async Task Web_public_risk_finding_replaces_forged_provenance_before_duplicate_check_and_ingestion()
    {
        var duplicateGuard = new RecordingDuplicateSubmissionGuard();
        var ingestionService = new RecordingRiskFindingIngestionService();
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IDuplicateSubmissionGuard>();
                services.RemoveAll<IRiskFindingIngestionService>();
                services.AddSingleton<IDuplicateSubmissionGuard>(duplicateGuard);
                services.AddSingleton<IRiskFindingIngestionService>(ingestionService);
            }));
        using var client = factory.CreateClient();
        var forgedDetectedAt = DateTimeOffset.UtcNow.AddYears(10);
        var forgedReport = new RiskFindingReport(
            "caller-controlled-report-id",
            SourceClient.AdminPortal,
            ReportPlatform.Discord,
            TargetType.Domain,
            $"anonymous-risk-{Guid.NewGuid():N}.example",
            "sha256:privacy-safe-url-hash",
            null,
            null,
            RiskStatus.Critical,
            "Privacy-safe forged-provenance test finding.",
            forgedDetectedAt,
            ReporterTrustLevel.Trusted,
            new PrivacySafeEvidence(
                "security-test",
                "Privacy-safe evidence.",
                new Dictionary<string, string>()),
            "caller-forged-signature",
            "caller-forged-consumer-scope");
        var earliestServerTime = DateTimeOffset.UtcNow;

        var response = await client.PostAsJsonAsync("/api/v1/public/risk-findings", forgedReport);

        var latestServerTime = DateTimeOffset.UtcNow;
        var acceptedReport = ingestionService.LastReport;
        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(duplicateGuard.Scope, Is.EqualTo("web-risk-finding"));
            Assert.That(duplicateGuard.SourceClientPart, Is.EqualTo(nameof(SourceClient.Unknown)));
            Assert.That(duplicateGuard.PlatformPart, Is.EqualTo(nameof(ReportPlatform.Unknown)));
            Assert.That(acceptedReport, Is.Not.Null);
            Assert.That(acceptedReport!.ReportId, Does.StartWith("risk-report-"));
            Assert.That(acceptedReport.ReportId, Is.Not.EqualTo(forgedReport.ReportId));
            Assert.That(acceptedReport.SourceClient, Is.EqualTo(SourceClient.Unknown));
            Assert.That(acceptedReport.Platform, Is.EqualTo(ReportPlatform.Unknown));
            Assert.That(acceptedReport.ReporterTrustLevel, Is.EqualTo(ReporterTrustLevel.Unknown));
            Assert.That(acceptedReport.DetectedAtUtc, Is.InRange(earliestServerTime, latestServerTime));
            Assert.That(acceptedReport.DetectedAtUtc, Is.Not.EqualTo(forgedDetectedAt));
            Assert.That(acceptedReport.HipSignature, Is.Empty);
            Assert.That(acceptedReport.ConsumerScopeHash, Is.Null);
        });
    }

    private sealed class RecordingDuplicateSubmissionGuard : IDuplicateSubmissionGuard
    {
        private IReadOnlyList<string?>? parts;

        public string? Scope { get; private set; }

        public string? SourceClientPart => parts is { Count: > 0 } ? parts[0] : null;

        public string? PlatformPart => parts is { Count: > 1 } ? parts[1] : null;

        public ValueTask<bool> TryAcceptAsync(
            string scope,
            IEnumerable<string?> parts,
            TimeSpan window,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Scope = scope;
            this.parts = parts.ToArray();
            return ValueTask.FromResult(true);
        }
    }

    private sealed class RecordingRiskFindingIngestionService : IRiskFindingIngestionService
    {
        public RiskFindingReport? LastReport { get; private set; }

        public Task<RiskFindingIngestionResponse> IngestAsync(
            RiskFindingReport report,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastReport = report;
            return Task.FromResult(new RiskFindingIngestionResponse(
                true,
                report.ReportId,
                report.Domain,
                report.RiskLevel,
                false,
                "Risk finding accepted."));
        }

        public Task<IReadOnlyCollection<RiskFindingReport>> ListReportsAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<IReadOnlyCollection<PatternCluster>> DetectPatternsAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
