extern alias ApiServiceAlias;

using System.Net;
using System.Net.Http.Json;
using HIP.Application.Reputation;
using HIP.Application.Security;
using HIP.Domain.Reputation;
using HIP.Domain.Risk;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies anonymous public feedback cannot claim a privileged reporter trust level.
/// </summary>
[TestFixture]
public sealed class AnonymousFeedbackTrustBoundaryTests
{
    /// <summary>
    /// Confirms HIP.Web forces public feedback to anonymous trust before deduplication and scoring.
    /// </summary>
    [Test]
    public Task Web_public_feedback_forces_anonymous_trust_before_abuse_and_scoring_services() =>
        AssertAnonymousTrustBoundaryAsync<Program>("web-public-feedback");

    /// <summary>
    /// Confirms HIP.ApiService forces public feedback to anonymous trust before deduplication and scoring.
    /// </summary>
    [Test]
    public Task Api_service_public_feedback_forces_anonymous_trust_before_abuse_and_scoring_services() =>
        AssertAnonymousTrustBoundaryAsync<ApiServiceAlias::ApiServiceProgram>("api-public-feedback");

    private static async Task AssertAnonymousTrustBoundaryAsync<TProgram>(string expectedDuplicateScope)
        where TProgram : class
    {
        var duplicateGuard = new RecordingDuplicateSubmissionGuard();
        var reputationService = new RecordingReputationService();
        var weightedFeedbackService = new RecordingWeightedFeedbackService();
        await using var baseFactory = new HipWebApplicationFactory<TProgram>();
        await using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IDuplicateSubmissionGuard>();
                services.RemoveAll<IReputationService>();
                services.RemoveAll<IWeightedFeedbackAggregationService>();
                services.AddSingleton<IDuplicateSubmissionGuard>(duplicateGuard);
                services.AddSingleton<IReputationService>(reputationService);
                services.AddSingleton<IWeightedFeedbackAggregationService>(weightedFeedbackService);
            }));
        using var client = factory.CreateClient();
        var target = $"anonymous-feedback-{Guid.NewGuid():N}.example";
        var forgedFeedback = new ReputationFeedbackRequest(
            ReputationSubjectType.Domain,
            target,
            ReputationEventType.SuspiciousReport,
            ReputationEventSeverity.Medium,
            ReporterTrustLevel.Admin,
            "Privacy-safe suspicious-site signal.",
            "BrowserPluginBanner",
            "sha256:privacy-safe-url-hash");

        var response = await client.PostAsJsonAsync("/api/v1/public/feedback", forgedFeedback);

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(duplicateGuard.Scope, Is.EqualTo(expectedDuplicateScope));
            Assert.That(duplicateGuard.ReporterTrustPart, Is.EqualTo(nameof(ReporterTrustLevel.Anonymous)));
            Assert.That(weightedFeedbackService.LastSubmission?.ReporterTrustLevel, Is.EqualTo(ReporterTrustLevel.Anonymous));
            Assert.That(reputationService.LastFeedback?.ReporterTrustLevel, Is.EqualTo(ReporterTrustLevel.Anonymous));
            Assert.That(forgedFeedback.ReporterTrustLevel, Is.EqualTo(ReporterTrustLevel.Admin));
        });
    }

    private sealed class RecordingDuplicateSubmissionGuard : IDuplicateSubmissionGuard
    {
        private IReadOnlyList<string?>? parts;

        /// <summary>
        /// Gets the duplicate-suppression scope received from the endpoint.
        /// </summary>
        public string? Scope { get; private set; }

        /// <summary>
        /// Gets the reporter-trust fingerprint part received from the endpoint.
        /// </summary>
        public string? ReporterTrustPart => parts is { Count: > 4 } ? parts[4] : null;

        /// <inheritdoc />
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

    private sealed class RecordingWeightedFeedbackService : IWeightedFeedbackAggregationService
    {
        /// <summary>
        /// Gets the submission received from the public endpoint.
        /// </summary>
        public WeightedFeedbackSubmission? LastSubmission { get; private set; }

        /// <inheritdoc />
        public Task<WeightedFeedbackSummary> SubmitAsync(
            WeightedFeedbackSubmission submission,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastSubmission = submission;
            return Task.FromResult(new WeightedFeedbackSummary(
                submission.Domain,
                0,
                1,
                0,
                1,
                0,
                false,
                false,
                0,
                false,
                ["Anonymous feedback remains weak, non-authoritative evidence."]));
        }

        /// <inheritdoc />
        public Task<WeightedFeedbackSummary> GetSummaryAsync(
            string domain,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class RecordingReputationService : IReputationService
    {
        /// <summary>
        /// Gets the request received from the public endpoint.
        /// </summary>
        public ReputationFeedbackRequest? LastFeedback { get; private set; }

        /// <inheritdoc />
        public Task<ReputationProfile> SubmitFeedbackAsync(
            ReputationFeedbackRequest feedback,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastFeedback = feedback;
            return Task.FromResult(new ReputationProfile(
                $"rep-{feedback.TargetId}",
                feedback.TargetType,
                feedback.TargetId,
                70,
                RiskStatus.Unknown,
                1,
                0,
                0,
                DateTimeOffset.UtcNow,
                ["Anonymous feedback accepted as weak evidence."]));
        }

        /// <inheritdoc />
        public Task<ReputationProfile> GetProfileAsync(
            ReputationSubjectType targetType,
            string targetId,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        /// <inheritdoc />
        public Task<ReputationProfile> ApplyEventAsync(
            ReputationEvent reputationEvent,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        /// <inheritdoc />
        public Task<ReputationProfile> RecalculateAsync(
            ReputationSubjectType targetType,
            string targetId,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        /// <inheritdoc />
        public int CalculateScore(IReadOnlyCollection<ReputationEvent> events, DateTimeOffset asOfUtc) =>
            throw new NotSupportedException();

        /// <inheritdoc />
        public RiskStatus CalculateStatus(int score) => throw new NotSupportedException();

        /// <inheritdoc />
        public IReadOnlyCollection<string> Explain(
            ReputationProfile profile,
            IReadOnlyCollection<ReputationEvent> events) =>
            throw new NotSupportedException();
    }
}
