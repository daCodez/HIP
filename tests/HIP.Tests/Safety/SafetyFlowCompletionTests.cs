using HIP.Application.Reporting;
using HIP.Application.Safety;
using HIP.Domain.Risk;
using HIP.Domain.Safety;

namespace HIP.Tests.Safety;

[TestFixture]
public sealed class SafetyFlowCompletionTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 21, 18, 0, 0, TimeSpan.Zero);

    [TestCase("https://bit.ly/login", SafetyContinuationRequirement.Confirmation, true)]
    [TestCase("https://danger-example.com/pay", SafetyContinuationRequirement.ExtraConfirmation, true)]
    [TestCase("https://critical-example.com/pay", SafetyContinuationRequirement.Blocked, false)]
    public void Safety_policy_requires_risk_appropriate_confirmation(
        string url,
        SafetyContinuationRequirement expectedRequirement,
        bool expectedAllowContinue)
    {
        var result = new SafetyRoutingService().EvaluateUrl(url, "browser-extension");

        Assert.Multiple(() =>
        {
            Assert.That(result.ContinuationRequirement, Is.EqualTo(expectedRequirement));
            Assert.That(result.AllowContinue, Is.EqualTo(expectedAllowContinue));
            Assert.That(result.PageTrustScore, Is.InRange(0, 100));
            Assert.That(result.ContentRiskScore, Is.InRange(0, 100));
            Assert.That(result.FinalHipScore, Is.InRange(0, 100));
            Assert.That(result.ContentRiskScoreHigherMeansMoreRisk, Is.True);
        });
    }

    [Test]
    public async Task Dangerous_continue_requires_acknowledgement_and_critical_continue_is_always_rejected()
    {
        var repository = new InMemorySafetyDecisionRepository();
        var service = CreateDecisionService(repository);

        var unconfirmed = await service.RecordAsync(
            new SafetyDecisionRequest(
                "https://danger-example.com/pay?token=private#secret",
                "browser-extension",
                SafetyDecisionAction.Continue,
                DangerAcknowledged: false),
            CancellationToken.None);
        var confirmed = await service.RecordAsync(
            new SafetyDecisionRequest(
                "https://danger-example.com/pay?token=private#secret",
                "browser-extension",
                SafetyDecisionAction.Continue,
                DangerAcknowledged: true),
            CancellationToken.None);
        var critical = await service.RecordAsync(
            new SafetyDecisionRequest(
                "https://critical-example.com/pay",
                "browser-extension",
                SafetyDecisionAction.Continue,
                DangerAcknowledged: true),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(unconfirmed.Status, Is.EqualTo(SafetyDecisionStatus.AdditionalConfirmationRequired));
            Assert.That(confirmed.Status, Is.EqualTo(SafetyDecisionStatus.Recorded));
            Assert.That(critical.Status, Is.EqualTo(SafetyDecisionStatus.BlockedByPolicy));
            Assert.That(repository.Records, Has.Count.EqualTo(1));
        });
    }

    [Test]
    public async Task Recorded_decision_contains_only_keyed_hashes_and_bounded_public_metadata()
    {
        const string privateUrl = "https://danger-example.com/pay?token=private-marker#message";
        var repository = new InMemorySafetyDecisionRepository();
        var service = CreateDecisionService(repository);

        var result = await service.RecordAsync(
            new SafetyDecisionRequest(
                privateUrl,
                " Browser-Extension ",
                SafetyDecisionAction.ReportDangerous,
                DangerAcknowledged: false),
            CancellationToken.None);

        var record = repository.Records.Single();
        var serializedRecord = System.Text.Json.JsonSerializer.Serialize(record);
        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(SafetyDecisionStatus.Recorded));
            Assert.That(record.UrlHash, Does.StartWith("sha256:"));
            Assert.That(record.DomainHash, Does.StartWith("sha256:"));
            Assert.That(record.Source, Is.EqualTo("browser-extension"));
            Assert.That(record.RiskLevel, Is.EqualTo(RiskStatus.Dangerous));
            Assert.That(record.RecordedAtUtc, Is.EqualTo(Now));
            Assert.That(serializedRecord, Does.Not.Contain(privateUrl));
            Assert.That(serializedRecord, Does.Not.Contain("private-marker"));
            Assert.That(serializedRecord, Does.Not.Contain("danger-example.com"));
            Assert.That(record.GetType().GetProperties().Select(property => property.Name),
                Does.Not.Contain("Url"));
        });
    }

    private static SafetyDecisionService CreateDecisionService(ISafetyDecisionRepository repository) =>
        new(
            new SafetyRoutingService(),
            repository,
            new Sha256PrivacyHashingService(),
            new FixedTimeProvider(Now));

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }
}
