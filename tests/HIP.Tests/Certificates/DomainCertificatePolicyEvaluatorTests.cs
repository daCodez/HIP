using HIP.Application.Certificates;
using HIP.Domain.Certificates;

namespace HIP.Tests.Certificates;

/// <summary>Locks certificate levels to explicit, versioned evidence instead of score alone.</summary>
public sealed class DomainCertificatePolicyEvaluatorTests
{
    [Test]
    public void Registered_requires_verified_domain_control()
    {
        var result = Evaluate(
            DomainCertificateLevel.Registered,
            Evidence() with { AccountContactVerified = true });

        Assert.That(result.Decision, Is.EqualTo(DomainCertificatePolicyDecision.Ineligible));
        Assert.That(result.Requirements.Single(item => item.Code == "ownership.domain-control").Status,
            Is.EqualTo(DomainCertificateRequirementStatus.Missing));
    }

    [Test]
    public void Certified_applies_stronger_configured_requirements()
    {
        var result = Evaluate(
            DomainCertificateLevel.Certified,
            VerifiedEvidence() with
            {
                DnssecStatus = HIP.Domain.Domains.DomainDnssecStatus.Valid,
                OrganizationIdentityVerified = true,
                UnresolvedHighRiskFindings = 0,
                CurrentTrustScore = 90
            });

        Assert.That(result.Decision, Is.EqualTo(DomainCertificatePolicyDecision.RequiresReview));
        Assert.That(result.Requirements.Select(item => item.Code), Does.Contain("dnssec.valid"));
        Assert.That(result.Requirements.Select(item => item.Code), Does.Contain("security.no-high-risk-findings"));
        Assert.That(result.Requirements.Select(item => item.Code), Does.Contain("identity.organization"));
        Assert.That(result.Requirements.Select(item => item.Code), Does.Contain("score.certified-minimum"));
        Assert.That(result.Requirements.Select(item => item.Code), Does.Contain("review.certified"));
    }

    [Test]
    public void Certified_rejects_invalid_dnssec_even_when_verified_requirements_pass()
    {
        var result = Evaluate(
            DomainCertificateLevel.Certified,
            VerifiedEvidence() with
            {
                DnssecStatus = HIP.Domain.Domains.DomainDnssecStatus.Invalid,
                OrganizationIdentityVerified = true,
                CurrentTrustScore = 100
            });

        Assert.That(result.Decision, Is.EqualTo(DomainCertificatePolicyDecision.Ineligible));
        Assert.That(result.Requirements.Single(item => item.Code == "dnssec.valid").Status,
            Is.EqualTo(DomainCertificateRequirementStatus.Missing));
    }
    private static readonly DateTimeOffset Now = new(2026, 7, 24, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void Registered_requires_contact_and_domain_control_but_makes_no_safety_claim()
    {
        var result = Evaluate(
            DomainCertificateLevel.Registered,
            Evidence() with
            {
                AccountContactVerified = true,
                DomainControlVerifiedAtUtc = Now.AddMinutes(-10)
            });

        Assert.Multiple(() =>
        {
            Assert.That(result.Decision, Is.EqualTo(DomainCertificatePolicyDecision.Eligible));
            Assert.That(result.PolicyVersion, Is.EqualTo(DomainCertificatePolicy.V1.Version));
            Assert.That(result.Requirements, Has.None.Matches<DomainCertificateRequirementResult>(
                requirement => requirement.Code == "security.baseline"));
            Assert.That(result.PublicMeaning, Does.Contain("Domain control has been verified"));
            Assert.That(result.PublicMeaning, Does.Not.Contain("safe").IgnoreCase);
        });
    }

    [Test]
    public void High_score_alone_cannot_make_a_domain_verified()
    {
        var result = Evaluate(
            DomainCertificateLevel.Verified,
            Evidence() with { CurrentTrustScore = 100 });

        Assert.Multiple(() =>
        {
            Assert.That(result.Decision, Is.EqualTo(DomainCertificatePolicyDecision.Ineligible));
            Assert.That(MissingCodes(result), Does.Contain("ownership.dns"));
            Assert.That(MissingCodes(result), Does.Contain("ownership.https"));
            Assert.That(MissingCodes(result), Does.Contain("security.baseline"));
            Assert.That(MissingCodes(result), Does.Contain("identity.public-profile"));
        });
    }

    [Test]
    public void Verified_is_eligible_only_when_every_baseline_requirement_passes()
    {
        var result = Evaluate(DomainCertificateLevel.Verified, VerifiedEvidence());

        Assert.Multiple(() =>
        {
            Assert.That(result.Decision, Is.EqualTo(DomainCertificatePolicyDecision.Eligible));
            Assert.That(result.Requirements, Has.All.Property("Status")
                .EqualTo(DomainCertificateRequirementStatus.Satisfied));
            Assert.That(result.PublicMeaning, Does.Contain("identity and baseline security verification"));
        });
    }

    [Test]
    public void Review_signals_prevent_automatic_issuance_without_falsifying_passed_requirements()
    {
        var result = Evaluate(
            DomainCertificateLevel.Verified,
            VerifiedEvidence(),
            new DomainCertificateReviewSignals(UnresolvedHighRiskFindings: true));

        Assert.Multiple(() =>
        {
            Assert.That(result.Decision, Is.EqualTo(DomainCertificatePolicyDecision.RequiresReview));
            Assert.That(result.Requirements, Has.Some.Matches<DomainCertificateRequirementResult>(
                requirement => requirement.Code == "review.high-risk" &&
                    requirement.Status == DomainCertificateRequirementStatus.ReviewRequired));
            Assert.That(result.Requirements.Where(requirement => !requirement.Code.StartsWith("review.", StringComparison.Ordinal)),
                Has.All.Property("Status").EqualTo(DomainCertificateRequirementStatus.Satisfied));
        });
    }

    [Test]
    public void Monitored_requires_active_monitoring_freshness_and_the_policy_score_floor()
    {
        var evidence = VerifiedEvidence() with
        {
            ContinuousMonitoringEnabled = true,
            CertificateActive = true,
            CurrentTrustScore = DomainCertificatePolicy.V1.MinimumMonitoredTrustScore - 1,
            LastMonitoringAtUtc = Now.Subtract(DomainCertificatePolicy.V1.MonitoringFreshness).AddTicks(-1)
        };

        var result = Evaluate(DomainCertificateLevel.Monitored, evidence);

        Assert.Multiple(() =>
        {
            Assert.That(result.Decision, Is.EqualTo(DomainCertificatePolicyDecision.Ineligible));
            Assert.That(MissingCodes(result), Does.Contain("monitoring.score"));
            Assert.That(MissingCodes(result), Does.Contain("monitoring.freshness"));
        });
    }

    [Test]
    public void Monitored_is_eligible_when_verified_requirements_and_current_monitoring_pass()
    {
        var result = Evaluate(
            DomainCertificateLevel.Monitored,
            VerifiedEvidence() with
            {
                ContinuousMonitoringEnabled = true,
                CertificateActive = true,
                CurrentTrustScore = DomainCertificatePolicy.V1.MinimumMonitoredTrustScore,
                LastMonitoringAtUtc = Now.Subtract(DomainCertificatePolicy.V1.MonitoringFreshness)
            });

        Assert.Multiple(() =>
        {
            Assert.That(result.Decision, Is.EqualTo(DomainCertificatePolicyDecision.Eligible));
            Assert.That(result.PublicMeaning, Does.Contain("continuously monitored"));
        });
    }

    [Test]
    public void Critical_findings_are_ineligible_even_when_review_signals_are_present()
    {
        var result = Evaluate(
            DomainCertificateLevel.Verified,
            VerifiedEvidence() with { UnresolvedCriticalFindings = 1 },
            new DomainCertificateReviewSignals(PolicyRequiresManualReview: true));

        Assert.That(result.Decision, Is.EqualTo(DomainCertificatePolicyDecision.Ineligible));
        Assert.That(MissingCodes(result), Does.Contain("security.no-critical-findings"));
    }

    [Test]
    public void Evaluation_is_deterministic_and_rejects_invalid_snapshot_values()
    {
        var request = Request(DomainCertificateLevel.Verified, VerifiedEvidence());
        var evaluator = new DomainCertificatePolicyEvaluator(DomainCertificatePolicy.V1);

        var first = evaluator.Evaluate(request);
        var second = evaluator.Evaluate(request);
        Assert.Multiple(() =>
        {
            Assert.That(second.Requirements, Is.EqualTo(first.Requirements));
            Assert.That(second with { Requirements = first.Requirements }, Is.EqualTo(first));
            Assert.That(
                () => evaluator.Evaluate(request with
                {
                    Evidence = request.Evidence with { CurrentTrustScore = 101 }
                }),
                Throws.ArgumentException);
        });
    }

    private static DomainCertificatePolicyEvaluationResult Evaluate(
        DomainCertificateLevel level,
        DomainCertificateEvidenceSnapshot evidence,
        DomainCertificateReviewSignals? signals = null) =>
        new DomainCertificatePolicyEvaluator(DomainCertificatePolicy.V1).Evaluate(
            Request(level, evidence, signals));

    private static DomainCertificatePolicyEvaluationRequest Request(
        DomainCertificateLevel level,
        DomainCertificateEvidenceSnapshot evidence,
        DomainCertificateReviewSignals? signals = null) =>
        new("example.com", level, evidence, signals ?? new DomainCertificateReviewSignals(), Now);

    private static DomainCertificateEvidenceSnapshot Evidence() => new();

    private static DomainCertificateEvidenceSnapshot VerifiedEvidence() => Evidence() with
    {
        AccountContactVerified = true,
        DomainControlVerifiedAtUtc = Now.AddHours(-2),
        DnsVerifiedAtUtc = Now.AddHours(-2),
        WebsiteVerifiedAtUtc = Now.AddHours(-1),
        InitialSecurityScanCompleted = true,
        UnresolvedCriticalFindings = 0,
        IdentityInformationCompleted = true,
        HttpsAvailable = true,
        TlsCertificateValid = true,
        RequiredPoliciesPassed = true,
        CurrentTrustScore = 80
    };

    private static string[] MissingCodes(DomainCertificatePolicyEvaluationResult result) =>
        result.Requirements
            .Where(requirement => requirement.Status == DomainCertificateRequirementStatus.Missing)
            .Select(requirement => requirement.Code)
            .ToArray();
}
