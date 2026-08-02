using System.Text;
using System.Text.Json.Nodes;
using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Application.Review;
using HIP.Application.Scoring;
using HIP.Application.SiteSafety;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;
using HIP.Domain.Scoring;

namespace HIP.Tests.Protocol;

[TestFixture]
[NonParallelizable]
public sealed class HipTrustReceiptServiceTests
{
    private const string IssuerId = "hip:web:receipt-issuer.example";
    private const string KeyId = "receipt-key-1";
    private const string PrivateMarker = "private-marker-must-not-appear";
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 14, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Authoritative_evaluation_is_issued_and_repeatably_verified_with_explicit_risk_direction()
    {
        var fixture = await CreateFixtureAsync();

        var issued = await fixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);
        var json = HipTrustReceiptJson.Serialize(issued.Receipt!);
        var firstVerification = await fixture.Verification.VerifyAsync(
            Encoding.UTF8.GetBytes(json),
            CancellationToken.None);
        var secondVerification = await fixture.Verification.VerifyAsync(
            Encoding.UTF8.GetBytes(json),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(issued.Status, Is.EqualTo(HipTrustReceiptIssueStatus.Issued));
            Assert.That(issued.Receipt!.Scores.ContentRiskScore, Is.EqualTo(78));
            Assert.That(issued.Receipt.Scores.ContentRiskScore, Is.Not.EqualTo(Evaluation().ContentRiskScore));
            Assert.That(issued.Receipt.Scores.ContentRiskScoreHigherMeansMoreRisk, Is.True);
            Assert.That(firstVerification.Status, Is.EqualTo(HipTrustReceiptVerificationStatus.Verified));
            Assert.That(secondVerification.Status, Is.EqualTo(HipTrustReceiptVerificationStatus.Verified));
            Assert.That(firstVerification.EstablishesSafetyOrReputationBySignatureAlone, Is.False);
            Assert.That(json, Does.Not.Contain(PrivateMarker));
            Assert.That(json, Does.Not.Contain("plain-language reason"));
            Assert.That(fixture.Signer.SignCount, Is.EqualTo(1));
            Assert.That(fixture.ReceiptRepository.Count, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Versioned_formal_scoring_is_the_signed_score_source_when_available()
    {
        var fixture = await CreateFixtureAsync();
        var formalScoring = new HipScoringPipeline(new NoOpHipScoreConstraintPolicy()).Score(
            new HipScoringRequest(
                DomainTrustScore: 64,
                PageTrustScore: 52,
                ContentRiskScore: 47,
                HipScoreConfidence.Medium,
                HipEvidenceFreshness.Fresh,
                Reasons: ["Formal scoring test evidence."],
                Warnings: []));
        var evaluation = Evaluation() with { Scoring = formalScoring };

        var issued = await fixture.Issuance.IssueAsync(evaluation, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(issued.Status, Is.EqualTo(HipTrustReceiptIssueStatus.Issued));
            Assert.That(issued.Receipt!.Scores.DomainTrustScore, Is.EqualTo(formalScoring.DomainTrustScore));
            Assert.That(issued.Receipt.Scores.PageTrustScore, Is.EqualTo(formalScoring.PageTrustScore));
            Assert.That(issued.Receipt.Scores.ContentRiskScore, Is.EqualTo(formalScoring.ContentRiskScore));
            Assert.That(issued.Receipt.Scores.FinalHipScore, Is.EqualTo(formalScoring.FinalHipScore));
            Assert.That(issued.Receipt.Scores.ContentRiskScore, Is.Not.EqualTo(evaluation.OverallSafetyRiskScore));
        });
    }

    [Test]
    public async Task Conflicted_formal_scoring_uses_the_conservative_status_and_preserves_conflict_in_v1_codes()
    {
        var fixture = await CreateFixtureAsync();
        var formalScoring = new HipScoringPipeline(new NoOpHipScoreConstraintPolicy()).Score(
            new HipScoringRequest(
                DomainTrustScore: 90,
                PageTrustScore: 90,
                ContentRiskScore: 10,
                HipScoreConfidence.Conflicted,
                HipEvidenceFreshness.Fresh,
                Reasons: ["Formal evidence conflicts."],
                Warnings: []));
        var evaluation = WithoutLegacyRisk(Evaluation()) with
        {
            Status = SiteSafetyScanStatus.Clean,
            Scoring = formalScoring
        };

        var issued = await fixture.Issuance.IssueAsync(evaluation, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(issued.Status, Is.EqualTo(HipTrustReceiptIssueStatus.Issued));
            Assert.That(issued.Receipt!.Status, Is.EqualTo(HIP.Domain.Risk.RiskStatus.Unknown));
            Assert.That(issued.Receipt.Confidence, Is.EqualTo(HipTrustConfidence.Low));
            Assert.That(issued.Receipt.ReasonCodes, Does.Contain("status:unknown"));
            Assert.That(issued.Receipt.ReasonCodes, Does.Not.Contain("status:clean"));
            Assert.That(issued.Receipt.WarningCodes, Does.Contain("confidence:conflicted"));
        });
    }

    [TestCase(HipEvidenceFreshness.Missing, "evidence-freshness:missing")]
    [TestCase(HipEvidenceFreshness.Stale, "evidence-freshness:stale")]
    public async Task Incomplete_formal_evidence_preserves_freshness_in_v1_warning_codes(
        HipEvidenceFreshness freshness,
        string expectedWarningCode)
    {
        var fixture = await CreateFixtureAsync();
        var formalScoring = new HipScoringPipeline(new NoOpHipScoreConstraintPolicy()).Score(
            new HipScoringRequest(
                DomainTrustScore: 90,
                PageTrustScore: 90,
                ContentRiskScore: 10,
                HipScoreConfidence.High,
                freshness,
                Reasons: ["Formal evidence freshness test."],
                Warnings: []));
        var evaluation = WithoutLegacyRisk(Evaluation()) with
        {
            Status = SiteSafetyScanStatus.Clean,
            Scoring = formalScoring
        };

        var issued = await fixture.Issuance.IssueAsync(evaluation, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(issued.Status, Is.EqualTo(HipTrustReceiptIssueStatus.Issued));
            Assert.That(issued.Receipt!.Status, Is.EqualTo(HIP.Domain.Risk.RiskStatus.LimitedTrustData));
            Assert.That(issued.Receipt.ReasonCodes, Does.Contain("status:limitedtrustdata"));
            Assert.That(issued.Receipt.ReasonCodes, Does.Not.Contain("status:clean"));
            Assert.That(issued.Receipt.WarningCodes, Does.Contain(expectedWarningCode));
        });
    }

    [Test]
    public async Task Formal_reason_catalog_codes_are_projected_into_the_existing_v1_receipt_shape()
    {
        var fixture = await CreateFixtureAsync();
        var formalScoring = new HipScoringPipeline(new HipMandatoryScoreConstraintPolicy()).Score(
            new HipScoringRequest(
                DomainTrustScore: 90,
                PageTrustScore: 90,
                ContentRiskScore: 10,
                HipScoreConfidence.High,
                HipEvidenceFreshness.Fresh,
                Reasons: ["Formal confirmed-threat evidence."],
                Warnings: [],
                EvidenceContext: new HipScoringEvidenceContext(
                [
                    new(HipScoringEvidenceFactType.ConfirmedMalware, "site-safety:confirmed-malware")
                ])));
        var evaluation = WithoutLegacyRisk(Evaluation()) with
        {
            Status = SiteSafetyScanStatus.Dangerous,
            Scoring = formalScoring
        };

        var issued = await fixture.Issuance.IssueAsync(evaluation, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(issued.Status, Is.EqualTo(HipTrustReceiptIssueStatus.Issued));
            Assert.That(issued.Receipt!.Scores.FinalHipScore, Is.EqualTo(9));
            Assert.That(issued.Receipt.ReasonCodes, Does.Contain("score-cap:confirmed-threat"));
            Assert.That(issued.Receipt.WarningCodes, Does.Contain("warning:confirmed-threat"));
        });
    }

    [Test]
    public async Task Formal_catalog_and_legacy_warning_codes_remain_bounded_at_the_receipt_limit()
    {
        var fixture = await CreateFixtureAsync();
        var entries = Enumerable.Range(0, 26)
            .Select(index => new HipScoringReasonEntry(
                $"catalog:test-{index}",
                "Bounded receipt catalog entry.",
                $"warning:test-{index}",
                "Bounded receipt warning.",
                new HipScoreImpact(HipScoreImpactKind.None, null),
                "test:receipt",
                null,
                HipEvidencePrivacyClassification.DerivedMetadata))
            .ToArray();
        var formalScoring = new HipScoringPipeline(new NoOpHipScoreConstraintPolicy()).Score(
            new HipScoringRequest(
                42,
                25,
                78,
                HipScoreConfidence.High,
                HipEvidenceFreshness.Fresh,
                Reasons: ["Bounded receipt catalog test."],
                Warnings: [],
                ReasonEntries: entries));
        var evaluation = Evaluation() with
        {
            Scoring = formalScoring,
            MatchedRules = [Rule("warning-rule", "Warning rule", riskImpact: 40) with
            {
                Warning = "Rule warning must remain within the receipt limit."
            }]
        };

        var issued = await fixture.Issuance.IssueAsync(evaluation, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(issued.Status, Is.EqualTo(HipTrustReceiptIssueStatus.Issued));
            Assert.That(issued.Receipt!.WarningCodes.Count, Is.EqualTo(HipTrustReceipt.MaximumCodesPerCollection));
        });
    }

    [Test]
    public async Task Same_authoritative_evaluation_is_idempotent_and_changed_evidence_conflicts_before_resigning()
    {
        var fixture = await CreateFixtureAsync();
        var evaluation = Evaluation();

        var first = await fixture.Issuance.IssueAsync(evaluation, CancellationToken.None);
        var retry = await fixture.Issuance.IssueAsync(evaluation, CancellationToken.None);
        var changed = await fixture.Issuance.IssueAsync(
            evaluation with { OverallSafetyRiskScore = evaluation.OverallSafetyRiskScore + 1 },
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(first.Status, Is.EqualTo(HipTrustReceiptIssueStatus.Issued));
            Assert.That(retry.Status, Is.EqualTo(HipTrustReceiptIssueStatus.Existing));
            Assert.That(
                HipTrustReceiptJson.Serialize(retry.Receipt!),
                Is.EqualTo(HipTrustReceiptJson.Serialize(first.Receipt!)));
            Assert.That(changed.Status, Is.EqualTo(HipTrustReceiptIssueStatus.Conflict));
            Assert.That(fixture.Signer.SignCount, Is.EqualTo(1));
            Assert.That(fixture.ReceiptRepository.Count, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Changed_signed_score_fails_verification_without_affecting_the_stored_receipt()
    {
        var fixture = await CreateFixtureAsync();
        var issued = await fixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);
        var receipt = issued.Receipt!;
        var tampered = Copy(
            receipt,
            scores: new HipTrustReceiptScores(
                receipt.Scores.DomainTrustScore,
                receipt.Scores.FinalHipScore,
                receipt.Scores.PageTrustScore,
                receipt.Scores.ContentRiskScore!.Value - 1));

        var result = await fixture.Verification.VerifyAsync(
            Encoding.UTF8.GetBytes(HipTrustReceiptJson.Serialize(tampered)),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipTrustReceiptVerificationStatus.InvalidSignature));
            Assert.That(fixture.ReceiptRepository.Count, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Every_signed_receipt_field_is_tamper_evident()
    {
        var fixture = await CreateFixtureAsync();
        var issued = await fixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);
        var originalJson = HipTrustReceiptJson.Serialize(issued.Receipt!);
        string[] signedFields =
        [
            "documentType",
            "version",
            "receiptId",
            "relatedEvaluationId",
            "subject.type",
            "subject.id",
            "evaluatedAtUtc",
            "issuedAtUtc",
            "expiresAtUtc",
            "scores.domainTrustScore",
            "scores.pageTrustScore",
            "scores.contentRiskScore",
            "scores.finalHipScore",
            "status",
            "confidence",
            "reasonCodes",
            "warningCodes",
            "policyVersion",
            "ruleSetVersion",
            "evidenceDigest.algorithm",
            "evidenceDigest.value",
            "issuer.id",
            "signature.scope",
            "signature.keyId",
            "signature.algorithm",
            "signature.algorithmFamily",
            "signature.canonicalization",
            "signature.value"
        ];

        foreach (var field in signedFields)
        {
            var tamperedJson = Tamper(originalJson, field);
            var result = await fixture.Verification.VerifyAsync(
                Encoding.UTF8.GetBytes(tamperedJson),
                CancellationToken.None);

            Assert.Multiple(() =>
            {
                Assert.That(tamperedJson, Is.Not.EqualTo(originalJson), field);
                Assert.That(
                    result.Status,
                    Is.Not.EqualTo(HipTrustReceiptVerificationStatus.Verified),
                    field);
            });
        }
    }

    [Test]
    public async Task Authentic_receipt_expires_at_its_signed_boundary()
    {
        var fixture = await CreateFixtureAsync();
        var issued = await fixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);
        var expiredVerifier = CreateVerificationService(
            fixture.KeyRepository,
            fixture.Provider,
            issued.Receipt!.ExpiresAtUtc);

        var result = await expiredVerifier.VerifyAsync(
            Encoding.UTF8.GetBytes(HipTrustReceiptJson.Serialize(issued.Receipt)),
            CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(HipTrustReceiptVerificationStatus.Expired));
    }

    [Test]
    public async Task Receipt_issued_beyond_the_allowed_clock_skew_is_rejected_before_crypto()
    {
        var fixture = await CreateFixtureAsync();
        var issued = await fixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);
        var futureIssuedAt = Now + HipTrustReceiptPolicy.Default.AllowedClockSkew + TimeSpan.FromMilliseconds(1);
        var futureReceipt = Copy(
            issued.Receipt!,
            issuedAtUtc: futureIssuedAt,
            expiresAtUtc: futureIssuedAt + HipTrustReceiptPolicy.Default.ValidityPeriod);
        var verifier = new HipTrustReceiptVerificationService(
            new ThrowingSignedDocumentVerifier(),
            AuthorizedIssuerPolicy(),
            HipTrustReceiptPolicy.Default,
            new FixedTimeProvider(Now));

        var result = await verifier.VerifyAsync(
            Encoding.UTF8.GetBytes(HipTrustReceiptJson.Serialize(futureReceipt)),
            CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(HipTrustReceiptVerificationStatus.TimestampOutsideTolerance));
    }

    [Test]
    public async Task Receipt_validity_beyond_the_policy_limit_is_rejected_before_crypto()
    {
        var fixture = await CreateFixtureAsync();
        var issued = await fixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);
        var overlongReceipt = Copy(
            issued.Receipt!,
            expiresAtUtc: issued.Receipt!.IssuedAtUtc +
                HipTrustReceiptPolicy.Default.ValidityPeriod +
                TimeSpan.FromMilliseconds(1));
        var verifier = new HipTrustReceiptVerificationService(
            new ThrowingSignedDocumentVerifier(),
            AuthorizedIssuerPolicy(),
            HipTrustReceiptPolicy.Default,
            new FixedTimeProvider(Now));

        var result = await verifier.VerifyAsync(
            Encoding.UTF8.GetBytes(HipTrustReceiptJson.Serialize(overlongReceipt)),
            CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(HipTrustReceiptVerificationStatus.ValidityWindowExceeded));
    }

    [Test]
    public async Task Issuer_revocation_invalidates_an_existing_receipt()
    {
        var fixture = await CreateFixtureAsync();
        var issued = await fixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);
        var current = await fixture.KeyRepository.GetRegisteredIdentityAsync(IssuerId, CancellationToken.None);
        var identityRepository = (IHipIdentityRepository)fixture.KeyRepository;
        var revoked = current! with { VerificationStatus = VerificationStatus.Revoked };
        var updated = await identityRepository.TryUpdateAsync(current, revoked, CancellationToken.None);

        var result = await fixture.Verification.VerifyAsync(
            Encoding.UTF8.GetBytes(HipTrustReceiptJson.Serialize(issued.Receipt!)),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(updated, Is.True);
            Assert.That(result.Status, Is.EqualTo(HipTrustReceiptVerificationStatus.IssuerRevoked));
        });
    }

    [TestCase(
        HipSignedDocumentVerificationStatus.ProviderUnavailable,
        HipTrustReceiptVerificationStatus.ProviderUnavailable)]
    [TestCase(
        HipSignedDocumentVerificationStatus.VerificationStateUnavailable,
        HipTrustReceiptVerificationStatus.VerificationStateUnavailable)]
    public async Task Provider_and_verification_state_failures_map_to_typed_fail_closed_outcomes(
        HipSignedDocumentVerificationStatus documentStatus,
        HipTrustReceiptVerificationStatus expectedStatus)
    {
        var fixture = await CreateFixtureAsync();
        var issued = await fixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);
        var verifier = new HipTrustReceiptVerificationService(
            new FixedSignedDocumentVerifier(documentStatus),
            AuthorizedIssuerPolicy(),
            HipTrustReceiptPolicy.Default,
            new FixedTimeProvider(Now));

        var result = await verifier.VerifyAsync(
            Encoding.UTF8.GetBytes(HipTrustReceiptJson.Serialize(issued.Receipt!)),
            CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(expectedStatus));
    }

    [Test]
    public async Task Unexpected_signed_document_verifier_failure_is_typed_and_fail_closed()
    {
        var fixture = await CreateFixtureAsync();
        var issued = await fixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);
        var verifier = new HipTrustReceiptVerificationService(
            new ThrowingSignedDocumentVerifier(),
            AuthorizedIssuerPolicy(),
            HipTrustReceiptPolicy.Default,
            new FixedTimeProvider(Now));

        var result = await verifier.VerifyAsync(
            Encoding.UTF8.GetBytes(HipTrustReceiptJson.Serialize(issued.Receipt!)),
            CancellationToken.None);

        Assert.That(
            result.Status,
            Is.EqualTo(HipTrustReceiptVerificationStatus.VerificationStateUnavailable));
    }

    [Test]
    public async Task Valid_signature_from_a_non_authorized_receipt_signer_is_rejected_before_identity_crypto()
    {
        var fixture = await CreateFixtureAsync();
        var issued = await fixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);
        var verifier = new HipTrustReceiptVerificationService(
            new ThrowingSignedDocumentVerifier(),
            HipTrustReceiptIssuerPolicy.Default,
            HipTrustReceiptPolicy.Default,
            new FixedTimeProvider(Now));

        var result = await verifier.VerifyAsync(
            Encoding.UTF8.GetBytes(HipTrustReceiptJson.Serialize(issued.Receipt!)),
            CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(HipTrustReceiptVerificationStatus.IssuerNotAuthorized));
    }

    [Test]
    public async Task Managed_signer_must_be_explicitly_authorized_for_receipt_use()
    {
        var fixture = await CreateFixtureAsync(issuerPolicy: HipTrustReceiptIssuerPolicy.Default);

        var result = await fixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipTrustReceiptIssueStatus.SignerNotAuthorized));
            Assert.That(fixture.Signer.SignCount, Is.Zero);
            Assert.That(fixture.ReceiptRepository.Count, Is.Zero);
        });
    }

    [Test]
    public void Evidence_digest_is_stable_when_tied_rule_identities_arrive_in_a_different_order()
    {
        var first = Rule("duplicate-rule", "First", riskImpact: 10);
        var second = Rule("duplicate-rule", "Second", riskImpact: 20);
        var forward = Evaluation() with { MatchedRules = [first, second] };
        var reverse = Evaluation() with { MatchedRules = [second, first] };
        var service = new HipTrustReceiptEvidenceDigestService(new Rfc8785CanonicalJsonService());

        var forwardDigest = service.Compute(
            forward,
            ["status:highrisk"],
            ["risk:phishing"],
            HipTrustReceiptPolicy.Default);
        var reverseDigest = service.Compute(
            reverse,
            ["status:highrisk"],
            ["risk:phishing"],
            HipTrustReceiptPolicy.Default);

        Assert.That(reverseDigest, Is.EqualTo(forwardDigest));
    }

    [Test]
    public void Evidence_digest_binds_typed_formal_scoring_facts()
    {
        var pipeline = new HipScoringPipeline(new NoOpHipScoreConstraintPolicy());
        var unknownTarget = pipeline.Score(new HipScoringRequest(
            60,
            60,
            40,
            HipScoreConfidence.Low,
            HipEvidenceFreshness.Missing,
            ["Typed fact digest test."],
            [],
            EvidenceContext: new HipScoringEvidenceContext(
            [
                new(HipScoringEvidenceFactType.UnknownTarget, "test:unknown-target")
            ])));
        var limitedEvidence = pipeline.Score(new HipScoringRequest(
            60,
            60,
            40,
            HipScoreConfidence.Low,
            HipEvidenceFreshness.Missing,
            ["Typed fact digest test."],
            [],
            EvidenceContext: new HipScoringEvidenceContext(
            [
                new(HipScoringEvidenceFactType.LimitedEvidence, "test:limited-evidence")
            ])));
        var service = new HipTrustReceiptEvidenceDigestService(new Rfc8785CanonicalJsonService());
        var policy = HipTrustReceiptPolicy.Default;

        var first = service.Compute(
            Evaluation() with { Scoring = unknownTarget },
            ["status:limitedtrustdata"],
            ["evidence-freshness:missing"],
            policy);
        var second = service.Compute(
            Evaluation() with { Scoring = limitedEvidence },
            ["status:limitedtrustdata"],
            ["evidence-freshness:missing"],
            policy);

        Assert.That(second, Is.Not.EqualTo(first));
    }

    [Test]
    public async Task Revoked_signing_key_invalidates_an_existing_receipt()
    {
        var fixture = await CreateFixtureAsync();
        var issued = await fixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);
        var ring = await fixture.KeyRepository.GetAsync(IssuerId, CancellationToken.None);
        var replacement = fixture.Provider.GenerateKeyPair();
        await fixture.Lifecycle.EmergencyReplaceAsync(
            new EmergencyReplaceSigningKeyRequest(
                IssuerId,
                KeyId,
                ring!.Version,
                "receipt-key-2",
                replacement.Algorithm,
                replacement.PublicKey,
                "security-operator",
                "Receipt signing key compromise",
                Now.AddMilliseconds(1)),
            CancellationToken.None);

        var result = await fixture.Verification.VerifyAsync(
            Encoding.UTF8.GetBytes(HipTrustReceiptJson.Serialize(issued.Receipt!)),
            CancellationToken.None);
        var reissue = await fixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipTrustReceiptVerificationStatus.KeyRevoked));
            Assert.That(reissue.Status, Is.EqualTo(HipTrustReceiptIssueStatus.VerificationFailed));
        });
    }

    [Test]
    public async Task Stale_evaluation_and_unavailable_signer_fail_closed_without_persistence()
    {
        var staleFixture = await CreateFixtureAsync();
        var stale = await staleFixture.Issuance.IssueAsync(
            Evaluation() with { ScannedAtUtc = Now.AddMinutes(-6) },
            CancellationToken.None);
        var unavailableFixture = await CreateFixtureAsync(new UnavailableManagedTrustReceiptSigner());
        var unavailable = await unavailableFixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);
        var malformedFixture = await CreateFixtureAsync();
        var malformed = await malformedFixture.Issuance.IssueAsync(
            Evaluation() with { ScanId = "invalid evaluation id" },
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(stale.Status, Is.EqualTo(HipTrustReceiptIssueStatus.InvalidEvaluation));
            Assert.That(staleFixture.ReceiptRepository.Count, Is.Zero);
            Assert.That(unavailable.Status, Is.EqualTo(HipTrustReceiptIssueStatus.SignerUnavailable));
            Assert.That(unavailableFixture.ReceiptRepository.Count, Is.Zero);
            Assert.That(malformed.Status, Is.EqualTo(HipTrustReceiptIssueStatus.InvalidEvaluation));
            Assert.That(malformedFixture.Signer.SignCount, Is.Zero);
            Assert.That(malformedFixture.ReceiptRepository.Count, Is.Zero);
        });
    }

    [TestCase("http://receipt.example/path")]
    [TestCase("/relative/path")]
    [TestCase("https://different.example/path")]
    public async Task Authoritative_evaluation_requires_a_matching_absolute_https_target(string evaluationUrl)
    {
        var fixture = await CreateFixtureAsync();

        var result = await fixture.Issuance.IssueAsync(
            Evaluation() with { Url = evaluationUrl },
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipTrustReceiptIssueStatus.InvalidEvaluation));
            Assert.That(fixture.Signer.SignCount, Is.Zero);
            Assert.That(fixture.ReceiptRepository.Count, Is.Zero);
        });
    }

    [Test]
    public async Task Authoritative_evaluation_accepts_an_equivalent_normalized_https_host()
    {
        var fixture = await CreateFixtureAsync();

        var result = await fixture.Issuance.IssueAsync(
            Evaluation() with { Url = "https://RECEIPT.EXAMPLE./path" },
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipTrustReceiptIssueStatus.Issued));
            Assert.That(result.Receipt?.Subject.Id, Is.EqualTo("receipt.example"));
            Assert.That(fixture.Signer.SignCount, Is.EqualTo(1));
            Assert.That(fixture.ReceiptRepository.Count, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Invalid_managed_signature_is_verified_before_storage_and_fails_closed()
    {
        var fixture = await CreateFixtureAsync(new InvalidManagedSigner());

        var result = await fixture.Issuance.IssueAsync(Evaluation(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipTrustReceiptIssueStatus.VerificationFailed));
            Assert.That(fixture.ReceiptRepository.Count, Is.Zero);
        });
    }

    private static async Task<Fixture> CreateFixtureAsync(
        IManagedTrustReceiptSigner? signer = null,
        HipTrustReceiptIssuerPolicy? issuerPolicy = null)
    {
        var provider = new DevelopmentHipCryptoProvider();
        var keyPair = provider.GenerateKeyPair();
        var keyRepository = new InMemorySigningKeyLifecycleRepository();
        var lifecycle = new SigningKeyLifecycleService(
            keyRepository,
            new AuditLogService(keyRepository),
            new HipPublicKeyFingerprintService([provider]));
        await lifecycle.RegisterIdentityAsync(
            new RegisterIdentitySigningKeyRequest(
                new HipIdentity(
                    IssuerId,
                    IdentitySubjectType.Website,
                    "HIP Receipt Issuer",
                    keyPair.PublicKey,
                    keyPair.Algorithm,
                    VerificationStatus.Verified,
                    Now.AddMinutes(-10),
                    "receipt-issuer.example"),
                KeyId,
                "system:test",
                "Register receipt signing key",
                Now.AddMinutes(-10)),
            CancellationToken.None);
        var documentVerifier = new HipSignedDocumentVerifier(
            keyRepository,
            new HipSignatureProviderFactory([provider]),
            SignatureProviderRuntimePolicy.ForDevelopment(DevelopmentHipCryptoProvider.Algorithm),
            new Rfc8785CanonicalJsonService());
        var clock = new FixedTimeProvider(Now);
        var effectiveIssuerPolicy = issuerPolicy ?? AuthorizedIssuerPolicy();
        var verification = new HipTrustReceiptVerificationService(
            documentVerifier,
            effectiveIssuerPolicy,
            HipTrustReceiptPolicy.Default,
            clock);
        var receiptRepository = new TestReceiptRepository();
        var recordingSigner = signer as RecordingManagedSigner ??
            new RecordingManagedSigner(provider, keyPair.PrivateKey);
        var issuance = new HipTrustReceiptIssuanceService(
            signer ?? recordingSigner,
            new HipTrustReceiptEvidenceDigestService(new Rfc8785CanonicalJsonService()),
            new Rfc8785CanonicalJsonService(),
            verification,
            receiptRepository,
            HipTrustReceiptPolicy.Default,
            effectiveIssuerPolicy,
            clock);
        return new Fixture(
            issuance,
            verification,
            receiptRepository,
            recordingSigner,
            lifecycle,
            keyRepository,
            provider);
    }

    private static SiteSafetyScanResult WithoutLegacyRisk(SiteSafetyScanResult evaluation) => evaluation with
    {
        MalwareRiskScore = 0,
        PhishingRiskScore = 0,
        RedirectRiskScore = 0,
        ScriptRiskScore = 0,
        DownloadRiskScore = 0,
        FormRiskScore = 0,
        ReputationRiskScore = 0,
        OverallSafetyRiskScore = 0
    };

    private static SiteSafetyScanResult Evaluation() => new(
        "site-safety-evaluation-1",
        "https://receipt.example/path?private=value",
        "receipt.example",
        Now.AddMinutes(-1),
        MalwareRiskScore: 80,
        PhishingRiskScore: 70,
        RedirectRiskScore: 20,
        ScriptRiskScore: 35,
        DownloadRiskScore: 40,
        FormRiskScore: 45,
        ReputationRiskScore: 30,
        OverallSafetyRiskScore: 78,
        SiteSafetyScanStatus.HighRisk,
        $"{PrivateMarker} summary",
        [$"{PrivateMarker} plain-language reason"],
        [$"{PrivateMarker} warning"],
        [],
        [],
        "High",
        DomainTrustScore: 42,
        PageTrustScore: 25,
        ContentRiskScore: 22,
        FinalHipScore: 30,
        [],
        new SiteSafetyScoreImpact(42, 25, 22, 30, []),
        []);

    private static SiteSafetyRuleResult Rule(
        string ruleId,
        string name,
        int riskImpact) => new(
        ruleId,
        name,
        "Deterministic receipt evidence ordering test.",
        SiteSafetyRuleSource.BuiltIn,
        SiteSafetyRuleCollectionType.PhishingRiskRules,
        SiteSafetyRiskCategory.Phishing,
        riskImpact,
        0,
        "Privacy-safe reason.",
        null,
        SiteSafetyRuleSeverity.Medium,
        SiteSafetyEvidenceQuality.Medium,
        null,
        0,
        false,
        false);

    private static HipTrustReceiptVerificationService CreateVerificationService(
        ISigningKeyLifecycleRepository keyRepository,
        DevelopmentHipCryptoProvider provider,
        DateTimeOffset utcNow) => new(
        new HipSignedDocumentVerifier(
            keyRepository,
            new HipSignatureProviderFactory([provider]),
            SignatureProviderRuntimePolicy.ForDevelopment(DevelopmentHipCryptoProvider.Algorithm),
            new Rfc8785CanonicalJsonService()),
        AuthorizedIssuerPolicy(),
        HipTrustReceiptPolicy.Default,
        new FixedTimeProvider(utcNow));

    private static HipTrustReceiptIssuerPolicy AuthorizedIssuerPolicy() => new(
        [new HipTrustReceiptAuthorizedSigner(IssuerId, KeyId)]);

    private static string Tamper(string receiptJson, string field)
    {
        var root = JsonNode.Parse(receiptJson)?.AsObject()
            ?? throw new InvalidOperationException("The issued receipt JSON was not an object.");
        switch (field)
        {
            case "documentType": root["documentType"] = "hip-envelope"; break;
            case "version": root["version"] = "9.0"; break;
            case "receiptId": root["receiptId"] = "receipt:tampered"; break;
            case "relatedEvaluationId": root["relatedEvaluationId"] = "evaluation:tampered"; break;
            case "subject.type": root["subject"]!["type"] = "domain"; break;
            case "subject.id": root["subject"]!["id"] = "tampered.example"; break;
            case "evaluatedAtUtc": root["evaluatedAtUtc"] = "2026-07-19T12:58:00.000Z"; break;
            case "issuedAtUtc": root["issuedAtUtc"] = "2026-07-19T14:00:00.001Z"; break;
            case "expiresAtUtc": root["expiresAtUtc"] = "2026-07-20T13:59:59.000Z"; break;
            case "scores.domainTrustScore": root["scores"]!["domainTrustScore"] = 41; break;
            case "scores.pageTrustScore": root["scores"]!["pageTrustScore"] = 24; break;
            case "scores.contentRiskScore": root["scores"]!["contentRiskScore"] = 77; break;
            case "scores.finalHipScore": root["scores"]!["finalHipScore"] = 29; break;
            case "status": root["status"] = "dangerous"; break;
            case "confidence": root["confidence"] = "medium"; break;
            case "reasonCodes": root["reasonCodes"] = new JsonArray("status:dangerous"); break;
            case "warningCodes": root["warningCodes"] = new JsonArray(); break;
            case "policyVersion": root["policyVersion"] = "site-safety-policy-v2"; break;
            case "ruleSetVersion": root["ruleSetVersion"] = "site-safety-rules-v2"; break;
            case "evidenceDigest.algorithm": root["evidenceDigest"]!["algorithm"] = "sha512"; break;
            case "evidenceDigest.value":
                var value = root["evidenceDigest"]!["value"]!.GetValue<string>();
                root["evidenceDigest"]!["value"] = $"{(value[0] == '0' ? '1' : '0')}{value[1..]}";
                break;
            case "issuer.id": root["issuer"]!["id"] = "hip:web:other.example"; break;
            case "signature.scope": root["signature"]!["scope"] = "trust"; break;
            case "signature.keyId": root["signature"]!["keyId"] = "receipt-key-other"; break;
            case "signature.algorithm": root["signature"]!["algorithm"] = "other-algorithm"; break;
            case "signature.algorithmFamily": root["signature"]!["algorithmFamily"] = "postQuantum"; break;
            case "signature.canonicalization": root["signature"]!["canonicalization"] = "other"; break;
            case "signature.value": root["signature"]!["value"] = "invalid-signature"; break;
            default: throw new ArgumentOutOfRangeException(nameof(field), field, "Unknown signed receipt field.");
        }

        return root.ToJsonString();
    }

    private static HipTrustReceipt Copy(
        HipTrustReceipt source,
        HipTrustReceiptScores? scores = null,
        DateTimeOffset? issuedAtUtc = null,
        DateTimeOffset? expiresAtUtc = null) => new(
        source.DocumentType,
        source.Version,
        source.ReceiptId,
        source.RelatedEvaluationId,
        source.Subject,
        source.EvaluatedAtUtc,
        issuedAtUtc ?? source.IssuedAtUtc,
        expiresAtUtc ?? source.ExpiresAtUtc,
        scores ?? source.Scores,
        source.Status,
        source.Confidence,
        source.ReasonCodes,
        source.WarningCodes,
        source.PolicyVersion,
        source.RuleSetVersion,
        source.EvidenceDigest,
        source.Issuer,
        source.Signature);

    private sealed record Fixture(
        HipTrustReceiptIssuanceService Issuance,
        HipTrustReceiptVerificationService Verification,
        TestReceiptRepository ReceiptRepository,
        RecordingManagedSigner Signer,
        SigningKeyLifecycleService Lifecycle,
        InMemorySigningKeyLifecycleRepository KeyRepository,
        DevelopmentHipCryptoProvider Provider);

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    private sealed class RecordingManagedSigner(
        DevelopmentHipCryptoProvider provider,
        string privateKey) : IManagedTrustReceiptSigner
    {
        public int SignCount { get; private set; }

        public Task<HipManagedTrustReceiptSigningKey> GetSigningKeyAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new HipManagedTrustReceiptSigningKey(
                IssuerId,
                KeyId,
                provider.Capabilities.Algorithm,
                provider.Capabilities.AlgorithmFamily));
        }

        public Task<string> SignHashAsync(
            HipManagedTrustReceiptSigningKey signingKey,
            string contentHash,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SignCount++;
            return Task.FromResult(provider.SignHash(contentHash, privateKey));
        }
    }

    private sealed class InvalidManagedSigner : IManagedTrustReceiptSigner
    {
        public Task<HipManagedTrustReceiptSigningKey> GetSigningKeyAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new HipManagedTrustReceiptSigningKey(
                IssuerId,
                KeyId,
                DevelopmentHipCryptoProvider.Algorithm,
                SignatureAlgorithmFamily.Unknown));

        public Task<string> SignHashAsync(
            HipManagedTrustReceiptSigningKey signingKey,
            string contentHash,
            CancellationToken cancellationToken) => Task.FromResult("invalid-signature");
    }

    private sealed class FixedSignedDocumentVerifier(HipSignedDocumentVerificationStatus status)
        : IHipSignedDocumentVerifier
    {
        public Task<HipSignedDocumentVerificationResult> VerifyAsync(
            HipSignedDocumentVerificationRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new HipSignedDocumentVerificationResult(status));
        }
    }

    private sealed class ThrowingSignedDocumentVerifier : IHipSignedDocumentVerifier
    {
        public Task<HipSignedDocumentVerificationResult> VerifyAsync(
            HipSignedDocumentVerificationRequest request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Synthetic verification-state failure.");
    }

    private sealed class TestReceiptRepository : IHipTrustReceiptRepository
    {
        private readonly object gate = new();
        private readonly Dictionary<string, HipStoredTrustReceipt> byId = new(StringComparer.Ordinal);
        private readonly Dictionary<string, HipStoredTrustReceipt> byEvaluation = new(StringComparer.Ordinal);

        public int Count
        {
            get
            {
                lock (gate)
                {
                    return byId.Count;
                }
            }
        }

        public Task<HipStoredTrustReceipt?> GetByIdAsync(
            string receiptId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (gate)
            {
                return Task.FromResult(byId.GetValueOrDefault(receiptId));
            }
        }

        public Task<HipStoredTrustReceipt?> GetByRelatedEvaluationIdAsync(
            string relatedEvaluationId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (gate)
            {
                return Task.FromResult(byEvaluation.GetValueOrDefault(relatedEvaluationId));
            }
        }

        public Task<HipTrustReceiptRepositoryWriteResult> TryCreateAsync(
            HipStoredTrustReceipt receipt,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (gate)
            {
                if (byId.TryGetValue(receipt.Receipt.ReceiptId, out var byIdExisting) ||
                    byEvaluation.TryGetValue(receipt.Receipt.RelatedEvaluationId, out byIdExisting))
                {
                    var same = string.Equals(
                        byIdExisting.SourceEvaluationDigest,
                        receipt.SourceEvaluationDigest,
                        StringComparison.Ordinal);
                    return Task.FromResult(new HipTrustReceiptRepositoryWriteResult(
                        same
                            ? HipTrustReceiptRepositoryWriteStatus.ExistingSame
                            : HipTrustReceiptRepositoryWriteStatus.Conflict,
                        byIdExisting));
                }

                byId.Add(receipt.Receipt.ReceiptId, receipt);
                byEvaluation.Add(receipt.Receipt.RelatedEvaluationId, receipt);
                return Task.FromResult(new HipTrustReceiptRepositoryWriteResult(
                    HipTrustReceiptRepositoryWriteStatus.Created,
                    receipt));
            }
        }
    }
}
