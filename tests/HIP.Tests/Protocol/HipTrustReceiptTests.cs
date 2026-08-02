using System.Text;
using System.Text.Json;
using HIP.Application.Protocol;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;
using HIP.Domain.Risk;

namespace HIP.Tests.Protocol;

[NonParallelizable]
public sealed class HipTrustReceiptTests
{
    [Test]
    public void Version_one_receipt_matches_stable_wire_fixture()
    {
        var receipt = ValidReceipt();
        var expected = ReadFixture("hip-trust-receipt-v1.json");

        var json = HipTrustReceiptJson.Serialize(receipt);
        var roundTrip = HipTrustReceiptJson.Deserialize(json);

        Assert.Multiple(() =>
        {
            Assert.That(json, Is.EqualTo(expected));
            Assert.That(roundTrip.DocumentType, Is.EqualTo(HipTrustReceipt.TrustReceiptDocumentType));
            Assert.That(roundTrip.Version, Is.EqualTo(HipProtocolVersion.Current));
            Assert.That(roundTrip.ReceiptId, Is.EqualTo("receipt-20260719-0001"));
            Assert.That(roundTrip.RelatedEvaluationId, Is.EqualTo("scan-20260719-0001"));
            Assert.That(roundTrip.Subject.Type, Is.EqualTo(IdentitySubjectType.Website));
            Assert.That(roundTrip.Scores.DomainTrustScore, Is.EqualTo(82));
            Assert.That(roundTrip.Scores.PageTrustScore, Is.EqualTo(61));
            Assert.That(roundTrip.Scores.ContentRiskScore, Is.EqualTo(39));
            Assert.That(roundTrip.Scores.FinalHipScore, Is.EqualTo(74));
            Assert.That(roundTrip.Status, Is.EqualTo(RiskStatus.ProbablySafe));
            Assert.That(roundTrip.Confidence, Is.EqualTo(HipTrustConfidence.High));
            Assert.That(roundTrip.ReasonCodes, Is.EqualTo(new[] { "domain-verified", "tls-valid" }));
            Assert.That(roundTrip.WarningCodes, Is.EqualTo(new[] { "limited-content-evidence" }));
            Assert.That(roundTrip.EvidenceDigest.ToPrefixedString(), Is.EqualTo($"sha256:{new string('d', 64)}"));
            Assert.That(roundTrip.Signature.Canonicalization, Is.EqualTo(HipProtocolSignature.Rfc8785Canonicalization));
        });
    }

    [Test]
    public void Receipt_signing_payload_removes_only_the_signature_value_and_matches_stable_fixture()
    {
        var receipt = ValidReceipt();
        var signingPayload = HipTrustReceiptSigningPayload.Create(receipt);
        var canonical = new Rfc8785CanonicalJsonService().Canonicalize(signingPayload);
        var expected = ReadFixture("hip-trust-receipt-v1.signing.canonical.json");
        using var document = JsonDocument.Parse(signingPayload);
        var signature = document.RootElement.GetProperty("signature");

        Assert.Multiple(() =>
        {
            Assert.That(Encoding.UTF8.GetString(canonical), Is.EqualTo(expected));
            Assert.That(signature.TryGetProperty("value", out _), Is.False);
            Assert.That(signature.GetProperty("scope").GetString(), Is.EqualTo(HipProtocolSignature.OriginAndIntegrityScope));
            Assert.That(signature.GetProperty("keyId").GetString(), Is.EqualTo(receipt.Signature.KeyId));
            Assert.That(signature.GetProperty("algorithm").GetString(), Is.EqualTo(receipt.Signature.Algorithm));
            Assert.That(signature.GetProperty("algorithmFamily").GetString(), Is.EqualTo("unknown"));
            Assert.That(signature.GetProperty("canonicalization").GetString(), Is.EqualTo("RFC8785"));
        });
    }

    [Test]
    public void Receipt_codes_are_copied_sorted_and_deduplicated_by_validation()
    {
        var reasons = new List<string> { "tls-valid", "domain-verified" };
        var warnings = new List<string> { "limited-content-evidence" };
        var receipt = ValidReceipt(reasonCodes: reasons, warningCodes: warnings);

        reasons.Clear();
        warnings.Clear();

        Assert.Multiple(() =>
        {
            Assert.That(receipt.ReasonCodes, Is.EqualTo(new[] { "domain-verified", "tls-valid" }));
            Assert.That(receipt.WarningCodes, Is.EqualTo(new[] { "limited-content-evidence" }));
            Assert.Throws<ArgumentException>(() => ValidReceipt(reasonCodes: new[] { "duplicate", "duplicate" }));
            Assert.Throws<ArgumentException>(() => ValidReceipt(reasonCodes: new[] { "Not-Canonical" }));
            Assert.Throws<ArgumentOutOfRangeException>(() => ValidReceipt(reasonCodes: Array.Empty<string>()));
        });
    }

    [Test]
    public void Receipt_scores_are_bounded_and_preserve_explicit_risk_direction()
    {
        var scores = new HipTrustReceiptScores(
            domainTrustScore: 82,
            finalHipScore: 74,
            pageTrustScore: 61,
            contentRiskScore: 39);

        Assert.Multiple(() =>
        {
            Assert.That(scores.ContentRiskScoreHigherMeansMoreRisk, Is.True);
            Assert.Throws<ArgumentOutOfRangeException>(() => new HipTrustReceiptScores(
                domainTrustScore: -1,
                finalHipScore: 50));
            Assert.Throws<ArgumentOutOfRangeException>(() => new HipTrustReceiptScores(
                domainTrustScore: 50,
                finalHipScore: 101));
            Assert.Throws<ArgumentOutOfRangeException>(() => new HipTrustReceiptScores(
                domainTrustScore: 50,
                finalHipScore: 50,
                pageTrustScore: 101));
            Assert.Throws<ArgumentOutOfRangeException>(() => new HipTrustReceiptScores(
                domainTrustScore: 50,
                finalHipScore: 50,
                contentRiskScore: -1));
        });
    }

    [Test]
    public void Receipt_requires_utc_ordered_millisecond_timestamps()
    {
        var issuedAt = new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);

        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentException>(() => ValidReceipt(
                evaluatedAtUtc: issuedAt.ToOffset(TimeSpan.FromHours(1))));
            Assert.Throws<ArgumentException>(() => ValidReceipt(evaluatedAtUtc: issuedAt.AddTicks(1)));
            Assert.Throws<ArgumentException>(() => ValidReceipt(evaluatedAtUtc: issuedAt.AddSeconds(1)));
            Assert.Throws<ArgumentException>(() => ValidReceipt(expiresAtUtc: issuedAt));
        });
    }

    [TestCase("{")]
    [TestCase("[]")]
    [TestCase("null")]
    public void Deserializer_rejects_malformed_or_wrong_root_json(string json)
    {
        Assert.Catch<JsonException>(() => HipTrustReceiptJson.Deserialize(json));
    }

    [Test]
    public void Deserializer_rejects_missing_unknown_duplicate_and_unsupported_fields()
    {
        var valid = HipTrustReceiptJson.Serialize(ValidReceipt());
        var missingDocumentType = valid.Replace(
            $"\"documentType\":\"{HipTrustReceipt.TrustReceiptDocumentType}\",",
            string.Empty,
            StringComparison.Ordinal);
        var missingReceiptId = valid.Replace("\"receiptId\":\"receipt-20260719-0001\",", string.Empty, StringComparison.Ordinal);
        var missingReasonCodes = valid.Replace(
            "\"reasonCodes\":[\"domain-verified\",\"tls-valid\"],",
            string.Empty,
            StringComparison.Ordinal);
        var missingCanonicalization = valid.Replace("\"canonicalization\":\"RFC8785\",", string.Empty, StringComparison.Ordinal);
        var unknownField = valid[..^1] + ",\"unexpected\":true}";
        var duplicateVersion = valid.Replace("\"version\":\"1.0\"", "\"version\":\"1.0\",\"version\":\"1.0\"", StringComparison.Ordinal);
        var unsupportedDocumentType = valid.Replace(HipTrustReceipt.TrustReceiptDocumentType, "other-document", StringComparison.Ordinal);
        var unsupportedVersion = valid.Replace("\"version\":\"1.0\"", "\"version\":\"2.0\"", StringComparison.Ordinal);
        var nonCanonicalTimestamp = valid.Replace("2026-07-19T12:00:00.000Z", "2026-07-19T12:00:00Z", StringComparison.Ordinal);
        var integerStatus = valid.Replace("\"status\":\"probablySafe\"", "\"status\":5", StringComparison.Ordinal);
        var unsupportedDocumentTypeException = Assert.Throws<JsonException>(() =>
            HipTrustReceiptJson.Deserialize(unsupportedDocumentType));

        Assert.Multiple(() =>
        {
            Assert.Throws<JsonException>(() => HipTrustReceiptJson.Deserialize(missingDocumentType));
            Assert.Throws<JsonException>(() => HipTrustReceiptJson.Deserialize(missingReceiptId));
            Assert.Throws<JsonException>(() => HipTrustReceiptJson.Deserialize(missingReasonCodes));
            Assert.Throws<JsonException>(() => HipTrustReceiptJson.Deserialize(missingCanonicalization));
            Assert.Throws<JsonException>(() => HipTrustReceiptJson.Deserialize(unknownField));
            Assert.Throws<JsonException>(() => HipTrustReceiptJson.Deserialize(duplicateVersion));
            Assert.That(
                Contains<HipTrustReceiptDocumentTypeException>(unsupportedDocumentTypeException!),
                Is.True);
            Assert.Throws<JsonException>(() => HipTrustReceiptJson.Deserialize(unsupportedVersion));
            Assert.Throws<JsonException>(() => HipTrustReceiptJson.Deserialize(nonCanonicalTimestamp));
            Assert.Throws<JsonException>(() => HipTrustReceiptJson.Deserialize(integerStatus));
        });
    }

    [Test]
    public void Deserializer_rejects_receipts_over_the_utf8_limit()
    {
        var oversized = "{\"value\":\"" + new string('x', HipTrustReceiptJson.MaximumReceiptBytes) + "\"}";

        var exception = Assert.Throws<JsonException>(() => HipTrustReceiptJson.Deserialize(oversized));

        Assert.That(exception!.Message, Does.Contain(HipTrustReceiptJson.MaximumReceiptBytes.ToString()));
    }

    [Test]
    public void Receipt_signature_does_not_establish_safety_or_reputation_by_itself()
    {
        var receipt = ValidReceipt();

        Assert.Multiple(() =>
        {
            Assert.That(receipt.Signature.Scope, Is.EqualTo(HipProtocolSignature.OriginAndIntegrityScope));
            Assert.That(receipt.EstablishesSafetyOrReputationBySignatureAlone, Is.False);
            Assert.That(receipt.Status, Is.EqualTo(RiskStatus.ProbablySafe));
            Assert.That(receipt.Confidence, Is.EqualTo(HipTrustConfidence.High));
        });
    }

    private static HipTrustReceipt ValidReceipt(
        IReadOnlyCollection<string>? reasonCodes = null,
        IReadOnlyCollection<string>? warningCodes = null,
        DateTimeOffset? evaluatedAtUtc = null,
        DateTimeOffset? issuedAtUtc = null,
        DateTimeOffset? expiresAtUtc = null)
    {
        var issuedAt = issuedAtUtc ?? new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);
        return new HipTrustReceipt(
            HipTrustReceipt.TrustReceiptDocumentType,
            HipProtocolVersion.Current,
            "receipt-20260719-0001",
            "scan-20260719-0001",
            new HipProtocolSubject(IdentitySubjectType.Website, "example.com"),
            evaluatedAtUtc ?? issuedAt.AddSeconds(-2),
            issuedAt,
            expiresAtUtc ?? issuedAt.AddMinutes(10),
            new HipTrustReceiptScores(
                domainTrustScore: 82,
                finalHipScore: 74,
                pageTrustScore: 61,
                contentRiskScore: 39),
            RiskStatus.ProbablySafe,
            HipTrustConfidence.High,
            reasonCodes ?? new[] { "tls-valid", "domain-verified" },
            warningCodes ?? new[] { "limited-content-evidence" },
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
    }

    private static string ReadFixture(string fileName) =>
        File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "tests",
            "HIP.Tests",
            "Protocol",
            "Fixtures",
            fileName)).TrimEnd();

    private static bool Contains<TException>(Exception exception)
        where TException : Exception
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is TException)
            {
                return true;
            }
        }

        return false;
    }

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
}
