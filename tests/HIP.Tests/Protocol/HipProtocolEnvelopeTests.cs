using System.Text;
using System.Text.Json;
using HIP.Application.Protocol;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;

namespace HIP.Tests.Protocol;

public sealed class HipProtocolEnvelopeTests
{
    [Test]
    public void Version_one_envelope_matches_stable_wire_fixture()
    {
        var envelope = ValidEnvelope();
        var expected = File.ReadAllText(Path.Combine(
            RepositoryRoot(), "tests", "HIP.Tests", "Protocol", "Fixtures", "hip-envelope-v1.json")).TrimEnd();

        var json = HipProtocolEnvelopeJson.Serialize(envelope);
        var roundTrip = HipProtocolEnvelopeJson.Deserialize(json);

        Assert.Multiple(() =>
        {
            Assert.That(json, Is.EqualTo(expected));
            Assert.That(roundTrip.Version, Is.EqualTo(HipProtocolVersion.Current));
            Assert.That(roundTrip.MessageId, Is.EqualTo("msg-20260717-0001"));
            Assert.That(roundTrip.Nonce, Is.EqualTo("AAECAwQFBgcICQoLDA0ODw"));
            Assert.That(roundTrip.Issuer.Id, Is.EqualTo("hip:domain:issuer.example"));
            Assert.That(roundTrip.Subject.Type, Is.EqualTo(IdentitySubjectType.Website));
            Assert.That(roundTrip.ContentDigest.ToPrefixedString(), Is.EqualTo($"sha256:{new string('a', 64)}"));
            Assert.That(roundTrip.Claims.Values.Keys, Is.EqualTo(new[] { "riskStatus", "source" }));
            Assert.That(roundTrip.Signature.Scope, Is.EqualTo(HipProtocolSignature.OriginAndIntegrityScope));
            Assert.That(roundTrip.Signature.Canonicalization, Is.EqualTo(HipProtocolSignature.Rfc8785Canonicalization));
        });
    }

    [Test]
    public void Envelope_signing_payload_removes_only_the_signature_value_and_matches_stable_fixture()
    {
        var envelope = ValidEnvelope();
        var signingPayload = HipProtocolEnvelopeSigningPayload.Create(envelope);
        var canonical = new Rfc8785CanonicalJsonService().Canonicalize(signingPayload);
        var expected = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "tests",
            "HIP.Tests",
            "Protocol",
            "Fixtures",
            "hip-envelope-v1.signing.canonical.json")).TrimEnd();
        using var document = JsonDocument.Parse(signingPayload);
        var signature = document.RootElement.GetProperty("signature");

        Assert.Multiple(() =>
        {
            Assert.That(Encoding.UTF8.GetString(canonical), Is.EqualTo(expected));
            Assert.That(signature.TryGetProperty("value", out _), Is.False);
            Assert.That(signature.GetProperty("scope").GetString(), Is.EqualTo(HipProtocolSignature.OriginAndIntegrityScope));
            Assert.That(signature.GetProperty("keyId").GetString(), Is.EqualTo(envelope.Signature.KeyId));
            Assert.That(signature.GetProperty("algorithm").GetString(), Is.EqualTo(envelope.Signature.Algorithm));
            Assert.That(signature.GetProperty("algorithmFamily").GetString(), Is.EqualTo("unknown"));
            Assert.That(signature.GetProperty("canonicalization").GetString(), Is.EqualTo("RFC8785"));
        });
    }

    [Test]
    public void Claims_are_copied_and_sorted_before_becoming_signed_state()
    {
        var mutableClaims = new Dictionary<string, JsonElement>
        {
            ["source"] = JsonValue("\"browser-extension\""),
            ["riskStatus"] = JsonValue("\"dangerous\"")
        };
        var claims = new HipProtocolClaims(mutableClaims);

        mutableClaims.Clear();

        Assert.That(claims.Values.Keys, Is.EqualTo(new[] { "riskStatus", "source" }));
        Assert.That(claims.Values["riskStatus"].GetString(), Is.EqualTo("dangerous"));
    }

    [TestCase("")]
    [TestCase("1")]
    [TestCase("v1.0")]
    [TestCase("1.0.0")]
    [TestCase("2.0")]
    public void Unsupported_or_malformed_protocol_versions_are_rejected(string value)
    {
        Assert.Throws<NotSupportedException>(() => HipProtocolVersion.Parse(value));
    }

    [Test]
    public void Content_digest_preserves_existing_sha256_convention()
    {
        var prefixed = $"sha256:{new string('b', 64)}";

        var digest = HipContentDigest.FromPrefixedString(prefixed);

        Assert.Multiple(() =>
        {
            Assert.That(digest.Algorithm, Is.EqualTo(HipContentDigest.Sha256Algorithm));
            Assert.That(digest.Value, Is.EqualTo(new string('b', 64)));
            Assert.That(digest.ToPrefixedString(), Is.EqualTo(prefixed));
        });
    }

    [TestCase("sha512", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [TestCase("sha256", "abc")]
    [TestCase("sha256", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void Unsupported_or_malformed_content_digests_are_rejected(string algorithm, string value)
    {
        Assert.Throws<ArgumentException>(() => new HipContentDigest(algorithm, value));
    }

    [Test]
    public void Envelope_requires_utc_ordered_millisecond_timestamps()
    {
        var valid = ValidEnvelope();
        var nonUtc = valid.IssuedAtUtc.ToOffset(TimeSpan.FromHours(1));
        var subMillisecond = valid.IssuedAtUtc.AddTicks(1);

        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentException>(() => Copy(valid, issuedAtUtc: nonUtc));
            Assert.Throws<ArgumentException>(() => Copy(valid, issuedAtUtc: subMillisecond));
            Assert.Throws<ArgumentException>(() => Copy(valid, expiresAtUtc: valid.IssuedAtUtc));
            Assert.Throws<ArgumentException>(() => Copy(valid, expiresAtUtc: valid.IssuedAtUtc.AddSeconds(-1)));
        });
    }

    [TestCase("")]
    [TestCase("contains space")]
    [TestCase("contains/slash")]
    public void Envelope_rejects_invalid_message_identifiers(string messageId)
    {
        var valid = ValidEnvelope();

        Assert.Throws<ArgumentException>(() => Copy(valid, messageId: messageId));
    }

    [Test]
    public void Envelope_rejects_oversized_message_identifiers()
    {
        var valid = ValidEnvelope();

        Assert.Throws<ArgumentException>(() => Copy(
            valid,
            messageId: new string('m', HipProtocolEnvelope.MaximumMessageIdLength + 1)));
    }

    [TestCase("AQID")]
    [TestCase("AAECAwQFBgcICQoLDA0ODw==")]
    [TestCase("AAECAwQFBgcICQoLDA0OD+")]
    [TestCase("A")]
    public void Envelope_rejects_noncanonical_or_too_short_nonces(string nonce)
    {
        var valid = ValidEnvelope();

        Assert.Throws<ArgumentException>(() => Copy(valid, nonce: nonce));
    }

    [Test]
    public void Envelope_accepts_the_maximum_canonical_nonce_size()
    {
        var valid = ValidEnvelope();
        var nonce = Convert.ToBase64String(new byte[HipProtocolEnvelope.MaximumNonceBytes])
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        var envelope = Copy(valid, nonce: nonce);

        Assert.That(envelope.Nonce, Is.EqualTo(nonce));
    }

    [Test]
    public void Protocol_components_enforce_size_limits()
    {
        var tooManyClaims = Enumerable.Range(0, HipProtocolClaims.MaximumCount + 1)
            .ToDictionary(index => $"claim-{index:D2}", _ => JsonValue("true"), StringComparer.Ordinal);

        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentException>(() => new HipProtocolIssuer(new string('i', HipProtocolIssuer.MaximumIdLength + 1)));
            Assert.Throws<ArgumentException>(() => new HipProtocolIssuer("hip:domain:bad issuer"));
            Assert.Throws<ArgumentException>(() => new HipProtocolSubject(IdentitySubjectType.Website, new string('s', HipProtocolSubject.MaximumIdLength + 1)));
            Assert.Throws<NotSupportedException>(() => HipProtocolVersion.Parse(new string('1', HipProtocolVersion.MaximumLength + 1)));
            Assert.Throws<ArgumentException>(() => new HipProtocolClaims(tooManyClaims));
            Assert.Throws<ArgumentException>(() => new HipProtocolClaim("oversized", JsonValue($"\"{new string('x', HipProtocolClaim.MaximumValueBytes + 1)}\"")));
            Assert.Throws<ArgumentException>(() => new HipProtocolClaim("duplicate", JsonValue("{\"item\":1,\"item\":2}")));
            Assert.Throws<ArgumentException>(() => new HipProtocolClaim("deep", DeepJson(HipProtocolClaim.MaximumValueDepth + 1)));
            Assert.Throws<ArgumentException>(() => new HipProtocolSignature(
                HipProtocolSignature.OriginAndIntegrityScope,
                "key-1",
                "algorithm",
                SignatureAlgorithmFamily.Unknown,
                HipProtocolSignature.Rfc8785Canonicalization,
                new string('s', HipProtocolSignature.MaximumValueLength + 1)));
        });
    }

    [TestCase("{")]
    [TestCase("[]")]
    [TestCase("null")]
    public void Deserializer_rejects_malformed_or_wrong_root_json(string json)
    {
        Assert.Catch<JsonException>(() => HipProtocolEnvelopeJson.Deserialize(json));
    }

    [Test]
    public void Deserializer_rejects_missing_unknown_duplicate_and_unsupported_fields()
    {
        var valid = HipProtocolEnvelopeJson.Serialize(ValidEnvelope());
        var missingIssuer = valid.Replace("\"issuer\":{\"id\":\"hip:domain:issuer.example\"},", string.Empty, StringComparison.Ordinal);
        var missingMessageId = valid.Replace("\"messageId\":\"msg-20260717-0001\",", string.Empty, StringComparison.Ordinal);
        var missingNonce = valid.Replace("\"nonce\":\"AAECAwQFBgcICQoLDA0ODw\",", string.Empty, StringComparison.Ordinal);
        var missingCanonicalization = valid.Replace("\"canonicalization\":\"RFC8785\",", string.Empty, StringComparison.Ordinal);
        var unknownField = valid[..^1] + ",\"unexpected\":true}";
        var duplicateVersion = valid.Replace("\"version\":\"1.0\"", "\"version\":\"1.0\",\"version\":\"1.0\"", StringComparison.Ordinal);
        var unsupportedVersion = valid.Replace("\"version\":\"1.0\"", "\"version\":\"2.0\"", StringComparison.Ordinal);

        Assert.Multiple(() =>
        {
            Assert.Throws<JsonException>(() => HipProtocolEnvelopeJson.Deserialize(missingIssuer));
            Assert.Throws<JsonException>(() => HipProtocolEnvelopeJson.Deserialize(missingMessageId));
            Assert.Throws<JsonException>(() => HipProtocolEnvelopeJson.Deserialize(missingNonce));
            Assert.Throws<JsonException>(() => HipProtocolEnvelopeJson.Deserialize(missingCanonicalization));
            Assert.Throws<JsonException>(() => HipProtocolEnvelopeJson.Deserialize(unknownField));
            Assert.Throws<JsonException>(() => HipProtocolEnvelopeJson.Deserialize(duplicateVersion));
            Assert.Throws<JsonException>(() => HipProtocolEnvelopeJson.Deserialize(unsupportedVersion));
        });
    }

    [Test]
    public void Deserializer_rejects_envelopes_over_the_utf8_limit()
    {
        var oversized = "{\"value\":\"" + new string('x', HipProtocolEnvelopeJson.MaximumEnvelopeBytes) + "\"}";

        var exception = Assert.Throws<JsonException>(() => HipProtocolEnvelopeJson.Deserialize(oversized));

        Assert.That(exception!.Message, Does.Contain(HipProtocolEnvelopeJson.MaximumEnvelopeBytes.ToString()));
    }

    [Test]
    public void Origin_and_integrity_signature_does_not_imply_safety_or_reputation()
    {
        var envelope = ValidEnvelope();

        Assert.Multiple(() =>
        {
            Assert.That(envelope.Signature.Scope, Is.EqualTo("origin-and-integrity"));
            Assert.That(envelope.Signature.AlgorithmFamily, Is.EqualTo(SignatureAlgorithmFamily.Unknown));
            Assert.That(envelope.Claims.Values["riskStatus"].GetString(), Is.EqualTo("dangerous"));
            Assert.That(typeof(HipProtocolSignature).GetProperties().Select(property => property.Name),
                Has.None.Contains("IsSafe").And.None.Contains("Reputation"));
        });
    }

    private static HipProtocolEnvelope ValidEnvelope()
    {
        var issuedAt = new DateTimeOffset(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);
        return new HipProtocolEnvelope(
            HipProtocolVersion.Current,
            "msg-20260717-0001",
            "AAECAwQFBgcICQoLDA0ODw",
            new HipProtocolIssuer("hip:domain:issuer.example"),
            new HipProtocolSubject(IdentitySubjectType.Website, "example.com"),
            HipContentDigest.FromPrefixedString($"sha256:{new string('a', 64)}"),
            new HipProtocolClaims(new Dictionary<string, JsonElement>
            {
                ["source"] = JsonValue("\"browser-extension\""),
                ["riskStatus"] = JsonValue("\"dangerous\"")
            }),
            new HipProtocolSignature(
                HipProtocolSignature.OriginAndIntegrityScope,
                "dev-key-1",
                "PQ-Placeholder-Development-Only",
                SignatureAlgorithmFamily.Unknown,
                HipProtocolSignature.Rfc8785Canonicalization,
                $"devsig:{new string('c', 64)}"),
            issuedAt,
            issuedAt.AddMinutes(5));
    }

    private static HipProtocolEnvelope Copy(
        HipProtocolEnvelope source,
        string? messageId = null,
        string? nonce = null,
        DateTimeOffset? issuedAtUtc = null,
        DateTimeOffset? expiresAtUtc = null) =>
        new(
            source.Version,
            messageId ?? source.MessageId,
            nonce ?? source.Nonce,
            source.Issuer,
            source.Subject,
            source.ContentDigest,
            source.Claims,
            source.Signature,
            issuedAtUtc ?? source.IssuedAtUtc,
            expiresAtUtc ?? source.ExpiresAtUtc);

    private static JsonElement JsonValue(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static JsonElement DeepJson(int depth)
    {
        var json = "true";
        for (var index = 0; index < depth; index++)
        {
            json = $"{{\"value\":{json}}}";
        }

        return JsonValue(json);
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
