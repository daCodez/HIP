using System.Security.Cryptography;
using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;

namespace HIP.Tests.Identity;

/// <summary>Locks signed well-known domain control to the active challenge and registered key.</summary>
public sealed class WellKnownHipDocumentVerifierTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Matching_signed_document_proves_domain_control_and_key_possession()
    {
        var fixture = CreateFixture();
        fixture.Fetcher.Document = Sign(fixture.Document, fixture.KeyPair.PrivateKey, fixture.Crypto, fixture.Canonicalizer);

        var result = await fixture.Verifier.VerifyAsync(fixture.Request, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(WellKnownHipDocumentVerificationStatus.Verified));
            Assert.That(result.Message, Does.Contain("safety is evaluated separately"));
        });
    }

    [Test]
    public async Task Valid_signature_for_wrong_challenge_is_rejected()
    {
        var fixture = CreateFixture();
        var wrong = fixture.Document with { VerificationChallenge = "another-challenge" };
        fixture.Fetcher.Document = Sign(wrong, fixture.KeyPair.PrivateKey, fixture.Crypto, fixture.Canonicalizer);

        var result = await fixture.Verifier.VerifyAsync(fixture.Request, CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(WellKnownHipDocumentVerificationStatus.Invalid));
    }

    [Test]
    public async Task Tampered_document_after_signing_is_rejected()
    {
        var fixture = CreateFixture();
        var signed = Sign(fixture.Document, fixture.KeyPair.PrivateKey, fixture.Crypto, fixture.Canonicalizer);
        fixture.Fetcher.Document = signed with { HipIdentityId = "hip:web:attacker.example" };

        var result = await fixture.Verifier.VerifyAsync(fixture.Request, CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(WellKnownHipDocumentVerificationStatus.Invalid));
    }

    private static Fixture CreateFixture()
    {
        const string domain = "signed-well-known.example";
        const string challenge = "active-challenge";
        var crypto = new DevelopmentHipCryptoProvider();
        var keyPair = crypto.GenerateKeyPair();
        var key = new SigningKey("default", keyPair.Algorithm, keyPair.PublicKey);
        var request = new DomainVerificationRequest(
            domain,
            VerificationMethod.WellKnownHipJson,
            challenge,
            VerificationStatus.Pending,
            Now.AddMinutes(-1),
            null,
            Now.AddHours(1));
        var identity = new WebsiteIdentity(
            domain,
            $"hip:web:{domain}",
            [key],
            VerificationStatus.Pending,
            VerificationMethod.WellKnownHipJson,
            Now.AddMinutes(-2),
            null);
        var document = new HipWellKnownDocument(
            domain,
            identity.HipIdentityId,
            [key],
            Now,
            "1",
            challenge,
            Now.AddMinutes(30));
        var fetcher = new StubFetcher();
        var canonicalizer = new Rfc8785CanonicalJsonService();
        var verifier = new WellKnownHipDocumentVerifier(
            fetcher,
            new StubWebsiteIdentityRepository(identity),
            canonicalizer,
            new HipSignatureProviderFactory([crypto]),
            SignatureProviderRuntimePolicy.ForDevelopment(DevelopmentHipCryptoProvider.Algorithm),
            new FixedTimeProvider(Now));
        return new Fixture(verifier, fetcher, request, document, keyPair, crypto, canonicalizer);
    }

    private static HipWellKnownDocument Sign(
        HipWellKnownDocument document,
        string privateKey,
        DevelopmentHipCryptoProvider crypto,
        ICanonicalJsonService canonicalizer)
    {
        var canonical = WellKnownHipDocumentVerifier.CreateCanonicalSigningPayload(document, canonicalizer);
        var hash = $"sha256:{Convert.ToHexString(SHA256.HashData(canonical)).ToLowerInvariant()}";
        return document with
        {
            Signature = new HipProtocolSignature(
                HipProtocolSignature.OriginAndIntegrityScope,
                "default",
                DevelopmentHipCryptoProvider.Algorithm,
                SignatureAlgorithmFamily.Unknown,
                HipProtocolSignature.Rfc8785Canonicalization,
                crypto.SignHash(hash, privateKey))
        };
    }

    private sealed record Fixture(
        WellKnownHipDocumentVerifier Verifier,
        StubFetcher Fetcher,
        DomainVerificationRequest Request,
        HipWellKnownDocument Document,
        HipKeyPair KeyPair,
        DevelopmentHipCryptoProvider Crypto,
        ICanonicalJsonService Canonicalizer);

    private sealed class StubFetcher : IWellKnownHipDocumentFetcher
    {
        public HipWellKnownDocument? Document { get; set; }
        public Task<HipWellKnownDocument?> FetchAsync(string normalizedDomain, CancellationToken cancellationToken) =>
            Task.FromResult(Document);
    }

    private sealed class StubWebsiteIdentityRepository(WebsiteIdentity identity) : IWebsiteIdentityRepository
    {
        public Task<WebsiteIdentity?> GetAsync(string domain, CancellationToken cancellationToken) =>
            Task.FromResult<WebsiteIdentity?>(string.Equals(domain, identity.Domain, StringComparison.Ordinal) ? identity : null);
        public Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyCollection<WebsiteIdentity>>([identity]);
        public Task<bool> TryCreateAsync(WebsiteIdentity websiteIdentity, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<bool> TryUpdateAsync(WebsiteIdentity expected, WebsiteIdentity updated, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<WebsiteIdentity> SaveAsync(WebsiteIdentity websiteIdentity, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
