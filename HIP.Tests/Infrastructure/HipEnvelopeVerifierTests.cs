using System.Security.Cryptography;
using System.Text;
using HIP.ApiService;
using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Contracts;
using HIP.ApiService.Infrastructure.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NUnit.Framework;

namespace HIP.Tests.Infrastructure;

public sealed class HipEnvelopeVerifierTests
{
    private sealed class RecordingReplayProtectionService(bool nextResult) : IReplayProtectionService
    {
        public int Calls { get; private set; }

        public Task<bool> TryConsumeAsync(string messageId, string identityId, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(nextResult);
        }
    }

    private sealed class FakeIdentityService(params string[] knownIds) : IIdentityService
    {
        private readonly HashSet<string> _known = new(knownIds, StringComparer.Ordinal);

        public Task<IdentityDto?> GetByIdAsync(string id, CancellationToken cancellationToken)
            => Task.FromResult<IdentityDto?>(_known.Contains(id) ? new IdentityDto(id, $"pkref:{id}-main") : null);
    }

    [Test]
    public async Task VerifyIfRequiredAsync_InvalidSignature_DoesNotConsumeReplayNonce()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyId = "hip-system";
        var tempDir = Directory.CreateTempSubdirectory("hip-env-test-");
        try
        {
            var pubPath = Path.Combine(tempDir.FullName, $"{keyId}.pub");
            await File.WriteAllTextAsync(pubPath, ecdsa.ExportSubjectPublicKeyInfoPem());

            var replay = new RecordingReplayProtectionService(nextResult: true);
            var verifier = new HipEnvelopeVerifier(
                Options.Create(new CryptoProviderOptions { Provider = "ECDsa", PublicKeyStorePath = tempDir.FullName }),
                replay,
                new FakeIdentityService("hip-system"));

            var context = BuildContext(identityId: "hip-system", keyId: keyId, msgId: "msg-1", nonce: "n-1", signWith: null);

            var result = await verifier.VerifyIfRequiredAsync(context, CancellationToken.None);

            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Code, Is.EqualTo("policy.invalidSignature"));
            Assert.That(replay.Calls, Is.EqualTo(0));
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    [Test]
    public async Task VerifyIfRequiredAsync_ValidSignature_ReplayConsumedAfterVerification()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyId = "hip-system";
        var tempDir = Directory.CreateTempSubdirectory("hip-env-test-");
        try
        {
            var pubPath = Path.Combine(tempDir.FullName, $"{keyId}.pub");
            await File.WriteAllTextAsync(pubPath, ecdsa.ExportSubjectPublicKeyInfoPem());

            var replay = new RecordingReplayProtectionService(nextResult: false);
            var verifier = new HipEnvelopeVerifier(
                Options.Create(new CryptoProviderOptions { Provider = "ECDsa", PublicKeyStorePath = tempDir.FullName }),
                replay,
                new FakeIdentityService("hip-system"));

            var context = BuildContext(identityId: "hip-system", keyId: keyId, msgId: "msg-2", nonce: "n-2", signWith: ecdsa);

            var result = await verifier.VerifyIfRequiredAsync(context, CancellationToken.None);

            Assert.That(result.IsValid, Is.False);
            Assert.That(result.StatusCode, Is.EqualTo(StatusCodes.Status409Conflict));
            Assert.That(result.Code, Is.EqualTo("policy.replayDetected"));
            Assert.That(replay.Calls, Is.EqualTo(1));
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    [Test]
    public async Task VerifyIfRequiredAsync_IdentityKeyMismatch_IsRejectedBeforeSignatureVerification()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyId = "hip-system";
        var tempDir = Directory.CreateTempSubdirectory("hip-env-test-");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(tempDir.FullName, $"{keyId}.pub"), ecdsa.ExportSubjectPublicKeyInfoPem());

            var replay = new RecordingReplayProtectionService(nextResult: true);
            var verifier = new HipEnvelopeVerifier(
                Options.Create(new CryptoProviderOptions { Provider = "ECDsa", PublicKeyStorePath = tempDir.FullName }),
                replay,
                new FakeIdentityService("hip-system", "alpha-node"));

            var context = BuildContext(identityId: "alpha-node", keyId: "hip-system", msgId: "msg-3", nonce: "n-3", signWith: ecdsa);
            var result = await verifier.VerifyIfRequiredAsync(context, CancellationToken.None);

            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Code, Is.EqualTo("policy.identityKeyMismatch"));
            Assert.That(replay.Calls, Is.EqualTo(0));
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    [Test]
    public async Task VerifyIfRequiredAsync_InvalidHeaderFormat_IsRejected()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyId = "hip-system";
        var tempDir = Directory.CreateTempSubdirectory("hip-env-test-");
        try
        {
            await File.WriteAllTextAsync(Path.Combine(tempDir.FullName, $"{keyId}.pub"), ecdsa.ExportSubjectPublicKeyInfoPem());

            var replay = new RecordingReplayProtectionService(nextResult: true);
            var verifier = new HipEnvelopeVerifier(
                Options.Create(new CryptoProviderOptions { Provider = "ECDsa", PublicKeyStorePath = tempDir.FullName }),
                replay,
                new FakeIdentityService("hip-system"));

            var context = BuildContext(identityId: "hip-system", keyId: "hip-system", msgId: "../bad", nonce: "n-4", signWith: ecdsa);
            var result = await verifier.VerifyIfRequiredAsync(context, CancellationToken.None);

            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Code, Is.EqualTo("policy.invalidEnvelope"));
            Assert.That(replay.Calls, Is.EqualTo(0));
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    private static DefaultHttpContext BuildContext(string identityId, string keyId, string msgId, string nonce, ECDsa? signWith)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = "/api/identity/hip-system";
        context.Request.QueryString = QueryString.Empty;
        context.Request.Headers["x-hip-origin"] = "bff";
        context.Request.Headers["x-hip-identity"] = identityId;
        context.Request.Headers["x-hip-key-id"] = keyId;
        context.Request.Headers["x-hip-msg-id"] = msgId;
        context.Request.Headers["x-hip-nonce"] = nonce;

        var issued = DateTimeOffset.UtcNow.AddSeconds(-10).ToUnixTimeSeconds();
        var expires = DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeSeconds();
        context.Request.Headers["x-hip-issued-at"] = issued.ToString();
        context.Request.Headers["x-hip-expires-at"] = expires.ToString();

        var bodyHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Empty))).ToLowerInvariant();
        var payload = $"{msgId}|{identityId}|{keyId}|{issued}|{expires}|{nonce}|GET|/api/identity/hip-system|{bodyHash}";

        var signer = signWith ?? ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signature = signer.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256);
        context.Request.Headers["x-hip-signature"] = Convert.ToBase64String(signature);

        if (signWith is null)
        {
            signer.Dispose();
        }

        return context;
    }
}
