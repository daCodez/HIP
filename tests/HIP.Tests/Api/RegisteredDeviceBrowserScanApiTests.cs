using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using HIP.Application.Browser;
using HIP.Application.Devices;
using HIP.Domain.Devices;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Api;

/// <summary>Exercises the registered-device proof contract at the browser scan API boundary.</summary>
[TestFixture]
public sealed class RegisteredDeviceBrowserScanApiTests
{
    private const string ScanPath = "/api/v1/browser/scan-results";
    private static readonly DateTimeOffset Now = new(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Proves an active device receives distinct provenance and that its nonce cannot be replayed.</summary>
    [Test]
    public async Task Active_device_proof_is_registered_device_provenance_and_replay_is_rejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var device = CreateDevice(key, DeviceRevocationState.Active);
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = ConfigureDevice(baseFactory, device);
        using var client = factory.CreateClient();
        var body = ValidRequest($"registered-{Guid.NewGuid():N}.com");
        var proof = CreateProofRequest(key, device.DeviceId, body, "BwcHBwcHBwcHBwcHBwcHBwcH");

        using var accepted = await client.SendAsync(proof);
        using var stored = await client.GetAsync($"{ScanPath}/{body.Domain}");
        using var replay = await client.SendAsync(
            CreateProofRequest(key, device.DeviceId, body, "BwcHBwcHBwcHBwcHBwcHBwcH"));
        var storedJson = await JsonDocument.ParseAsync(await stored.Content.ReadAsStreamAsync());
        var replayBody = await replay.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(accepted.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(stored.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(
                storedJson.RootElement.GetProperty("privacySafeMetadata").GetProperty("submissionTrust").GetString(),
                Is.EqualTo(BrowserScanResultProvenance.RegisteredDevice));
            Assert.That(replay.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
            Assert.That(replayBody, Does.Contain("already used"));
        });
    }

    /// <summary>Proves partial proof headers fail closed while a header-free submission stays available and untrusted.</summary>
    [Test]
    public async Task Partial_proof_is_rejected_while_anonymous_submission_remains_untrusted()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var device = CreateDevice(key, DeviceRevocationState.Active);
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = ConfigureDevice(baseFactory, device);
        using var client = factory.CreateClient();
        var rejectedBody = ValidRequest($"partial-{Guid.NewGuid():N}.com");
        using var partialRequest = new HttpRequestMessage(HttpMethod.Post, ScanPath)
        {
            Content = JsonContent.Create(rejectedBody)
        };
        partialRequest.Headers.TryAddWithoutValidation("X-HIP-Device-Id", device.DeviceId);

        using var rejected = await client.SendAsync(partialRequest);
        var anonymousBody = ValidRequest($"anonymous-{Guid.NewGuid():N}.com");
        using var anonymous = await client.PostAsJsonAsync(ScanPath, anonymousBody);
        using var stored = await client.GetAsync($"{ScanPath}/{anonymousBody.Domain}");
        var storedJson = await JsonDocument.ParseAsync(await stored.Content.ReadAsStreamAsync());

        Assert.Multiple(() =>
        {
            Assert.That(rejected.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(anonymous.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(
                storedJson.RootElement.GetProperty("privacySafeMetadata").GetProperty("submissionTrust").GetString(),
                Is.EqualTo(BrowserScanResultProvenance.UntrustedClient));
        });
    }

    /// <summary>Proves a cryptographically valid proof cannot restore trust after device revocation.</summary>
    [Test]
    public async Task Revoked_device_proof_fails_closed_at_the_api_boundary()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var device = CreateDevice(key, DeviceRevocationState.Revoked);
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = ConfigureDevice(baseFactory, device);
        using var client = factory.CreateClient();
        var body = ValidRequest($"revoked-{Guid.NewGuid():N}.com");

        using var response = await client.SendAsync(
            CreateProofRequest(key, device.DeviceId, body, "CAgICAgICAgICAgICAgICAgI"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    private static WebApplicationFactory<Program> ConfigureDevice(
        HipWebApplicationFactory<Program> baseFactory,
        RegisteredDevice device) =>
        baseFactory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IDeviceRegistrationRepository>();
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<IDeviceRegistrationRepository>(new StubDeviceRepository(device));
            services.AddSingleton<TimeProvider>(new FixedTimeProvider(Now));
        }));

    private static RegisteredDevice CreateDevice(ECDsa key, DeviceRevocationState revocationState)
    {
        var verifier = new Es256DeviceProofVerifier();
        var publicKey = verifier.ValidatePublicKey(
            Es256DeviceProofVerifier.Algorithm,
            Base64UrlEncode(key.ExportSubjectPublicKeyInfo()));
        return new RegisteredDevice(
            "dev_browser_api_test",
            "HIP browser extension",
            DevicePlatformType.BrowserExtension,
            "0.1.14",
            publicKey.Algorithm,
            publicKey.PublicKey,
            publicKey.PublicKeyFingerprint,
            DeviceTrustState.ProofOfPossessionVerified,
            revocationState,
            Now.AddDays(-1),
            Now.AddMinutes(-1),
            revocationState == DeviceRevocationState.Revoked ? Now.AddSeconds(-1) : null);
    }

    private static HttpRequestMessage CreateProofRequest(
        ECDsa key,
        string deviceId,
        BrowserScanResultSaveRequest body,
        string nonce)
    {
        var timestamp = Now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var digest = DeviceRequestProofCanonicalizer.BodyDigest(body);
        var signingInput = DeviceRequestProofCanonicalizer.SigningInput(
            deviceId,
            HttpMethod.Post.Method,
            ScanPath,
            digest,
            timestamp,
            nonce);
        var signature = Base64UrlEncode(key.SignData(
            signingInput,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        var request = new HttpRequestMessage(HttpMethod.Post, ScanPath)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.TryAddWithoutValidation("X-HIP-Device-Id", deviceId);
        request.Headers.TryAddWithoutValidation("X-HIP-Device-Timestamp", timestamp);
        request.Headers.TryAddWithoutValidation("X-HIP-Device-Nonce", nonce);
        request.Headers.TryAddWithoutValidation("X-HIP-Device-Body-SHA256", digest);
        request.Headers.TryAddWithoutValidation("X-HIP-Device-Signature", signature);
        return request;
    }

    private static BrowserScanResultSaveRequest ValidRequest(string domain) =>
        new(
            domain,
            null,
            84,
            "Trusted",
            "Trusted",
            ["No risky links found"],
            42,
            2,
            2,
            0,
            "Allow",
            new Dictionary<string, string> { ["scanMode"] = "Normal" },
            PageUrlHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            PluginVersion: "HIP Plugin v0.1.14");

    private static string Base64UrlEncode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class StubDeviceRepository(RegisteredDevice device) : IDeviceRegistrationRepository
    {
        public Task<RegisteredDevice?> GetDeviceAsync(string deviceId, CancellationToken cancellationToken) =>
            Task.FromResult<RegisteredDevice?>(
                string.Equals(deviceId, device.DeviceId, StringComparison.Ordinal) ? device : null);

        public Task<DeviceRegistrationAggregate?> GetAsync(string ownerScopeId, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<DeviceRegistrationSaveOutcome> TrySaveAsync(
            DeviceRegistrationTransitionBatch transition,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
