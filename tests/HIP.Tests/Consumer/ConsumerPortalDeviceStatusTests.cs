using HIP.Application.Consumer;
using HIP.Application.Devices;
using HIP.Domain.Devices;

namespace HIP.Tests.Consumer;

[TestFixture]
public sealed class ConsumerPortalDeviceStatusTests
{
    [Test]
    public async Task Status_reports_only_the_current_consumers_real_device_state()
    {
        var service = new ConsumerPortalService(
            riskFindingRepository: null!,
            appealService: null!,
            privacyHashingService: null!,
            deviceRegistrationService: new StubDeviceRegistrationService(),
            appealRepository: null!);

        var owner = await service.GetStatusAsync("consumer-A", CancellationToken.None);
        var other = await service.GetStatusAsync("consumer-B", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(owner.DeviceStatus, Is.EqualTo("1 active device · 1 revoked"));
            Assert.That(owner.Message, Does.Contain("owned by this consumer account"));
            Assert.That(other.DeviceStatus, Is.EqualTo("No registered devices"));
            Assert.That(owner.DeviceStatus, Does.Not.Contain("development device"));
        });
    }

    [Test]
    public async Task Status_reports_an_explicit_safe_unavailable_state_when_device_storage_fails()
    {
        const string sensitiveMarker = "sensitive-device-storage-detail-must-not-escape";
        var service = new ConsumerPortalService(
            riskFindingRepository: null!,
            appealService: null!,
            privacyHashingService: null!,
            deviceRegistrationService: new ThrowingDeviceRegistrationService(
                new InvalidOperationException(sensitiveMarker)),
            appealRepository: null!);

        var status = await service.GetStatusAsync("consumer-A", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(status.ProtectionStatus, Is.EqualTo("Unavailable"));
            Assert.That(status.DeviceStatus, Is.EqualTo("Device status unavailable"));
            Assert.That(status.Message, Does.Contain("temporarily unavailable"));
            Assert.That(status.Message, Does.Not.Contain(sensitiveMarker));
        });
    }

    private sealed class StubDeviceRegistrationService : IDeviceRegistrationService
    {
        private static readonly DateTimeOffset RegisteredAtUtc =
            new(2026, 7, 20, 12, 0, 0, TimeSpan.Zero);

        public Task<IReadOnlyCollection<DeviceRegistrationDeviceResponse>> ListAsync(
            string ownerId,
            CancellationToken cancellationToken)
        {
            IReadOnlyCollection<DeviceRegistrationDeviceResponse> devices =
                string.Equals(ownerId, "consumer-A", StringComparison.Ordinal)
                    ?
                    [
                        Device("active", DeviceRevocationState.Active, null),
                        Device("revoked", DeviceRevocationState.Revoked, RegisteredAtUtc.AddHours(1))
                    ]
                    : [];
            return Task.FromResult(devices);
        }

        public Task<DeviceRegistrationChallengeResult> IssueChallengeAsync(
            string ownerId,
            StartDeviceRegistrationRequest request,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DeviceRegistrationCompletionResult> CompleteAsync(
            string ownerId,
            string challengeId,
            CompleteDeviceRegistrationRequest request,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DeviceRegistrationRevocationResult> RevokeAsync(
            string ownerId,
            string deviceId,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        private static DeviceRegistrationDeviceResponse Device(
            string id,
            DeviceRevocationState state,
            DateTimeOffset? revokedAtUtc) =>
            new(
                $"dev_{id}",
                id,
                DevicePlatformType.BrowserExtension,
                "1.0",
                Es256DeviceProofVerifier.Algorithm,
                $"sha256:{id}",
                DeviceTrustState.ProofOfPossessionVerified,
                state,
                RegisteredAtUtc,
                RegisteredAtUtc,
                revokedAtUtc);
    }

    private sealed class ThrowingDeviceRegistrationService(Exception exception) : IDeviceRegistrationService
    {
        public Task<IReadOnlyCollection<DeviceRegistrationDeviceResponse>> ListAsync(
            string ownerId,
            CancellationToken cancellationToken) =>
            Task.FromException<IReadOnlyCollection<DeviceRegistrationDeviceResponse>>(exception);

        public Task<DeviceRegistrationChallengeResult> IssueChallengeAsync(
            string ownerId,
            StartDeviceRegistrationRequest request,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DeviceRegistrationCompletionResult> CompleteAsync(
            string ownerId,
            string challengeId,
            CompleteDeviceRegistrationRequest request,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DeviceRegistrationRevocationResult> RevokeAsync(
            string ownerId,
            string deviceId,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
