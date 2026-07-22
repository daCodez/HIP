using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HIP.Application.Security;
using HIP.Domain.Devices;

namespace HIP.Application.Devices;

public sealed record DeviceRequestProof(
    string DeviceId,
    string Timestamp,
    string Nonce,
    string BodyDigest,
    string Signature);

public enum DeviceRequestProofStatus
{
    Accepted = 0,
    Missing = 1,
    Invalid = 2,
    Expired = 3,
    Revoked = 4,
    Replayed = 5,
    StateUnavailable = 6
}

public sealed record DeviceRequestProofResult(DeviceRequestProofStatus Status)
{
    public bool IsAccepted => Status == DeviceRequestProofStatus.Accepted;
}

public interface IDeviceRequestProofService
{
    Task<DeviceRequestProofResult> ValidateAndReserveAsync<TBody>(
        DeviceRequestProof proof,
        string method,
        string path,
        TBody body,
        CancellationToken cancellationToken);
}

public sealed class DeviceRequestProofService(
    IDeviceRegistrationRepository repository,
    Es256DeviceProofVerifier proofVerifier,
    IReplayNonceStore nonceStore,
    TimeProvider? timeProvider = null) : IDeviceRequestProofService
{
    public static readonly TimeSpan TimestampTolerance = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan ReplayReservationLifetime = TimeSpan.FromMinutes(10);
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task<DeviceRequestProofResult> ValidateAndReserveAsync<TBody>(
        DeviceRequestProof proof,
        string method,
        string path,
        TBody body,
        CancellationToken cancellationToken)
    {
        if (!DeviceRequestProofCanonicalizer.IsValidProofShape(proof) ||
            !long.TryParse(proof.Timestamp, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var timestampSeconds))
        {
            return new(DeviceRequestProofStatus.Invalid);
        }

        DateTimeOffset timestamp;
        try { timestamp = DateTimeOffset.FromUnixTimeSeconds(timestampSeconds); }
        catch (ArgumentOutOfRangeException) { return new(DeviceRequestProofStatus.Invalid); }
        var skew = timestamp - clock.GetUtcNow();
        if (skew < -TimestampTolerance || skew > TimestampTolerance)
        {
            return new(DeviceRequestProofStatus.Expired);
        }

        RegisteredDevice? device;
        try
        {
            device = await repository.GetDeviceAsync(proof.DeviceId, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return new(DeviceRequestProofStatus.StateUnavailable); }

        if (device is null || device.TrustState != DeviceTrustState.ProofOfPossessionVerified)
        {
            return new(DeviceRequestProofStatus.Invalid);
        }
        if (device.RevocationState != DeviceRevocationState.Active)
        {
            return new(DeviceRequestProofStatus.Revoked);
        }

        var expectedDigest = DeviceRequestProofCanonicalizer.BodyDigest(body);
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(expectedDigest),
                Encoding.ASCII.GetBytes(proof.BodyDigest)))
        {
            return new(DeviceRequestProofStatus.Invalid);
        }

        var signingInput = DeviceRequestProofCanonicalizer.SigningInput(
            proof.DeviceId, method, path, proof.BodyDigest, proof.Timestamp, proof.Nonce);
        if (!proofVerifier.VerifySignature(
                new ValidatedDevicePublicKey(device.KeyAlgorithm, device.PublicKey, device.PublicKeyFingerprint),
                signingInput,
                proof.Signature))
        {
            return new(DeviceRequestProofStatus.Invalid);
        }

        try
        {
            var reserved = await nonceStore.TryReserveAsync(
                    proof.DeviceId,
                    proof.Nonce,
                    ReplayReservationLifetime,
                    cancellationToken)
                .ConfigureAwait(false);
            return new(reserved ? DeviceRequestProofStatus.Accepted : DeviceRequestProofStatus.Replayed);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return new(DeviceRequestProofStatus.StateUnavailable); }
    }
}

public static class DeviceRequestProofCanonicalizer
{
    private const string Version = "HIP-DEVICE-REQUEST-V1";
    private static readonly JsonSerializerOptions WebJsonOptions = new(JsonSerializerDefaults.Web);

    public static string BodyDigest<TBody>(TBody body)
    {
        var canonical = CanonicalJson(JsonSerializer.SerializeToElement(body, WebJsonOptions));
        return $"sha256:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant()}";
    }

    public static byte[] SigningInput(
        string deviceId,
        string method,
        string path,
        string bodyDigest,
        string timestamp,
        string nonce) => Encoding.UTF8.GetBytes(
            $"{Version}\n{deviceId}\n{method.ToUpperInvariant()}\n{path}\n{bodyDigest}\n{timestamp}\n{nonce}");

    public static bool IsValidProofShape(DeviceRequestProof? proof) =>
        proof is not null &&
        proof.DeviceId is { Length: > 4 and <= 160 } && proof.DeviceId.StartsWith("dev_", StringComparison.Ordinal) &&
        proof.Timestamp is { Length: >= 10 and <= 64 } &&
        proof.Nonce is { Length: >= 22 and <= 128 } && IsBase64Url(proof.Nonce) &&
        proof.BodyDigest is { Length: 71 } && proof.BodyDigest.StartsWith("sha256:", StringComparison.Ordinal) &&
        proof.BodyDigest[7..].All(static character => char.IsAsciiHexDigit(character) && !char.IsUpper(character)) &&
        proof.Signature is { Length: Es256DeviceProofVerifier.EncodedSignatureCharacters } && IsBase64Url(proof.Signature);

    private static string CanonicalJson(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Object => $"{{{string.Join(",", element.EnumerateObject()
            .OrderBy(property => property.Name, StringComparer.Ordinal)
            .Select(property => $"{JsonSerializer.Serialize(property.Name)}:{CanonicalJson(property.Value)}"))}}}",
        JsonValueKind.Array => $"[{string.Join(",", element.EnumerateArray().Select(CanonicalJson))}]",
        JsonValueKind.String => JsonSerializer.Serialize(element.GetString()),
        JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null => element.GetRawText(),
        _ => throw new ArgumentException("Device request proof body is not canonicalizable.")
    };

    private static bool IsBase64Url(string value) => value.All(static character =>
        char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
}
