using System.Security.Cryptography;
using System.Text;
using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Contracts;
using Microsoft.Extensions.Options;

namespace HIP.ApiService.Infrastructure.Security;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <returns>The operation result.</returns>
public sealed class EcdsaMessageSignatureService(
    IOptions<CryptoProviderOptions> options,
    IReplayProtectionService replayProtection,
    IReplayAssessmentService replayAssessment,
    IReputationService reputationService,
    ISecurityEventCounter securityCounter,
    ISecurityRejectLog securityRejectLog,
    ILogger<EcdsaMessageSignatureService> logger) : IMessageSignatureService
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="request">The request value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public Task<SignMessageResultDto> SignAsync(SignMessageRequestDto request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request); // validation

        var provider = options.Value.Provider?.Trim() ?? "Placeholder";
        if (!provider.Equals("ECDsa", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(new SignMessageResultDto(false, "provider_not_enabled", null));
        }

        var privateStorePath = options.Value.PrivateKeyStorePath;
        if (string.IsNullOrWhiteSpace(privateStorePath))
        {
            return Task.FromResult(new SignMessageResultDto(false, "missing_private_key_store", null));
        }

        var keyIdMissing = string.IsNullOrWhiteSpace(request.KeyId);
        var keyId = keyIdMissing ? request.From : request.KeyId!.Trim();
        if (keyIdMissing)
        {
            logger.LogWarning("Signing request from {From} omitted keyId; defaulting to legacy key id '{KeyId}'.", request.From, keyId);
        }

        var keyPath = Path.Combine(privateStorePath, $"{keyId}.key");
        if (!File.Exists(keyPath))
        {
            return Task.FromResult(new SignMessageResultDto(false, "private_key_not_found", null));
        }

        try
        {
            var keyPem = File.ReadAllText(keyPath);
            var id = string.IsNullOrWhiteSpace(request.Id) ? Guid.NewGuid().ToString("n") : request.Id;
            var createdAtUtc = DateTimeOffset.UtcNow;
            var payload = Encoding.UTF8.GetBytes($"{id}|{request.From}|{request.To}|{request.Body}|{keyId}|{createdAtUtc.ToUnixTimeSeconds()}");

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(keyPem);
            var signature = ecdsa.SignData(payload, HashAlgorithmName.SHA256);

            var message = new SignedMessageDto(id, request.From, request.To, request.Body, Convert.ToBase64String(signature), keyId, createdAtUtc);
            logger.LogInformation("Message signing completed for {From} -> {To} using keyId {KeyId}", request.From, request.To, keyId);
            return Task.FromResult(new SignMessageResultDto(true, "ok", message));
        }
        catch (CryptographicException ex)
        {
            logger.LogWarning(ex, "Cryptographic signing failure.");
            return Task.FromResult(new SignMessageResultDto(false, "crypto_error", null));
        }
    }

    private static readonly TimeSpan MaxMessageAge = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaxFutureSkew = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="message">The message value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public Task<VerifyMessageResultDto> VerifyAsync(SignedMessageDto message, CancellationToken cancellationToken)
        => VerifyCoreAsync(message, consumeReplayNonce: true, cancellationToken);

    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="message">The message value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public Task<VerifyMessageResultDto> VerifyReadOnlyAsync(SignedMessageDto message, CancellationToken cancellationToken)
        => VerifyCoreAsync(message, consumeReplayNonce: false, cancellationToken);

    private async Task<VerifyMessageResultDto> VerifyCoreAsync(SignedMessageDto message, bool consumeReplayNonce, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message); // validation

        var provider = options.Value.Provider?.Trim() ?? "Placeholder";
        if (!provider.Equals("ECDsa", StringComparison.OrdinalIgnoreCase))
        {
            return new VerifyMessageResultDto(false, "provider_not_enabled");
        }

        var storePath = options.Value.PublicKeyStorePath;
        if (string.IsNullOrWhiteSpace(storePath))
        {
            return new VerifyMessageResultDto(false, "missing_public_key_store");
        }

        if (message.CreatedAtUtc is null)
        {
            return new VerifyMessageResultDto(false, "missing_timestamp");
        }

        var now = DateTimeOffset.UtcNow;
        var age = now - message.CreatedAtUtc.Value;
        if (age > MaxMessageAge || age < -MaxFutureSkew)
        {
            securityCounter.IncrementMessageExpired();
            securityRejectLog.Add(new SecurityRejectEvent(
                Reason: "message_expired",
                IdentityId: message.From,
                MessageId: message.Id,
                ClockSkewSeconds: age.TotalSeconds,
                Classification: null,
                UtcTimestamp: DateTimeOffset.UtcNow));
            return new VerifyMessageResultDto(false, "message_expired");
        }

        var keyIdMissing = string.IsNullOrWhiteSpace(message.KeyId);
        var keyId = keyIdMissing ? message.From : message.KeyId!.Trim();
        if (keyIdMissing)
        {
            logger.LogWarning("Verification request from {From} omitted keyId; defaulting to legacy key id '{KeyId}'.", message.From, keyId);
        }

        var keyPath = Path.Combine(storePath, $"{keyId}.pub");
        if (!File.Exists(keyPath))
        {
            return new VerifyMessageResultDto(false, "public_key_not_found");
        }

        try
        {
            var keyPem = File.ReadAllText(keyPath);
            var signature = Convert.FromBase64String(message.SignatureBase64);

            var payload = Encoding.UTF8.GetBytes($"{message.Id}|{message.From}|{message.To}|{message.Body}|{keyId}|{message.CreatedAtUtc.Value.ToUnixTimeSeconds()}");

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(keyPem);
            var valid = ecdsa.VerifyData(payload, signature, HashAlgorithmName.SHA256);

            if (!valid)
            {
                logger.LogInformation("Message signature verification completed for {From} -> {To} using keyId {KeyId}: {Result}", message.From, message.To, keyId, false);
                return new VerifyMessageResultDto(false, "invalid_signature");
            }

            if (consumeReplayNonce && !await replayProtection.TryConsumeAsync(message.Id, message.From, cancellationToken))
            {
                securityCounter.IncrementReplayDetected();
                var assessment = replayAssessment.RegisterReplay(message.From, message.Id);

                if (assessment.ShouldPenalize)
                {
                    await reputationService.RecordSecurityEventAsync(message.From, "replay_abuse", cancellationToken);
                }
                else
                {
                    await reputationService.RecordSecurityEventAsync(message.From, "replay_benign", cancellationToken);
                }

                securityRejectLog.Add(new SecurityRejectEvent(
                    Reason: "replay_detected",
                    IdentityId: message.From,
                    MessageId: message.Id,
                    ClockSkewSeconds: age.TotalSeconds,
                    Classification: assessment.Classification,
                    UtcTimestamp: DateTimeOffset.UtcNow));

                logger.LogWarning("Replay detected for signed message {MessageId} from {From}. Classification={Classification} Count={Count}",
                    message.Id, message.From, assessment.Classification, assessment.RecentReplayCount);
                return new VerifyMessageResultDto(false, "replay_detected");
            }

            logger.LogInformation("Message signature verification completed for {From} -> {To} using keyId {KeyId}: {Result}", message.From, message.To, keyId, true);
            return new VerifyMessageResultDto(true, "ok");
        }
        catch (FormatException ex)
        {
            logger.LogWarning(ex, "Invalid base64 format for signature verification input.");
            return new VerifyMessageResultDto(false, "invalid_format");
        }
        catch (CryptographicException ex)
        {
            logger.LogWarning(ex, "Cryptographic verification failure.");
            return new VerifyMessageResultDto(false, "crypto_error");
        }
    }
}
