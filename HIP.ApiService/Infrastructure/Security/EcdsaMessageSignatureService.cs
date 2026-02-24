using System.Security.Cryptography;
using System.Text;
using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Contracts;
using Microsoft.Extensions.Options;

namespace HIP.ApiService.Infrastructure.Security;

public sealed class EcdsaMessageSignatureService(
    IOptions<CryptoProviderOptions> options,
    ILogger<EcdsaMessageSignatureService> logger) : IMessageSignatureService
{
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

        var keyId = string.IsNullOrWhiteSpace(request.KeyId) ? request.From : request.KeyId.Trim();
        var keyPath = Path.Combine(privateStorePath, $"{keyId}.key");
        if (!File.Exists(keyPath))
        {
            return Task.FromResult(new SignMessageResultDto(false, "private_key_not_found", null));
        }

        try
        {
            var keyPem = File.ReadAllText(keyPath);
            var id = string.IsNullOrWhiteSpace(request.Id) ? Guid.NewGuid().ToString("n") : request.Id;
            var payload = Encoding.UTF8.GetBytes($"{id}|{request.From}|{request.To}|{request.Body}|{keyId}");

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(keyPem);
            var signature = ecdsa.SignData(payload, HashAlgorithmName.SHA256);

            var message = new SignedMessageDto(id, request.From, request.To, request.Body, Convert.ToBase64String(signature), keyId);
            logger.LogInformation("Message signing completed for {From} -> {To} using keyId {KeyId}", request.From, request.To, keyId);
            return Task.FromResult(new SignMessageResultDto(true, "ok", message));
        }
        catch (CryptographicException ex)
        {
            logger.LogWarning(ex, "Cryptographic signing failure.");
            return Task.FromResult(new SignMessageResultDto(false, "crypto_error", null));
        }
    }

    public Task<VerifyMessageResultDto> VerifyAsync(SignedMessageDto message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message); // validation

        var provider = options.Value.Provider?.Trim() ?? "Placeholder";
        if (!provider.Equals("ECDsa", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(new VerifyMessageResultDto(false, "provider_not_enabled"));
        }

        var storePath = options.Value.PublicKeyStorePath;
        if (string.IsNullOrWhiteSpace(storePath))
        {
            return Task.FromResult(new VerifyMessageResultDto(false, "missing_public_key_store"));
        }

        var keyId = string.IsNullOrWhiteSpace(message.KeyId) ? message.From : message.KeyId.Trim();
        var keyPath = Path.Combine(storePath, $"{keyId}.pub");
        if (!File.Exists(keyPath))
        {
            return Task.FromResult(new VerifyMessageResultDto(false, "public_key_not_found"));
        }

        try
        {
            var keyPem = File.ReadAllText(keyPath);
            var signature = Convert.FromBase64String(message.SignatureBase64);

            var payload = Encoding.UTF8.GetBytes($"{message.Id}|{message.From}|{message.To}|{message.Body}|{keyId}");

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(keyPem);
            var valid = ecdsa.VerifyData(payload, signature, HashAlgorithmName.SHA256);

            logger.LogInformation("Message signature verification completed for {From} -> {To} using keyId {KeyId}: {Result}", message.From, message.To, keyId, valid);
            return Task.FromResult(new VerifyMessageResultDto(valid, valid ? "ok" : "invalid_signature"));
        }
        catch (FormatException ex)
        {
            logger.LogWarning(ex, "Invalid base64 format for signature verification input.");
            return Task.FromResult(new VerifyMessageResultDto(false, "invalid_format"));
        }
        catch (CryptographicException ex)
        {
            logger.LogWarning(ex, "Cryptographic verification failure.");
            return Task.FromResult(new VerifyMessageResultDto(false, "crypto_error"));
        }
    }
}
