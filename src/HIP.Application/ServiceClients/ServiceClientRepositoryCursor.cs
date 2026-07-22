using System.Security.Cryptography;
using System.Text;

namespace HIP.Application.ServiceClients;

/// <summary>
/// Shared canonical owner-bound cursor codec used by every service-client repository implementation.
/// </summary>
public static class ServiceClientRepositoryCursor
{
    public const int MaximumCursorLength = 512;
    private const string CursorPrefix = "scv2_";
    private const string OwnerScopePrefix = "service-client-owner-hmac-sha256-v1:";
    private const int AuthenticationTagBytes = 32;
    private static readonly byte[] CursorDomain = "HIP\0service-client\0cursor\0v2\0"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    /// <summary>Validates the exact versioned owner-scope format shared by persistence boundaries.</summary>
    public static void ValidateOwnerScopeId(string ownerScopeId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerScopeId);
        if (ownerScopeId.Length != OwnerScopePrefix.Length + 64 ||
            !ownerScopeId.StartsWith(OwnerScopePrefix, StringComparison.Ordinal) ||
            ownerScopeId.AsSpan(OwnerScopePrefix.Length).ContainsAnyExcept("0123456789abcdef"))
        {
            throw new ArgumentException("The service-client owner scope is invalid.", nameof(ownerScopeId));
        }
    }

    /// <summary>Validates a current-first, unique and bounded owner-partition set.</summary>
    public static void ValidateOwnerScopeIds(IReadOnlyList<string> ownerScopeIds)
    {
        ArgumentNullException.ThrowIfNull(ownerScopeIds);
        if (ownerScopeIds.Count is < 1 or > HIP.Application.Reporting.PrivacyHashingOptions.MaximumKeyCount)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ownerScopeIds),
                $"A service-client owner lookup requires between 1 and {HIP.Application.Reporting.PrivacyHashingOptions.MaximumKeyCount} partitions.");
        }

        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var ownerScopeId in ownerScopeIds)
        {
            ValidateOwnerScopeId(ownerScopeId);
            if (!unique.Add(ownerScopeId))
            {
                throw new ArgumentException(
                    "Service-client owner partitions must be unique and current-first.",
                    nameof(ownerScopeIds));
            }
        }
    }

    /// <summary>Returns whether a client identifier uses HIP's canonical version-one opaque form.</summary>
    public static bool IsCanonicalClientId(string? clientId) =>
        ServiceClientCredentialFormat.IsCanonicalClientId(clientId);

    /// <summary>
    /// Encodes a last-returned client ID with an authentication tag bound to the current owner
    /// scope. The owner scope itself is never included in the cursor payload.
    /// </summary>
    public static string Encode(string ownerScopeId, string clientId)
    {
        ValidateOwnerScopeId(ownerScopeId);
        if (!IsCanonicalClientId(clientId))
        {
            throw new ArgumentException("The service-client identifier is invalid.", nameof(clientId));
        }

        var clientBytes = StrictUtf8.GetBytes(clientId);
        var tag = ComputeTag(ownerScopeId, clientBytes);
        var payload = new byte[clientBytes.Length + tag.Length];
        clientBytes.CopyTo(payload, 0);
        tag.CopyTo(payload, clientBytes.Length);
        return CursorPrefix + EncodeBase64Url(payload);
    }

    /// <summary>Decodes a canonical cursor and proves that it belongs to the requested current owner scope.</summary>
    public static string Decode(string cursor, string expectedOwnerScopeId)
    {
        ValidateOwnerScopeId(expectedOwnerScopeId);
        if (string.IsNullOrWhiteSpace(cursor) ||
            cursor.Length > MaximumCursorLength ||
            !cursor.StartsWith(CursorPrefix, StringComparison.Ordinal))
        {
            throw InvalidCursor(nameof(cursor));
        }

        var encoded = cursor[CursorPrefix.Length..];
        if (encoded.Length == 0 || encoded.Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_')))
        {
            throw InvalidCursor(nameof(cursor));
        }

        try
        {
            var standard = encoded.Replace('-', '+').Replace('_', '/');
            standard = standard.PadRight(standard.Length + ((4 - (standard.Length % 4)) % 4), '=');
            var bytes = Convert.FromBase64String(standard);
            if (!string.Equals(EncodeBase64Url(bytes), encoded, StringComparison.Ordinal) ||
                bytes.Length <= AuthenticationTagBytes)
            {
                throw InvalidCursor(nameof(cursor));
            }

            var clientBytes = bytes.AsSpan(0, bytes.Length - AuthenticationTagBytes);
            var suppliedTag = bytes.AsSpan(bytes.Length - AuthenticationTagBytes);
            var clientId = StrictUtf8.GetString(clientBytes);
            if (!IsCanonicalClientId(clientId))
            {
                throw InvalidCursor(nameof(cursor));
            }

            var expectedTag = ComputeTag(expectedOwnerScopeId, clientBytes);
            if (!CryptographicOperations.FixedTimeEquals(expectedTag, suppliedTag))
            {
                throw InvalidCursor(nameof(cursor));
            }

            return clientId;
        }
        catch (Exception exception) when (exception is FormatException or DecoderFallbackException)
        {
            throw InvalidCursor(nameof(cursor), exception);
        }
    }

    private static byte[] ComputeTag(string ownerScopeId, ReadOnlySpan<byte> clientBytes)
    {
        var input = new byte[CursorDomain.Length + clientBytes.Length];
        CursorDomain.CopyTo(input, 0);
        clientBytes.CopyTo(input.AsSpan(CursorDomain.Length));
        return HMACSHA256.HashData(StrictUtf8.GetBytes(ownerScopeId), input);
    }

    private static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static ArgumentException InvalidCursor(string parameterName, Exception? innerException = null) =>
        new("The service-client continuation cursor is invalid.", parameterName, innerException);
}
