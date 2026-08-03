using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace HIP.Infrastructure.Protocol;

internal sealed record SoftHsmSigningKey(string PublicKeyPem);

internal interface ISoftHsmPkcs11Client
{
    Task<SoftHsmSigningKey> GetSigningKeyAsync(CancellationToken cancellationToken);

    Task<SoftHsmSigningKey> GetOrCreateSigningKeyAsync(
        string keyLabel,
        CancellationToken cancellationToken);

    Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken);
}

/// <summary>
/// Uses the PKCS #11 boundary exposed by SoftHSM. Private key attributes are never read or exported.
/// </summary>
internal sealed class SoftHsmPkcs11Client(SoftHsmManagedSigningOptions options) : ISoftHsmPkcs11Client
{
    internal const ulong MlDsaKeyType = 0x4A;
    internal const ulong MlDsaKeyPairGenerationMechanism = 0x1C;
    internal const ulong MlDsaSigningMechanism = 0x1D;
    internal const ulong ParameterSetAttribute = 0x61D;
    internal const ulong MlDsa65ParameterSet = 2;
    internal const int MlDsa65PublicKeySize = 1_952;
    internal const int MlDsa65SignatureSize = 3_309;
    internal const string MlDsa65ObjectIdentifier = "2.16.840.1.101.3.4.3.18";

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly TimeSpan ProvisioningLockTimeout = TimeSpan.FromSeconds(30);
    private readonly SoftHsmManagedSigningOptions settings = options;
    private readonly Pkcs11InteropFactories factories = new();

    public async Task<SoftHsmSigningKey> GetSigningKeyAsync(CancellationToken cancellationToken)
        => await GetOrCreateSigningKeyAsync(settings.KeyLabel, cancellationToken).ConfigureAwait(false);

    public async Task<SoftHsmSigningKey> GetOrCreateSigningKeyAsync(
        string keyLabel,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var normalizedLabel = NormalizeKeyLabel(keyLabel);
        var existing = ReadPublicKey(normalizedLabel, required: !settings.ProvisionKeyIfMissing);
        if (existing is not null)
        {
            return existing;
        }

        await using var provisioningLock = await AcquireProvisioningLockAsync(cancellationToken)
            .ConfigureAwait(false);
        existing = ReadPublicKey(normalizedLabel, required: false);
        if (existing is not null)
        {
            return existing;
        }

        GenerateKeyPair(normalizedLabel);
        return ReadPublicKey(normalizedLabel, required: true)!;
    }

    public Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (data.IsEmpty || data.Length > 1_024)
        {
            throw new ArgumentOutOfRangeException(nameof(data), "HIP signing input must contain between 1 and 1024 bytes.");
        }

        using var library = LoadLibrary();
        var slot = GetRequiredSlot(library);
        using var session = slot.OpenSession(SessionType.ReadOnly);
        var pin = ReadPin();
        try
        {
            session.Login(CKU.CKU_USER, pin);
            var privateKey = FindRequiredKey(session, CKO.CKO_PRIVATE_KEY, settings.KeyLabel);
            using var mechanism = factories.MechanismFactory.Create(MlDsaSigningMechanism);
            var signature = session.Sign(mechanism, privateKey, data.ToArray());
            if (signature.Length != MlDsa65SignatureSize)
            {
                throw new InvalidOperationException("SoftHSM returned a signature with the wrong ML-DSA-65 length.");
            }

            return Task.FromResult(signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pin);
        }
    }

    internal static string EncodePublicKey(ReadOnlySpan<byte> rawPublicKey)
    {
        if (rawPublicKey.Length != MlDsa65PublicKeySize)
        {
            throw new InvalidOperationException("SoftHSM returned a public key with the wrong ML-DSA-65 length.");
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteObjectIdentifier(MlDsa65ObjectIdentifier);
        writer.PopSequence();
        writer.WriteBitString(rawPublicKey);
        writer.PopSequence();
        return PemEncoding.WriteString("PUBLIC KEY", writer.Encode());
    }

    private SoftHsmSigningKey? ReadPublicKey(string keyLabel, bool required)
    {
        using var library = LoadLibrary();
        var slot = GetRequiredSlot(library);
        using var session = slot.OpenSession(SessionType.ReadOnly);
        var keys = FindKeys(session, CKO.CKO_PUBLIC_KEY, keyLabel);
        if (keys.Count == 0 && !required)
        {
            return null;
        }

        if (keys.Count != 1)
        {
            throw new InvalidOperationException(
                keys.Count == 0
                    ? "The configured SoftHSM ML-DSA-65 public key does not exist."
                    : "The configured SoftHSM key selector matched more than one public key.");
        }

        var attributes = session.GetAttributeValue(
            keys[0],
            [ParameterSetAttribute, (ulong)CKA.CKA_VALUE]);
        using var parameterSet = attributes[0];
        using var value = attributes[1];
        if (parameterSet.CannotBeRead || parameterSet.GetValueAsUlong() != MlDsa65ParameterSet)
        {
            throw new InvalidOperationException("The configured SoftHSM public key is not ML-DSA-65.");
        }

        if (value.CannotBeRead)
        {
            throw new InvalidOperationException("SoftHSM did not expose the public portion of the signing key.");
        }

        return new SoftHsmSigningKey(EncodePublicKey(value.GetValueAsByteArray()));
    }

    private void GenerateKeyPair(string keyLabel)
    {
        using var library = LoadLibrary();
        var slot = GetRequiredSlot(library);
        using var session = slot.OpenSession(SessionType.ReadWrite);
        var pin = ReadPin();
        try
        {
            session.Login(CKU.CKU_USER, pin);
            if (FindKeys(session, CKO.CKO_PUBLIC_KEY, keyLabel).Count != 0 ||
                FindKeys(session, CKO.CKO_PRIVATE_KEY, keyLabel).Count != 0)
            {
                return;
            }

            var keyId = StrictUtf8.GetBytes(keyLabel);
            var publicAttributes = new List<IObjectAttribute>
            {
                factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, keyLabel),
                factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyId),
                factories.ObjectAttributeFactory.Create((ulong)CKA.CKA_KEY_TYPE, MlDsaKeyType),
                factories.ObjectAttributeFactory.Create(ParameterSetAttribute, MlDsa65ParameterSet),
                factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true)
            };
            var privateAttributes = new List<IObjectAttribute>
            {
                factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, keyLabel),
                factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyId),
                factories.ObjectAttributeFactory.Create((ulong)CKA.CKA_KEY_TYPE, MlDsaKeyType),
                factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true),
                factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true),
                factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, false)
            };
            using var mechanism = factories.MechanismFactory.Create(MlDsaKeyPairGenerationMechanism);
            session.GenerateKeyPair(mechanism, publicAttributes, privateAttributes, out _, out _);
            foreach (var attribute in publicAttributes.Concat(privateAttributes))
            {
                attribute.Dispose();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pin);
        }
    }

    private IObjectHandle FindRequiredKey(ISession session, CKO keyClass, string keyLabel)
    {
        var keys = FindKeys(session, keyClass, keyLabel);
        if (keys.Count != 1)
        {
            throw new InvalidOperationException(
                keys.Count == 0
                    ? "The configured SoftHSM signing key does not exist."
                    : "The configured SoftHSM key selector matched more than one key.");
        }

        return keys[0];
    }

    private List<IObjectHandle> FindKeys(ISession session, CKO keyClass, string keyLabel)
    {
        var template = new List<IObjectAttribute>
        {
            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, keyClass),
            factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, NormalizeKeyLabel(keyLabel)),
            factories.ObjectAttributeFactory.Create((ulong)CKA.CKA_KEY_TYPE, MlDsaKeyType)
        };
        try
        {
            return session.FindAllObjects(template);
        }
        finally
        {
            foreach (var attribute in template)
            {
                attribute.Dispose();
            }
        }
    }

    private static string NormalizeKeyLabel(string keyLabel)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyLabel);
        var normalized = keyLabel.Trim();
        if (normalized.Length > 128 || normalized.Any(char.IsControl))
        {
            throw new ArgumentException("The SoftHSM key label is invalid.", nameof(keyLabel));
        }

        return normalized;
    }

    private IPkcs11Library LoadLibrary()
    {
        if (!File.Exists(settings.LibraryPath))
        {
            throw new InvalidOperationException("The configured SoftHSM PKCS #11 library is unavailable.");
        }

        return factories.Pkcs11LibraryFactory.LoadPkcs11Library(
            factories,
            settings.LibraryPath,
            AppType.MultiThreaded);
    }

    private ISlot GetRequiredSlot(IPkcs11Library library)
    {
        var matching = library.GetSlotList(SlotsType.WithTokenPresent)
            .Where(slot => string.Equals(
                slot.GetTokenInfo().Label.Trim(),
                settings.TokenLabel.Trim(),
                StringComparison.Ordinal))
            .ToArray();
        return matching.Length switch
        {
            1 => matching[0],
            0 => throw new InvalidOperationException("The configured SoftHSM token is unavailable."),
            _ => throw new InvalidOperationException("More than one SoftHSM token has the configured label.")
        };
    }

    private byte[] ReadPin()
    {
        if (!File.Exists(settings.UserPinFilePath))
        {
            throw new InvalidOperationException("The configured SoftHSM user PIN file is unavailable.");
        }

        var pin = File.ReadAllBytes(settings.UserPinFilePath);
        var length = pin.Length;
        while (length > 0 && pin[length - 1] is (byte)'\r' or (byte)'\n')
        {
            length--;
        }

        if (length is < 4 or > 255)
        {
            CryptographicOperations.ZeroMemory(pin);
            throw new InvalidOperationException("The SoftHSM user PIN file has an invalid length.");
        }

        if (length == pin.Length)
        {
            return pin;
        }

        var normalized = pin[..length];
        CryptographicOperations.ZeroMemory(pin);
        return normalized;
    }

    private async Task<FileStream> AcquireProvisioningLockAsync(CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + ProvisioningLockTimeout;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(
                    settings.ProvisioningLockFilePath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    bufferSize: 1,
                    FileOptions.Asynchronous);
            }
            catch (IOException) when (DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(200), cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
