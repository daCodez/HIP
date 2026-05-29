namespace HIP.Application.Identity;

public interface IHipCryptoProvider
{
    HipKeyPair GenerateKeyPair();

    string SignHash(string contentHash, string privateKey);

    bool VerifySignature(string contentHash, string signatureValue, string publicKey);

    string HashContent(string content);
}
