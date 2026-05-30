using System.Security.Cryptography;
using System.Text;

namespace HIP.Application.Reporting;

public sealed class Sha256PrivacyHashingService : IPrivacyHashingService
{
    public string Hash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return $"sha256:{Convert.ToHexString(bytes).ToLowerInvariant()}";
    }
}
