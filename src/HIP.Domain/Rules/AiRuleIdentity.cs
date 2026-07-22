using System.Security.Cryptography;
using System.Text;

namespace HIP.Domain.Rules;

/// <summary>Reserved identity namespace for AI rule provenance; it never grants human authority.</summary>
public static class AiRuleIdentity
{
    public const string Prefix = "ai:";

    public static string ProviderActor(string providerName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        return $"{Prefix}{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(providerName.Trim()))).ToLowerInvariant()[..32]}";
    }

    public static bool IsAiActor(string? actorId) =>
        actorId?.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase) is true;

    public static void RejectAiActor(string actorId)
    {
        if (IsAiActor(actorId))
            throw new InvalidOperationException("AI identities cannot approve or change rule deployments.");
    }
}
