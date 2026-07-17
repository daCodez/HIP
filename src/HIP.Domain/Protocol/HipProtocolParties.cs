using System.Text.Json.Serialization;
using HIP.Domain.Identity;

namespace HIP.Domain.Protocol;

public sealed record HipProtocolIssuer
{
    public const int MaximumIdLength = 256;

    [JsonConstructor]
    public HipProtocolIssuer(string id)
    {
        Id = HipProtocolValidation.RequiredIdentifier(id, nameof(id), MaximumIdLength);
    }

    [JsonPropertyName("id")]
    [JsonPropertyOrder(0)]
    public string Id { get; }
}

public sealed record HipProtocolSubject
{
    public const int MaximumIdLength = 512;

    [JsonConstructor]
    public HipProtocolSubject(IdentitySubjectType type, string id)
    {
        if (!Enum.IsDefined(type))
        {
            throw new ArgumentOutOfRangeException(nameof(type), type, "HIP protocol subject type is unsupported.");
        }

        Type = type;
        Id = HipProtocolValidation.RequiredIdentifier(id, nameof(id), MaximumIdLength);
    }

    [JsonPropertyName("type")]
    [JsonPropertyOrder(0)]
    public IdentitySubjectType Type { get; }

    [JsonPropertyName("id")]
    [JsonPropertyOrder(1)]
    public string Id { get; }
}
