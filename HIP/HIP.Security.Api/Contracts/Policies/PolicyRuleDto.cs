using System.ComponentModel.DataAnnotations;

namespace HIP.Security.Api.Contracts.Policies;

public sealed record PolicyRuleDto(
    [property: Required, MaxLength(100)] string Key,
    [property: Required, MaxLength(16)] string Operator,
    [property: Required, MaxLength(256)] string Value);
