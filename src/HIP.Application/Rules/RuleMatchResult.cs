using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public sealed record RuleMatchResult(
    TrustRule Rule,
    bool IsMatch,
    IReadOnlyCollection<string> MatchedFields,
    IReadOnlyCollection<string> FailedFields);
