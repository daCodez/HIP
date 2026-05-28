using HIP.Domain.Scoring;

namespace HIP.Domain.Rules;

public sealed record RuleAction(
    RuleActionType Type,
    ScoreCategory? Category,
    int? Points,
    string Reason);
