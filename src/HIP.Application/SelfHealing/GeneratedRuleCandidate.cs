using HIP.Application.Simulation;
using HIP.Domain.Rules;
using HIP.Domain.SelfHealing;

namespace HIP.Application.SelfHealing;

public sealed record GeneratedRuleCandidate(
    string CandidateId,
    string SourceClusterId,
    TrustRule ProposedRule,
    DateTimeOffset CreatedAtUtc,
    string CreatedReason,
    RuleSimulationResult SimulationResult,
    decimal ConfidenceScore,
    RuleMode RecommendedMode,
    ApprovalStatus ApprovalStatus,
    RuleRollbackPlan RollbackPlan,
    GeneratedRuleCandidateStatus Status);
