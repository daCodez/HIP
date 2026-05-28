using HIP.Domain.Risk;

namespace HIP.Domain.Scoring;

public sealed record ScoreComponent
{
    public ScoreComponent(ScoreCategory category, ScoreValue score, string explanation)
        : this(category, score, explanation, [explanation])
    {
    }

    public ScoreComponent(ScoreCategory category, ScoreValue score, string explanation, IReadOnlyCollection<string> reasons)
    {
        if (string.IsNullOrWhiteSpace(explanation))
        {
            throw new ArgumentException("Every HIP score must include a plain-English explanation.", nameof(explanation));
        }

        if (reasons.Count == 0 || reasons.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("Every HIP score must include at least one plain-English reason.", nameof(reasons));
        }

        Category = category;
        Score = score;
        Explanation = explanation.Trim();
        Reasons = reasons.Select(reason => reason.Trim()).ToArray();
    }

    public ScoreCategory Category { get; }

    public ScoreValue Score { get; }

    public string Explanation { get; }

    public IReadOnlyCollection<string> Reasons { get; }

    public TrustLevel TrustLevel => Score.ToTrustLevel();

    public RiskStatus Status => RiskStatusMapper.FromScore(Score);
}
