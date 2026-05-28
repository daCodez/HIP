namespace HIP.Domain.Scoring;

public sealed record ScoreComponent
{
    public ScoreComponent(ScoreCategory category, ScoreValue score, string explanation)
    {
        if (string.IsNullOrWhiteSpace(explanation))
        {
            throw new ArgumentException("Every HIP score must include a plain-English explanation.", nameof(explanation));
        }

        Category = category;
        Score = score;
        Explanation = explanation.Trim();
    }

    public ScoreCategory Category { get; }

    public ScoreValue Score { get; }

    public string Explanation { get; }

    public TrustLevel TrustLevel => Score.ToTrustLevel();
}
