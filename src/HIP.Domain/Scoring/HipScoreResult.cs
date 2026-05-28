namespace HIP.Domain.Scoring;

public sealed record HipScoreResult
{
    public HipScoreResult(ScoreComponent finalScore, IReadOnlyCollection<ScoreComponent> componentScores)
    {
        if (componentScores.Count == 0)
        {
            throw new ArgumentException("A HIP score result must include at least one component score.", nameof(componentScores));
        }

        FinalScore = finalScore ?? throw new ArgumentNullException(nameof(finalScore));
        ComponentScores = componentScores;
    }

    public ScoreComponent FinalScore { get; }

    public IReadOnlyCollection<ScoreComponent> ComponentScores { get; }
}
