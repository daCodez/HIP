namespace HIP.Domain.Scoring;

public static class HipScoringModel
{
    public static HipScoreResult CalculateFinalScore(IEnumerable<WeightedScore> weightedScores)
    {
        var scores = weightedScores?.ToArray() ?? throw new ArgumentNullException(nameof(weightedScores));
        if (scores.Length == 0)
        {
            throw new ArgumentException("At least one score is required to calculate a final HIP score.", nameof(weightedScores));
        }

        var weightedTotal = scores.Sum(score => score.Component.Score.Value * score.Weight);
        var totalWeight = scores.Sum(score => score.Weight);
        var finalValue = (int)Math.Round(weightedTotal / totalWeight, MidpointRounding.AwayFromZero);

        var finalScore = new ScoreComponent(
            ScoreCategory.Final,
            ScoreValue.From(finalValue),
            BuildFinalExplanation(scores, finalValue));

        return new HipScoreResult(finalScore, scores.Select(score => score.Component).ToArray());
    }

    private static string BuildFinalExplanation(IReadOnlyCollection<WeightedScore> scores, int finalValue)
    {
        var weakest = scores.OrderBy(score => score.Component.Score.Value).First().Component;
        var strongest = scores.OrderByDescending(score => score.Component.Score.Value).First().Component;

        return $"The final HIP score is {finalValue}/100 based on weighted trust signals. " +
               $"The weakest signal is {weakest.Category} at {weakest.Score.Value}/100: {weakest.Explanation} " +
               $"The strongest signal is {strongest.Category} at {strongest.Score.Value}/100: {strongest.Explanation}";
    }
}
