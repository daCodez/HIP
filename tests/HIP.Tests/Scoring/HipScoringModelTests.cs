using HIP.Domain.Scoring;

namespace HIP.Tests.Scoring;

public sealed class HipScoringModelTests
{
    [TestCase(0, TrustLevel.Dangerous)]
    [TestCase(20, TrustLevel.Dangerous)]
    [TestCase(21, TrustLevel.HighRisk)]
    [TestCase(40, TrustLevel.HighRisk)]
    [TestCase(41, TrustLevel.Caution)]
    [TestCase(60, TrustLevel.Caution)]
    [TestCase(61, TrustLevel.ProbablySafe)]
    [TestCase(80, TrustLevel.ProbablySafe)]
    [TestCase(81, TrustLevel.Trusted)]
    [TestCase(100, TrustLevel.Trusted)]
    public void ScoreValue_maps_to_expected_trust_level(int score, TrustLevel expected)
    {
        Assert.That(ScoreValue.From(score).ToTrustLevel(), Is.EqualTo(expected));
    }

    [TestCase(-1)]
    [TestCase(101)]
    public void ScoreValue_rejects_scores_outside_hip_range(int score)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => ScoreValue.From(score));
    }

    [Test]
    public void ScoreComponent_requires_plain_english_explanation()
    {
        Assert.Throws<ArgumentException>(() =>
            new ScoreComponent(ScoreCategory.Link, ScoreValue.From(42), ""));
    }

    [Test]
    public void CalculateFinalScore_uses_weighted_average()
    {
        var result = HipScoringModel.CalculateFinalScore([
            new WeightedScore(new ScoreComponent(ScoreCategory.Domain, ScoreValue.From(90), "The domain has a strong history."), 2m),
            new WeightedScore(new ScoreComponent(ScoreCategory.Link, ScoreValue.From(30), "The link redirects through a suspicious shortener."), 1m)
        ]);

        Assert.That(result.FinalScore.Score.Value, Is.EqualTo(70));
        Assert.That(result.FinalScore.TrustLevel, Is.EqualTo(TrustLevel.ProbablySafe));
        Assert.That(result.FinalScore.Explanation, Does.Contain("weakest signal is Link"));
    }

    [Test]
    public void CalculateFinalScore_does_not_allow_missing_component_scores()
    {
        Assert.Throws<ArgumentException>(() => HipScoringModel.CalculateFinalScore([]));
    }
}
