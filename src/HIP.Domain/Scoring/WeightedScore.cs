namespace HIP.Domain.Scoring;

public sealed record WeightedScore
{
    public WeightedScore(ScoreComponent component, decimal weight)
    {
        if (weight <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(weight), weight, "Score weights must be greater than zero.");
        }

        Component = component ?? throw new ArgumentNullException(nameof(component));
        Weight = weight;
    }

    public ScoreComponent Component { get; }

    public decimal Weight { get; }
}
