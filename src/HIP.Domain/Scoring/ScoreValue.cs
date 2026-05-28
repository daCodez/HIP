namespace HIP.Domain.Scoring;

public readonly record struct ScoreValue
{
    public const int Minimum = 0;
    public const int Maximum = 100;

    private ScoreValue(int value)
    {
        Value = value;
    }

    public int Value { get; }

    public static ScoreValue From(int value)
    {
        if (value is < Minimum or > Maximum)
        {
            throw new ArgumentOutOfRangeException(nameof(value), value, "HIP scores must be between 0 and 100.");
        }

        return new ScoreValue(value);
    }

    public TrustLevel ToTrustLevel() => Value switch
    {
        <= 20 => TrustLevel.Dangerous,
        <= 40 => TrustLevel.HighRisk,
        <= 60 => TrustLevel.Caution,
        <= 80 => TrustLevel.ProbablySafe,
        _ => TrustLevel.Trusted
    };

    public override string ToString() => Value.ToString();
}
