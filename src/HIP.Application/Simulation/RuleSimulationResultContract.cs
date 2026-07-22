namespace HIP.Application.Simulation;

/// <summary>Validates durable simulation summaries and excludes sensitive fixture fields.</summary>
public static class RuleSimulationResultContract
{
    private static readonly string[] ForbiddenFieldFragments =
        ["password", "cookie", "token", "formvalue", "pagetext", "messagebody", "chatlog", "emailcontent"];

    public static void ValidateInputCases(IReadOnlyCollection<RuleSimulationTestCase> cases)
    {
        ArgumentNullException.ThrowIfNull(cases);
        if (cases.Count is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(nameof(cases));
        }
        foreach (var testCase in cases)
        {
            ArgumentNullException.ThrowIfNull(testCase);
            SafeMetadataLabel(testCase.Name, nameof(cases), 160);
            ArgumentNullException.ThrowIfNull(testCase.InputFacts);
            if (testCase.InputFacts.Values.Count > 64)
            {
                throw new ArgumentOutOfRangeException(nameof(cases));
            }
            foreach (var key in testCase.InputFacts.Values.Keys)
            {
                SafeFieldKey(key, nameof(cases));
            }
        }
    }

    public static void Validate(RuleSimulationResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        SafeText(result.SimulationId, nameof(result), 128);
        SafeText(result.RuleId, nameof(result), 160);
        SafeText(result.FixtureSetId, nameof(result), 80);
        if (!result.SimulationId.StartsWith("simulation:", StringComparison.Ordinal) ||
            !result.FixtureSetId.StartsWith("fixtures:", StringComparison.Ordinal) ||
            result.RuleVersion < 1 || result.Version != 1 ||
            result.TotalTestCases is < 1 or > 500 ||
            result.PassedCount < 0 || result.FailedCount < 0 ||
            result.PassedCount + result.FailedCount != result.TotalTestCases ||
            result.Passed != (result.FailedCount == 0) ||
            !Rate(result.DetectionRate) || !Rate(result.FalsePositiveRisk) ||
            !Rate(result.FalseNegativeRisk) || !Rate(result.ConfidenceScore) ||
            result.StartedAtUtc == default || result.CompletedAtUtc < result.StartedAtUtc)
        {
            throw new ArgumentException("Simulation summary is internally inconsistent.", nameof(result));
        }

        ArgumentNullException.ThrowIfNull(result.CaseResults);
        ArgumentNullException.ThrowIfNull(result.FailedCases);
        ArgumentNullException.ThrowIfNull(result.MatchedRules);
        ArgumentNullException.ThrowIfNull(result.RollbackPlan);
        if (result.CaseResults.Count != result.TotalTestCases || result.FailedCases.Count != result.FailedCount)
        {
            throw new ArgumentException("Simulation case counts do not match the summary.", nameof(result));
        }
        if (result.CaseResults.Select(item => item.Name).Distinct(StringComparer.Ordinal).Count() != result.TotalTestCases ||
            !result.FailedCases.Select(item => item.Name).OrderBy(value => value, StringComparer.Ordinal).SequenceEqual(
                result.CaseResults.Where(item => !item.Passed).Select(item => item.Name).OrderBy(value => value, StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw new ArgumentException("Simulation case identities or failed-case projection are inconsistent.", nameof(result));
        }
        foreach (var item in result.CaseResults)
        {
            SafeMetadataLabel(item.Name, nameof(result), 160);
            if (item.FailureReason is not null)
            {
                SafeText(item.FailureReason, nameof(result), 1_000);
            }
            var keys = item.InputFactKeys ?? [];
            if (keys.Count > 64 || keys.Distinct(StringComparer.Ordinal).Count() != keys.Count)
            {
                throw new ArgumentException("Simulation input field keys must be bounded and unique.", nameof(result));
            }
            foreach (var key in keys)
            {
                SafeFieldKey(key, nameof(result));
            }
        }
        foreach (var matchedRule in result.MatchedRules)
        {
            SafeText(matchedRule, nameof(result), 160);
        }
        if (!string.Equals(result.RollbackPlan.AffectedRuleId, result.RuleId, StringComparison.Ordinal) ||
            result.RollbackPlan.CreatedAtUtc < result.StartedAtUtc ||
            result.RollbackPlan.CreatedAtUtc > result.CompletedAtUtc)
        {
            throw new ArgumentException("Simulation rollback metadata is inconsistent.", nameof(result));
        }
        foreach (var value in new[]
                 {
                     result.SpeedImpact, result.PrivacyImpact, result.RecommendedAction,
                     result.RecommendedMode, result.ImpactClassification, result.RollbackPlan.RollbackReason
                 })
        {
            SafeText(value, nameof(result), 1_000);
        }
    }

    private static bool Rate(decimal value) => value is >= 0m and <= 1m;

    private static void SafeFieldKey(string value, string parameterName)
    {
        SafeText(value, parameterName, 128);
        var compact = value.Replace(".", string.Empty, StringComparison.Ordinal)
            .Replace("_", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal);
        if (ForbiddenFieldFragments.Any(fragment => compact.Contains(fragment, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException("Simulation fixtures cannot include private-content fields.", parameterName);
        }
    }

    private static void SafeMetadataLabel(string value, string parameterName, int maximumLength)
    {
        SafeText(value, parameterName, maximumLength);
        var compact = value.Replace(" ", string.Empty, StringComparison.Ordinal)
            .Replace(".", string.Empty, StringComparison.Ordinal)
            .Replace("_", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal);
        if (ForbiddenFieldFragments.Any(fragment => compact.Contains(fragment, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException("Simulation labels cannot contain private-content field names.", parameterName);
        }
    }

    private static void SafeText(string value, string parameterName, int maximumLength)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > maximumLength || value.Any(char.IsControl))
        {
            throw new ArgumentException("Simulation metadata must be bounded plain text.", parameterName);
        }
    }
}
