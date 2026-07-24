using System.Globalization;
using HIP.Application.Certificates;

namespace HIP.Infrastructure.Certificates;

/// <summary>Resolves registrable domains from HIP's embedded Public Suffix List without request-time network access.</summary>
public sealed class PublicSuffixListResolver : IPublicSuffixResolver
{
    private const string ResourceName = "HIP.Infrastructure.Certificates.public_suffix_list.dat";
    private static readonly Lazy<RuleSet> Rules = new(LoadRules, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <inheritdoc />
    public string? RegistrableDomain(string canonicalDomain)
    {
        if (string.IsNullOrWhiteSpace(canonicalDomain))
        {
            return null;
        }

        var labels = canonicalDomain.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length < 2)
        {
            return null;
        }

        var rules = Rules.Value;
        var exceptionLength = LongestExactMatch(labels, rules.Exceptions);
        var publicSuffixLength = exceptionLength > 0
            ? exceptionLength - 1
            : Math.Max(
                LongestExactMatch(labels, rules.Exact),
                LongestWildcardMatch(labels, rules.Wildcards));

        return publicSuffixLength < 1 || labels.Length <= publicSuffixLength
            ? null
            : string.Join('.', labels[(labels.Length - publicSuffixLength - 1)..]);
    }

    private static int LongestExactMatch(string[] labels, IReadOnlySet<string> rules)
    {
        for (var index = 0; index < labels.Length; index++)
        {
            if (rules.Contains(string.Join('.', labels[index..])))
            {
                return labels.Length - index;
            }
        }

        return 0;
    }

    private static int LongestWildcardMatch(string[] labels, IReadOnlySet<string> rules)
    {
        for (var index = 1; index < labels.Length; index++)
        {
            if (rules.Contains(string.Join('.', labels[index..])))
            {
                return labels.Length - index + 1;
            }
        }

        return 0;
    }

    private static RuleSet LoadRules()
    {
        using var stream = typeof(PublicSuffixListResolver).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException("The HIP Public Suffix List resource is unavailable.");
        using var reader = new StreamReader(stream);
        var exact = new HashSet<string>(StringComparer.Ordinal);
        var wildcards = new HashSet<string>(StringComparer.Ordinal);
        var exceptions = new HashSet<string>(StringComparer.Ordinal);
        var idn = new IdnMapping { UseStd3AsciiRules = true };

        while (reader.ReadLine() is { } line)
        {
            var rule = line.Trim();
            if (rule.Length == 0 || rule.StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            var target = exact;
            if (rule[0] == '!')
            {
                target = exceptions;
                rule = rule[1..];
            }
            else if (rule.StartsWith("*.", StringComparison.Ordinal))
            {
                target = wildcards;
                rule = rule[2..];
            }

            try
            {
                target.Add(idn.GetAscii(rule).ToLowerInvariant());
            }
            catch (ArgumentException exception)
            {
                throw new InvalidOperationException(
                    "The embedded HIP Public Suffix List contains an invalid rule.",
                    exception);
            }
        }

        return new RuleSet(exact, wildcards, exceptions);
    }

    private sealed record RuleSet(
        IReadOnlySet<string> Exact,
        IReadOnlySet<string> Wildcards,
        IReadOnlySet<string> Exceptions);
}
