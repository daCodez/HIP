using HIP.Application.PublicLookup;

namespace HIP.Tests.PublicLookup;

/// <summary>Locks canonical IDNA handling before domains reach DNS, HTTP, or persistence boundaries.</summary>
public sealed class DomainInputValidatorTests
{
    [TestCase(" Example.COM. ", "example.com")]
    [TestCase("bücher.test", "xn--bcher-kva.test")]
    [TestCase("XN--BCHER-KVA.TEST.", "xn--bcher-kva.test")]
    public void Valid_domains_are_normalized_to_canonical_ascii(string input, string expected)
    {
        Assert.That(DomainInputValidator.ValidateAndNormalize(input), Is.EqualTo(expected));
    }

    [TestCase("single-label")]
    [TestCase("-leading.example")]
    [TestCase("trailing-.example")]
    [TestCase("under_score.example")]
    [TestCase("https://example.com")]
    [TestCase("127.0.0.1")]
    public void Non_public_or_malformed_hosts_are_rejected(string input)
    {
        Assert.That(
            () => DomainInputValidator.ValidateAndNormalize(input),
            Throws.TypeOf<ArgumentException>());
    }
}
