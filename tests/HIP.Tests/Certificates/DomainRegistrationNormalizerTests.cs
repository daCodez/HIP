using HIP.Application.Certificates;

namespace HIP.Tests.Certificates;

/// <summary>Specifies the public-domain boundary used before certificate enrollment is persisted.</summary>
public sealed class DomainRegistrationNormalizerTests
{
    private readonly DomainRegistrationNormalizer normalizer = new(new TestPublicSuffixResolver());

    [TestCase(" Example.COM. ", "example.com")]
    [TestCase("https://BÜCHER.de:443/path?q=private#fragment", "xn--bcher-kva.de")]
    [TestCase("shop.example.co.uk/path", "shop.example.co.uk")]
    public void Public_domain_inputs_are_reduced_to_a_canonical_ascii_host(string input, string expected)
    {
        Assert.That(normalizer.Normalize(input), Is.EqualTo(expected));
    }

    [TestCase("127.0.0.1")]
    [TestCase("[::1]")]
    [TestCase("localhost")]
    [TestCase("service.internal")]
    [TestCase("printer.local")]
    [TestCase("example.invalid")]
    [TestCase("co.uk")]
    [TestCase("https://user:password@example.com")]
    public void Non_public_or_non_registrable_inputs_are_rejected(string input)
    {
        Assert.That(
            () => normalizer.Normalize(input),
            Throws.TypeOf<ArgumentException>());
    }

    private sealed class TestPublicSuffixResolver : IPublicSuffixResolver
    {
        public string? RegistrableDomain(string canonicalDomain) =>
            canonicalDomain switch
            {
                "example.com" => "example.com",
                "xn--bcher-kva.de" => "xn--bcher-kva.de",
                "shop.example.co.uk" => "example.co.uk",
                _ => null
            };
    }
}
