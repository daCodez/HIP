using HIP.Infrastructure.Certificates;

namespace HIP.Tests.Certificates;

/// <summary>Verifies HIP uses its embedded Public Suffix List without request-time network access.</summary>
public sealed class PublicSuffixListResolverTests
{
    [TestCase("www.example.com", "example.com")]
    [TestCase("shop.example.co.uk", "example.co.uk")]
    [TestCase("www.city.kawasaki.jp", "city.kawasaki.jp")]
    public void Resolver_returns_the_registrable_domain(string domain, string expected)
    {
        var resolver = new PublicSuffixListResolver();

        Assert.That(resolver.RegistrableDomain(domain), Is.EqualTo(expected));
    }

    [TestCase("com")]
    [TestCase("co.uk")]
    [TestCase("example.invalid")]
    public void Resolver_rejects_public_suffixes_and_unknown_suffixes(string domain)
    {
        var resolver = new PublicSuffixListResolver();

        Assert.That(resolver.RegistrableDomain(domain), Is.Null);
    }
}
