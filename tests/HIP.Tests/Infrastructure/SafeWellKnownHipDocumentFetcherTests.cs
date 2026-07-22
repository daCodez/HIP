using System.Net;
using HIP.Infrastructure.Identity;

namespace HIP.Tests.Infrastructure;

/// <summary>Locks the network-address boundary used by well-known verification.</summary>
public sealed class SafeWellKnownHipDocumentFetcherTests
{
    [TestCase("127.0.0.1")]
    [TestCase("10.0.0.1")]
    [TestCase("100.64.0.1")]
    [TestCase("169.254.1.1")]
    [TestCase("172.16.0.1")]
    [TestCase("192.168.0.1")]
    [TestCase("224.0.0.1")]
    [TestCase("::1")]
    [TestCase("fe80::1")]
    [TestCase("fc00::1")]
    [TestCase("::ffff:127.0.0.1")]
    public void Private_or_special_addresses_are_rejected(string value)
    {
        Assert.That(SafeWellKnownHipDocumentFetcher.IsPublicAddress(IPAddress.Parse(value)), Is.False);
    }

    [TestCase("8.8.8.8")]
    [TestCase("1.1.1.1")]
    [TestCase("2606:4700:4700::1111")]
    public void Public_unicast_addresses_are_allowed(string value)
    {
        Assert.That(SafeWellKnownHipDocumentFetcher.IsPublicAddress(IPAddress.Parse(value)), Is.True);
    }

    [Test]
    public void Fetch_limits_are_bounded()
    {
        Assert.Multiple(() =>
        {
            Assert.That(
                () => new WellKnownHipDocumentFetchOptions(TimeSpan.FromMilliseconds(500), 4096).Validate(),
                Throws.TypeOf<ArgumentOutOfRangeException>());
            Assert.That(
                () => new WellKnownHipDocumentFetchOptions(TimeSpan.FromSeconds(5), 512).Validate(),
                Throws.TypeOf<ArgumentOutOfRangeException>());
            Assert.That(
                () => new WellKnownHipDocumentFetchOptions(TimeSpan.FromSeconds(5), 4096).Validate(),
                Throws.Nothing);
        });
    }
}
