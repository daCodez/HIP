using HIP.ApiService;
using HIP.Communication.Domain;
using HIP.Communication.Domain.Identity;
using HIP.Reputation.Domain;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class DomainAndOptionsTests
{
    [Test]
    public void DomainRecords_AndOptions_CanBeConstructed()
    {
        var signed = new SignedMessage(Guid.NewGuid(), "a", "b", "hello", "sig");
        var identity = new Identity("id-1", "pkref:1");
        var score = new ReputationScore("id-1", ReputationConstants.BaseScore, DateTimeOffset.UtcNow);
        var options = new CryptoProviderOptions { Provider = "Placeholder", PublicKeyStorePath = "/tmp/keys" };

        Assert.That(signed.Body, Is.EqualTo("hello"));
        Assert.That(identity.PublicKeyRef, Is.EqualTo("pkref:1"));
        Assert.That(score.Score, Is.EqualTo(50));
        Assert.That(options.Provider, Is.EqualTo("Placeholder"));
    }
}
