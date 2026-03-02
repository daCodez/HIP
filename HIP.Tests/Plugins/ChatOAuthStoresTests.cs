using HIP.ApiService.Infrastructure.Plugins;
using NUnit.Framework;

namespace HIP.Tests.Plugins;

public sealed class ChatOAuthStoresTests
{
    [Test]
    public void StateStore_CreateThenConsume_WorksOnce()
    {
        var store = new ChatOAuthStateStore();
        var state = store.Create();

        Assert.That(state, Is.Not.Empty);
        Assert.That(store.Consume(state), Is.True);
        Assert.That(store.Consume(state), Is.False);
    }

    [Test]
    public void TokenStore_SetThenGet_ReturnsValue()
    {
        var store = new ChatOAuthTokenStore();
        var expires = DateTimeOffset.UtcNow.AddMinutes(30);

        store.Set("token-123", expires);
        var (token, expiry) = store.Get();

        Assert.That(token, Is.EqualTo("token-123"));
        Assert.That(expiry, Is.EqualTo(expires));
    }
}
