using HIP.Sdk;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Sdk.Tests;

public sealed class ServiceCollectionExtensionsTests
{
    [Test]
    public void AddHipSdkClient_RegistersClient()
    {
        var services = new ServiceCollection();
        services.AddHipSdkClient(o => o.BaseUrl = "http://127.0.0.1:5101");

        using var provider = services.BuildServiceProvider();
        var client = provider.GetService<IHipSdkClient>();

        Assert.That(client, Is.Not.Null);
    }
}
