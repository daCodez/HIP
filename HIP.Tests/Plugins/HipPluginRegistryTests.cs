using HIP.ApiService.Infrastructure.Plugins;
using HIP.Plugins.Abstractions.Contracts;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NUnit.Framework;

namespace HIP.Tests.Plugins;

public sealed class HipPluginRegistryTests
{
    [Test]
    public void Register_DuplicateId_Throws()
    {
        var registry = new HipPluginRegistry();
        var plugin = new FakePlugin("test.plugin");

        registry.Register(plugin);

        Assert.That(() => registry.Register(new FakePlugin("test.plugin")), Throws.TypeOf<InvalidOperationException>());
    }

    [Test]
    public void ConfigureServices_InvokesRegisteredPlugin()
    {
        var registry = new HipPluginRegistry();
        var plugin = new FakePlugin("test.plugin");
        var services = new ServiceCollection();
        var config = new ConfigurationBuilder().Build();
        var environment = new FakeHostEnvironment();

        registry.Register(plugin);
        registry.ConfigureServices(services, config, environment);

        Assert.That(plugin.ConfigureServicesCalled, Is.True);
    }

    private sealed class FakePlugin(string id) : IHipPlugin
    {
        public bool ConfigureServicesCalled { get; private set; }

        public HipPluginManifest Manifest { get; } = new(id, "0.1.0", ["test"]);

        public void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
            => ConfigureServicesCalled = true;

        public void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment)
        {
        }
    }

    private sealed class FakeHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "HIP.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }
}
