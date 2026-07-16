using System.Net;
using HIP.Application.Security;
using HIP.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests;

/// <summary>
/// Creates HIP Web/API test hosts with deterministic local-only infrastructure.
/// </summary>
/// <remarks>
/// Production HIP hosts intentionally require PostgreSQL. Route tests need the same application startup path without
/// depending on a developer's local containers, so this factory supplies a placeholder PostgreSQL connection string for
/// startup validation and then replaces EF Core with an isolated in-memory test database before the host runs.
/// </remarks>
/// <typeparam name="TProgram">The ASP.NET Core entry point under test.</typeparam>
public sealed class HipWebApplicationFactory<TProgram> : WebApplicationFactory<TProgram>
    where TProgram : class
{
    public const string TestAdminEmail = "owner@hip.test";
    public const string TestAdminPassword = "test-password-only";

    private readonly string databaseName = $"hip-tests-{Guid.NewGuid():N}";
    private readonly IPAddress remoteIpAddress;

    public HipWebApplicationFactory(IPAddress? remoteIpAddress = null)
    {
        this.remoteIpAddress = remoteIpAddress ?? IPAddress.Loopback;
    }

    /// <summary>
    /// Configures a test host that keeps runtime safety checks active while avoiding local PostgreSQL requirements.
    /// </summary>
    /// <param name="builder">The web host builder used by WebApplicationFactory.</param>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        var passwordHasher = new PasswordHasher<string>();
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration((_, configurationBuilder) =>
        {
            configurationBuilder.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:HipDatabase"] = "Host=localhost;Port=5432;Database=hip_tests;Username=hip;Password=hip",
                ["HipInfrastructure:DatabaseProvider"] = "PostgreSQL",
                ["HipSecurity:RecordEncryptionKey"] = "hip-test-record-key-32bytes-local",
                ["HipSecurity:PrivacyHashingKey"] = "hip-test-privacy-key-32bytes-local",
                ["HipSecurity:ClientWriteCorsOrigins:0"] = "http://localhost",
                ["HipSecurity:ClientWriteCorsOrigins:1"] = "https://localhost",
                ["HipAdminLogin:Email"] = TestAdminEmail,
                ["HipAdminLogin:PasswordHash"] = passwordHasher.HashPassword(TestAdminEmail, TestAdminPassword)
            });
        });
        builder.ConfigureServices(services =>
        {
            services.AddSingleton<IStartupFilter>(new RemoteIpAddressStartupFilter(remoteIpAddress));
            services.RemoveAll<IDbContextOptionsConfiguration<HipDbContext>>();
            services.RemoveAll<DbContextOptions<HipDbContext>>();
            services.RemoveAll<DbContextOptions>();
            services.RemoveAll<HipDbContext>();
            services.AddDbContext<HipDbContext>(options => options.UseInMemoryDatabase(databaseName));
        });
    }

    private sealed class RemoteIpAddressStartupFilter(IPAddress remoteIpAddress) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => application =>
        {
            application.Use((context, nextRequest) =>
            {
                context.Connection.RemoteIpAddress = remoteIpAddress;
                return nextRequest();
            });
            next(application);
        };
    }
}
