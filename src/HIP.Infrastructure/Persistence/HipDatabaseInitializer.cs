using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence;

/// <summary>
/// Initializes HIP's database without silently creating production schema.
/// </summary>
public static class HipDatabaseInitializer
{
    /// <summary>
    /// Creates a local development database or applies migrations when running outside Development.
    /// </summary>
    /// <param name="services">Application service provider.</param>
    /// <param name="isLocalDevelopment">Whether local Development schema creation is allowed.</param>
    /// <param name="cancellationToken">Token used to cancel initialization.</param>
    /// <exception cref="InvalidOperationException">Thrown outside Development when no EF migrations are configured.</exception>
    public static async Task EnsureCreatedAsync(IServiceProvider services, bool isLocalDevelopment = true, CancellationToken cancellationToken = default)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<HipDbContext>();
        if (isLocalDevelopment)
        {
            await dbContext.Database.EnsureCreatedAsync(cancellationToken);
            return;
        }

        var migrations = dbContext.Database.GetMigrations();
        if (!migrations.Any())
        {
            throw new InvalidOperationException("HIP database migrations are required outside local Development; refusing EnsureCreated.");
        }

        await dbContext.Database.MigrateAsync(cancellationToken);
    }
}
