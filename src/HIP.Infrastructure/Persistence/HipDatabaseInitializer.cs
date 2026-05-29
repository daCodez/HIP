using Microsoft.Extensions.DependencyInjection;

namespace HIP.Infrastructure.Persistence;

public static class HipDatabaseInitializer
{
    public static async Task EnsureCreatedAsync(IServiceProvider services, CancellationToken cancellationToken = default)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<HipDbContext>();
        await dbContext.Database.EnsureCreatedAsync(cancellationToken);
    }
}
