using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace HIP.Infrastructure.Persistence;

/// <summary>
/// Creates the HIP database context for explicit EF Core migration commands without starting the application.
/// </summary>
public sealed class HipDbContextDesignTimeFactory : IDesignTimeDbContextFactory<HipDbContext>
{
    private const string ConnectionStringEnvironmentVariable = "HIP_DATABASE_CONNECTION_STRING";

    /// <inheritdoc />
    public HipDbContext CreateDbContext(string[] args)
    {
        _ = args;
        var connectionString = Environment.GetEnvironmentVariable(ConnectionStringEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                $"Set {ConnectionStringEnvironmentVariable} for EF migration commands. HIP does not accept migration credentials through source-controlled configuration.");
        }

        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseNpgsql(connectionString)
            .Options;
        return new HipDbContext(options);
    }
}
