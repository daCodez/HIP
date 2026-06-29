using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence;

/// <summary>
/// Classifies provider-specific database errors without forcing HIP runtime projects to reference every provider package.
/// </summary>
internal static class RelationalExceptionClassifier
{
    /// <summary>
    /// Detects PostgreSQL duplicate-key insert races so concurrent writes can be treated as idempotent.
    /// </summary>
    /// <param name="exception">EF Core update exception raised while saving a record.</param>
    /// <returns>True when the inner provider error represents a duplicate primary key or unique constraint violation.</returns>
    public static bool IsDuplicateKeyViolation(DbUpdateException exception) =>
        exception.InnerException switch
        {
            Npgsql.PostgresException postgresException => postgresException.SqlState == "23505",
            _ => false
        };

    /// <summary>
    /// Detects missing table errors so optional legacy fallback reads can degrade to an empty result.
    /// </summary>
    /// <param name="exception">Database exception raised while reading optional fallback data.</param>
    /// <returns>True when the provider reports that the requested relation or table does not exist.</returns>
    public static bool IsMissingRelation(Exception exception) =>
        exception switch
        {
            Npgsql.PostgresException postgresException => postgresException.SqlState == "42P01",
            { InnerException: { } innerException } when IsMissingRelation(innerException) => true,
            _ => false
        };
}
