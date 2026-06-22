using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence;

/// <summary>
/// Classifies provider-specific database errors without forcing HIP runtime projects to reference every provider package.
/// </summary>
internal static class RelationalExceptionClassifier
{
    /// <summary>
    /// Detects duplicate-key insert races from the relational providers HIP currently exercises.
    /// PostgreSQL is the production provider; SQLite is recognized by name only so test projects can still use it
    /// without keeping the SQLite native dependency in HIP.Infrastructure.
    /// </summary>
    /// <param name="exception">EF Core update exception raised while saving a record.</param>
    /// <returns>True when the inner provider error represents a duplicate primary key or unique constraint violation.</returns>
    public static bool IsDuplicateKeyViolation(DbUpdateException exception) =>
        exception.InnerException switch
        {
            Npgsql.PostgresException postgresException => postgresException.SqlState == "23505",
            { } innerException when IsSqliteUniqueConstraint(innerException) => true,
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
            { } candidate when IsSqliteMissingTable(candidate) => true,
            _ => false
        };

    /// <summary>
    /// Recognizes SQLite unique constraint failures through reflection so runtime code stays free of SQLite references.
    /// </summary>
    /// <param name="exception">Provider exception from EF Core.</param>
    /// <returns>True when the exception is SQLite error code 19, which means a constraint failed.</returns>
    private static bool IsSqliteUniqueConstraint(Exception exception)
    {
        if (!string.Equals(exception.GetType().FullName, "Microsoft.Data.Sqlite.SqliteException", StringComparison.Ordinal))
        {
            return false;
        }

        var property = exception.GetType().GetProperty("SqliteErrorCode");
        return property?.GetValue(exception) is int errorCode && errorCode == 19;
    }

    /// <summary>
    /// Recognizes SQLite missing-table failures through reflection and message text so runtime code stays provider-light.
    /// </summary>
    /// <param name="exception">Provider exception from EF Core.</param>
    /// <returns>True when SQLite reports that the requested table is absent.</returns>
    private static bool IsSqliteMissingTable(Exception exception)
    {
        if (!string.Equals(exception.GetType().FullName, "Microsoft.Data.Sqlite.SqliteException", StringComparison.Ordinal))
        {
            return false;
        }

        var property = exception.GetType().GetProperty("SqliteErrorCode");
        return property?.GetValue(exception) is int errorCode
            && errorCode == 1
            && exception.Message.Contains("no such table", StringComparison.OrdinalIgnoreCase);
    }
}
