namespace HIP.Application.Dashboard;

/// <summary>
/// Provides privacy-safe admin dashboard summaries.
/// </summary>
public interface IAdminDashboardService
{
    /// <summary>
    /// Gets the dashboard summary using real stored scan data where available.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel repository reads.</param>
    /// <returns>Dashboard summary.</returns>
    Task<AdminDashboardSummary> GetSummaryAsync(CancellationToken cancellationToken);
}
