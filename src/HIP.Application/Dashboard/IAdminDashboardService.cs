namespace HIP.Application.Dashboard;

public interface IAdminDashboardService
{
    Task<AdminDashboardSummary> GetSummaryAsync(CancellationToken cancellationToken);
}
