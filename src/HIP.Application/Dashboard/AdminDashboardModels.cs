using HIP.Domain.Risk;

namespace HIP.Application.Dashboard;

public sealed record AdminDashboardSummary(
    IReadOnlyCollection<AdminDashboardCard> Cards,
    IReadOnlyCollection<AdminRecentActivityItem> RecentActivity,
    string ApiHealth,
    DateTimeOffset GeneratedAtUtc);

public sealed record AdminDashboardCard(
    string Key,
    string Label,
    int Value,
    string Status,
    bool IsPlaceholder,
    string Description);

public sealed record AdminRecentActivityItem(
    string ActivityType,
    string TargetType,
    string TargetId,
    RiskStatus? RiskLevel,
    string Summary,
    DateTimeOffset CreatedAtUtc);
