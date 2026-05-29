namespace HIP.Web.Security;

public static class AdminPolicies
{
    public const string CanManageRules = nameof(CanManageRules);
    public const string CanReviewReports = nameof(CanReviewReports);
    public const string CanApproveOverrides = nameof(CanApproveOverrides);
    public const string CanViewAuditLogs = nameof(CanViewAuditLogs);
    public const string CanManageLicenses = nameof(CanManageLicenses);
    public const string CanViewAdminDashboard = nameof(CanViewAdminDashboard);
}
