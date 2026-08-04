namespace HIP.Web.Security;

public static class AdminPolicies
{
    public const string CanViewOwnAdminAccess = nameof(CanViewOwnAdminAccess);
    public const string CanViewAdminUsers = nameof(CanViewAdminUsers);
    public const string CanManageAdmins = nameof(CanManageAdmins);
    public const string CanManageRules = nameof(CanManageRules);
    public const string CanReviewReports = nameof(CanReviewReports);
    public const string CanViewReviews = nameof(CanViewReviews);
    public const string CanDecideReviews = nameof(CanDecideReviews);
    public const string CanViewAppeals = nameof(CanViewAppeals);
    public const string CanDecideAppeals = nameof(CanDecideAppeals);
    public const string CanApproveOverrides = nameof(CanApproveOverrides);
    public const string CanManageReputation = nameof(CanManageReputation);
    public const string CanViewAuditLogs = nameof(CanViewAuditLogs);
    public const string CanManageLicenses = nameof(CanManageLicenses);
    public const string CanViewLicenses = nameof(CanViewLicenses);
    public const string CanSupportLicenses = nameof(CanSupportLicenses);
    public const string CanAdministerLicenses = nameof(CanAdministerLicenses);
    public const string CanManagePlatforms = nameof(CanManagePlatforms);
    public const string CanViewServiceClients = nameof(CanViewServiceClients);
    public const string CanManageServiceClients = nameof(CanManageServiceClients);
    public const string CanViewAdminDashboard = nameof(CanViewAdminDashboard);
    public const string CanManageDomainVerifications = nameof(CanManageDomainVerifications);
    public const string CanManageAuthoritativeDns = nameof(CanManageAuthoritativeDns);
    public const string CanRevokeDomainVerifications = nameof(CanRevokeDomainVerifications);
    public const string CanRequestPrivilegedStepUp = nameof(CanRequestPrivilegedStepUp);
    public const string RecentPrivilegedAuthentication = nameof(RecentPrivilegedAuthentication);
}
