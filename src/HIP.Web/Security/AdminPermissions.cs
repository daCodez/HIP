namespace HIP.Web.Security;

public static class AdminPermissions
{
    public const string RulesView = "Rules.View";
    public const string RulesEdit = "Rules.Edit";
    public const string RulesSimulate = "Rules.Simulate";
    public const string ReputationView = "Reputation.View";
    public const string ReputationOverrideRequest = "Reputation.OverrideRequest";
    public const string ReviewView = "Review.View";
    public const string ReviewDecide = "Review.Decide";
    public const string AppealsView = "Appeals.View";
    public const string AppealsDecide = "Appeals.Decide";
    public const string LicensesView = "Licenses.View";
    public const string LicensesManage = "Licenses.Manage";
    public const string AuditView = "Audit.View";
    public const string AdminsManage = "Admins.Manage";
    public const string SystemManage = "System.Manage";
}

public sealed record AdminRoleDefinition(
    string Role,
    string Description,
    IReadOnlyCollection<string> Permissions);

public static class AdminRoleCatalog
{
    public static readonly IReadOnlyCollection<AdminRoleDefinition> Roles =
    [
        new(AdminRoles.Owner, "Full control, admins, system settings, major overrides, and export/delete authority.", AllPermissions()),
        new(AdminRoles.Admin, "Manage rules, reviews, licenses, reputation views, appeals, and domains.", [
            AdminPermissions.RulesView,
            AdminPermissions.RulesEdit,
            AdminPermissions.RulesSimulate,
            AdminPermissions.ReputationView,
            AdminPermissions.ReputationOverrideRequest,
            AdminPermissions.ReviewView,
            AdminPermissions.ReviewDecide,
            AdminPermissions.AppealsView,
            AdminPermissions.AppealsDecide,
            AdminPermissions.LicensesView,
            AdminPermissions.LicensesManage,
            AdminPermissions.AuditView
        ]),
        new(AdminRoles.Moderator, "Review reports, handle appeals, mark false positives, and suggest reputation changes.", [
            AdminPermissions.ReviewView,
            AdminPermissions.ReviewDecide,
            AdminPermissions.AppealsView,
            AdminPermissions.AppealsDecide,
            AdminPermissions.ReputationView
        ]),
        new(AdminRoles.Support, "Look up license status, reset setup codes, help activation, and escalate issues.", [
            AdminPermissions.LicensesView,
            AdminPermissions.LicensesManage,
            AdminPermissions.ReviewView
        ]),
        new(AdminRoles.ReadOnly, "View dashboards, reports, reputation, and audit logs only.", [
            AdminPermissions.RulesView,
            AdminPermissions.ReputationView,
            AdminPermissions.ReviewView,
            AdminPermissions.AppealsView,
            AdminPermissions.LicensesView,
            AdminPermissions.AuditView
        ])
    ];

    public static bool HasPermission(string role, string permission) =>
        Roles.SingleOrDefault(item => string.Equals(item.Role, role, StringComparison.OrdinalIgnoreCase))
            ?.Permissions.Contains(permission, StringComparer.OrdinalIgnoreCase) == true;

    private static IReadOnlyCollection<string> AllPermissions() =>
    [
        AdminPermissions.RulesView,
        AdminPermissions.RulesEdit,
        AdminPermissions.RulesSimulate,
        AdminPermissions.ReputationView,
        AdminPermissions.ReputationOverrideRequest,
        AdminPermissions.ReviewView,
        AdminPermissions.ReviewDecide,
        AdminPermissions.AppealsView,
        AdminPermissions.AppealsDecide,
        AdminPermissions.LicensesView,
        AdminPermissions.LicensesManage,
        AdminPermissions.AuditView,
        AdminPermissions.AdminsManage,
        AdminPermissions.SystemManage
    ];
}
