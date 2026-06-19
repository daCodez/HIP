namespace HIP.Web.Security;

/// <summary>
/// Lists the named admin permissions that HIP uses to keep UI and API authorization checks consistent.
/// </summary>
public static class AdminPermissions
{
    /// <summary>
    /// Allows an admin user to view rule definitions and rule simulation results.
    /// </summary>
    public const string RulesView = "Rules.View";

    /// <summary>
    /// Allows an admin user to create, edit, enable, disable, or roll back rules.
    /// </summary>
    public const string RulesEdit = "Rules.Edit";

    /// <summary>
    /// Allows an admin user to run rule simulations without changing live scoring.
    /// </summary>
    public const string RulesSimulate = "Rules.Simulate";

    /// <summary>
    /// Allows an admin user to view reputation summaries without changing reputation data.
    /// </summary>
    public const string ReputationView = "Reputation.View";

    /// <summary>
    /// Allows an admin user to request reputation overrides that still require the approval flow.
    /// </summary>
    public const string ReputationOverrideRequest = "Reputation.OverrideRequest";

    /// <summary>
    /// Allows an admin user to view privacy-safe review queue items.
    /// </summary>
    public const string ReviewView = "Review.View";

    /// <summary>
    /// Allows an admin user to make review queue decisions that can influence future scoring.
    /// </summary>
    public const string ReviewDecide = "Review.Decide";

    /// <summary>
    /// Allows an admin user to view user appeal records.
    /// </summary>
    public const string AppealsView = "Appeals.View";

    /// <summary>
    /// Allows an admin user to approve, reject, or request more information for appeals.
    /// </summary>
    public const string AppealsDecide = "Appeals.Decide";

    /// <summary>
    /// Allows an admin user to inspect license and activation status.
    /// </summary>
    public const string LicensesView = "Licenses.View";

    /// <summary>
    /// Allows an admin user to manage license support actions such as reset or revoke flows.
    /// </summary>
    public const string LicensesManage = "Licenses.Manage";

    /// <summary>
    /// Allows an admin user to view audit log entries.
    /// </summary>
    public const string AuditView = "Audit.View";

    /// <summary>
    /// Allows an owner-level user to manage admin accounts and role assignments.
    /// </summary>
    public const string AdminsManage = "Admins.Manage";

    /// <summary>
    /// Allows an owner-level user to manage system-wide HIP settings.
    /// </summary>
    public const string SystemManage = "System.Manage";
}

/// <summary>
/// Describes one admin role and the permissions granted to that role.
/// </summary>
/// <param name="Role">The stable role name used by authorization policies.</param>
/// <param name="Description">A plain-English explanation of what the role is intended to do.</param>
/// <param name="Permissions">The permission set granted to users in this role.</param>
public sealed record AdminRoleDefinition(
    string Role,
    string Description,
    IReadOnlyCollection<string> Permissions);

/// <summary>
/// Provides the built-in admin role catalog used by the local MVP admin experience.
/// </summary>
public static class AdminRoleCatalog
{
    /// <summary>
    /// Gets the built-in HIP admin roles and their permission sets.
    /// </summary>
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

    /// <summary>
    /// Checks whether the supplied role grants the supplied permission.
    /// </summary>
    /// <param name="role">The admin role name to inspect.</param>
    /// <param name="permission">The permission name to require.</param>
    /// <returns><see langword="true"/> when the role exists and grants the permission; otherwise <see langword="false"/>.</returns>
    public static bool HasPermission(string role, string permission) =>
        Roles.SingleOrDefault(item => string.Equals(item.Role, role, StringComparison.OrdinalIgnoreCase))
            ?.Permissions.Contains(permission, StringComparer.OrdinalIgnoreCase) == true;

    /// <summary>
    /// Returns every built-in permission for the Owner role.
    /// </summary>
    /// <returns>The complete permission set for unrestricted local administration.</returns>
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
