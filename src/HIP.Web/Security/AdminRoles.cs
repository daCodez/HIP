using HIP.Application.Administration;

namespace HIP.Web.Security;

public static class AdminRoles
{
    public const string Owner = AdminAccessRoleNames.Owner;
    public const string Admin = AdminAccessRoleNames.Admin;
    public const string Moderator = AdminAccessRoleNames.Moderator;
    public const string Support = AdminAccessRoleNames.Support;
    public const string ReadOnly = AdminAccessRoleNames.ReadOnly;

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        Owner,
        Admin,
        Moderator,
        Support,
        ReadOnly
    };
}
