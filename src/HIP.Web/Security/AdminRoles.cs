namespace HIP.Web.Security;

public static class AdminRoles
{
    public const string Owner = nameof(Owner);
    public const string Admin = nameof(Admin);
    public const string Moderator = nameof(Moderator);
    public const string Support = nameof(Support);
    public const string ReadOnly = nameof(ReadOnly);

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        Owner,
        Admin,
        Moderator,
        Support,
        ReadOnly
    };
}
