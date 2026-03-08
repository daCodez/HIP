using HIP.Admin.Models;

namespace HIP.Admin.Navigation;

public sealed record AdminRouteEntry(
    string Key,
    string Title,
    string Path,
    string? Icon = null,
    bool Reserved = false,
    string? FeatureFlag = null,
    string Group = "Primary",
    IReadOnlyCollection<AdminRole>? RequiredRoles = null);

public static class AdminRoutes
{
    public static readonly IReadOnlyList<AdminRouteEntry> All =
    [
        new("overview", "Dashboard", "/", "fa fa-home", false, null, "Primary"),
        new("alerts", "Alerts & Incidents", "/alerts", "fa fa-bell", false, null, "Primary"),
        new("audit", "Audit Logs", "/audit-logs", "fa fa-file-text-o", false, null, "Primary"),
        new("policies", "Policy Management", "/policy-rules", "fa fa-shield", false, null, "Primary"),

        new("devices", "Devices", "/users-devices", "fa fa-laptop", true, "devices", "Reserved", [AdminRole.Admin, AdminRole.Support]),
        new("simulator", "Simulator", "/simulator", "fa fa-flask", true, "simulator", "Reserved", [AdminRole.Admin, AdminRole.Support]),
        new("protocol-health", "Protocol Health", "/system-health", "fa fa-heartbeat", true, "protocol-health", "Reserved"),
        new("settings", "Settings", "/admin-settings", "fa fa-cog", true, "settings", "Reserved", [AdminRole.Admin])
    ];

    public static AdminRouteEntry? FindByPath(string absolutePath)
    {
        var normalized = NormalizePath(absolutePath);
        return All.FirstOrDefault(route => NormalizePath(route.Path).Equals(normalized, StringComparison.OrdinalIgnoreCase));
    }

    public static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return "/";
        }

        var normalized = path.Trim();
        if (!normalized.StartsWith('/'))
        {
            normalized = "/" + normalized;
        }

        return normalized.TrimEnd('/') is { Length: > 0 } value ? value : "/";
    }
}
