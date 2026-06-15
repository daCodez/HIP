using System.Reflection;

namespace HIP.Web;

/// <summary>
/// Provides the HIP Web build identity that is safe to display in local and admin UI.
/// </summary>
public static class HipWebBuildInfo
{
    /// <summary>
    /// Gets the running HIP Web version from assembly metadata so UI labels do not duplicate version strings.
    /// </summary>
    public static string Version { get; } =
        typeof(HipWebBuildInfo).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion
        ?? typeof(HipWebBuildInfo).Assembly.GetName().Version?.ToString()
        ?? "dev";

    /// <summary>
    /// Gets the admin dashboard version label used to confirm which web build is running.
    /// </summary>
    public static string DashboardDisplayVersion => $"HIP Dashboard v{Version}";
}
