using System.Reflection;
using System.Runtime.Loader;
using HIP.Plugins.Abstractions.Contracts;

namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// Discovers HIP plugins from loaded assemblies and optional plugin directories.
/// </summary>
public static class HipPluginDiscovery
{
    /// <summary>
    /// Discovers plugin instances.
    /// </summary>
    public static IReadOnlyList<IHipPlugin> Discover(string? pluginDirectory)
    {
        LoadExternalAssemblies(pluginDirectory);

        var plugins = new List<IHipPlugin>();
        foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
        {
            Type[] types;
            try
            {
                types = assembly.GetTypes();
            }
            catch
            {
                continue;
            }

            foreach (var type in types)
            {
                if (type.IsAbstract || type.IsInterface)
                {
                    continue;
                }

                if (!typeof(IHipPlugin).IsAssignableFrom(type))
                {
                    continue;
                }

                if (type.GetConstructor(Type.EmptyTypes) is null)
                {
                    continue;
                }

                if (Activator.CreateInstance(type) is IHipPlugin plugin)
                {
                    plugins.Add(plugin);
                }
            }
        }

        return plugins;
    }

    private static void LoadExternalAssemblies(string? pluginDirectory)
    {
        if (string.IsNullOrWhiteSpace(pluginDirectory) || !Directory.Exists(pluginDirectory))
        {
            return;
        }

        foreach (var dll in Directory.EnumerateFiles(pluginDirectory, "*.dll", SearchOption.TopDirectoryOnly))
        {
            try
            {
                var fullPath = Path.GetFullPath(dll);
                AssemblyLoadContext.Default.LoadFromAssemblyPath(fullPath);
            }
            catch
            {
                // Ignore invalid plugin binaries; startup should stay resilient.
            }
        }
    }
}
