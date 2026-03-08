namespace HIP.Admin.Navigation;

public sealed class BreadcrumbService
{
    public IReadOnlyList<BreadcrumbItem> Build(string absolutePath)
    {
        var normalized = AdminRoutes.NormalizePath(absolutePath);
        var direct = AdminRoutes.FindByPath(normalized);
        if (direct is not null)
        {
            return
            [
                new("Admin", "/"),
                new(direct.Title, direct.Path)
            ];
        }

        var segments = normalized.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        var breadcrumbs = new List<BreadcrumbItem> { new("Admin", "/") };

        var path = string.Empty;
        foreach (var segment in segments)
        {
            path += "/" + segment;
            var title = string.Join(' ', segment.Split('-', StringSplitOptions.RemoveEmptyEntries)
                .Select(x => char.ToUpperInvariant(x[0]) + x[1..]));
            breadcrumbs.Add(new BreadcrumbItem(title, path));
        }

        return breadcrumbs;
    }
}

public sealed record BreadcrumbItem(string Label, string Href);
