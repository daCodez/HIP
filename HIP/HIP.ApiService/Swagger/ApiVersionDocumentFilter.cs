using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace HIP.ApiService.Swagger;

internal sealed class ApiVersionDocumentFilter : IDocumentFilter
{
    public void Apply(OpenApiDocument swaggerDoc, DocumentFilterContext context)
    {
        var original = swaggerDoc.Paths.ToList();
        swaggerDoc.Paths.Clear();

        foreach (var (path, item) in original)
        {
            if (path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase) &&
                !path.StartsWith("/api/v", StringComparison.OrdinalIgnoreCase))
            {
                swaggerDoc.Paths[$"/api/v1{path[4..]}"] = item;
            }
            else
            {
                swaggerDoc.Paths[path] = item;
            }
        }
    }
}
