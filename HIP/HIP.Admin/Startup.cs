using HIP.Admin.Services;
using Microsoft.AspNetCore.HttpOverrides;

namespace HIP.Admin;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddRazorPages();
        services.AddServerSideBlazor();

        services.AddHttpContextAccessor();
        services.AddHttpClient<HipAdminApiClient>(client =>
        {
            var baseUrl = Configuration["HipAdmin:ApiBaseUrl"];
            if (string.IsNullOrWhiteSpace(baseUrl))
            {
                // Default to local API service in this HIP deployment.
                baseUrl = "http://127.0.0.1:44985/";
            }

            client.BaseAddress = new Uri(baseUrl);
        });

        services.AddScoped<ThemeService>();
        services.AddScoped<AdminContextService>();
        services.AddScoped<ActionLogService>();
        services.AddScoped<ToastService>();
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        app.UseForwardedHeaders(new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
        });

        app.UseStaticFiles();
        app.UseRouting();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapBlazorHub();
            endpoints.MapFallbackToPage("/_Host");
        });
    }
}
