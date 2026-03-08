using HIP.Admin.Models;
using HIP.Admin.Navigation;
using HIP.Admin.Services;
using HIP.Simulator.Core.Extensions;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
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
        var authOptions = new AdminAuthOptions();
        Configuration.GetSection("HipAdmin:Auth").Bind(authOptions);
        services.Configure<AdminAuthOptions>(Configuration.GetSection("HipAdmin:Auth"));

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

        if (authOptions.EnableOidc)
        {
            services
                .AddAuthentication(options =>
                {
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                })
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
                {
                    options.Authority = authOptions.Authority;
                    options.ClientId = authOptions.ClientId;
                    options.ClientSecret = authOptions.ClientSecret;
                    options.ResponseType = "code";
                    options.SaveTokens = true;
                    options.GetClaimsFromUserInfoEndpoint = true;
                    options.CallbackPath = authOptions.CallbackPath;
                    options.SignedOutCallbackPath = authOptions.SignedOutCallbackPath;
                    options.TokenValidationParameters.RoleClaimType = authOptions.RoleClaimType;

                    options.Scope.Clear();
                    foreach (var scope in authOptions.Scopes.Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        options.Scope.Add(scope);
                    }
                });

            services.AddAuthorization(options =>
            {
                if (authOptions.EnforceLogin)
                {
                    options.FallbackPolicy = options.DefaultPolicy;
                }
            });
        }

        services.AddHipSimulatorCore();

        services.AddScoped<ThemeService>();
        services.AddScoped<AdminContextService>();
        services.AddScoped<BreadcrumbService>();
        services.AddScoped<ActionLogService>();
        services.AddScoped<ToastService>();
        services.AddSingleton<SimulatorAdminService>();
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        var authOptions = new AdminAuthOptions();
        Configuration.GetSection("HipAdmin:Auth").Bind(authOptions);

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

        if (authOptions.EnableOidc)
        {
            app.UseAuthentication();
            app.UseAuthorization();
        }

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapBlazorHub();
            endpoints.MapFallbackToPage("/_Host");
        });
    }
}
