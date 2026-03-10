using HIP.Admin.Models;
using HIP.Admin.Navigation;
using HIP.Admin.Services;
using HIP.Simulator.Core.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Hosting;

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
        services.AddControllers();

        var environmentName = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? Environments.Production;
        var isDevelopment = string.Equals(environmentName, Environments.Development, StringComparison.OrdinalIgnoreCase);

        if (!isDevelopment && authOptions.EnableLocalAuth)
        {
            if (string.IsNullOrWhiteSpace(authOptions.LocalAdmin.Password) ||
                string.Equals(authOptions.LocalAdmin.Password, "change-me-now", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("HipAdmin local auth is enabled with an unsafe default/empty password outside Development. Disable local auth or set a strong password.");
            }
        }

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

        if (authOptions.EnableOidc || authOptions.EnableLocalAuth)
        {
            var authBuilder = services
                .AddAuthentication(options =>
                {
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = authOptions.EnableOidc
                        ? OpenIdConnectDefaults.AuthenticationScheme
                        : CookieAuthenticationDefaults.AuthenticationScheme;
                })
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.Cookie.HttpOnly = true;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                    options.Cookie.SameSite = SameSiteMode.Lax;
                    options.SlidingExpiration = true;
                    options.LoginPath = "/login";
                    options.AccessDeniedPath = "/login";
                    options.Events = new CookieAuthenticationEvents
                    {
                        OnRedirectToLogin = context =>
                        {
                            var returnUrl = context.Request.PathBase + context.Request.Path + context.Request.QueryString;
                            context.Response.Redirect($"/admin/login?ReturnUrl={Uri.EscapeDataString(returnUrl)}");
                            return Task.CompletedTask;
                        },
                        OnRedirectToAccessDenied = context =>
                        {
                            var returnUrl = context.Request.PathBase + context.Request.Path + context.Request.QueryString;
                            context.Response.Redirect($"/admin/login?ReturnUrl={Uri.EscapeDataString(returnUrl)}");
                            return Task.CompletedTask;
                        }
                    };
                });

            if (authOptions.EnableOidc)
            {
                authBuilder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
                {
                    options.Authority = authOptions.Authority;
                    options.ClientId = authOptions.ClientId;
                    options.ClientSecret = authOptions.ClientSecret;
                    options.ResponseType = "code";
                    options.SaveTokens = true;
                    options.GetClaimsFromUserInfoEndpoint = true;
                    options.CallbackPath = authOptions.CallbackPath;
                    options.SignedOutCallbackPath = authOptions.SignedOutCallbackPath;
                    options.TokenValidationParameters.NameClaimType = "name";
                    options.TokenValidationParameters.RoleClaimType = "app:role";

                    options.Scope.Clear();
                    foreach (var scope in authOptions.Scopes.Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        options.Scope.Add(scope);
                    }
                });

                services.AddTransient<IClaimsTransformation, AdminClaimsTransformation>();
            }

            services.AddAuthorization(options =>
            {
                options.AddPolicy(AdminPolicyNames.AdminOnly, policy =>
                    policy.RequireClaim("app:role", "Admin"));

                options.AddPolicy(AdminPolicyNames.SupportOrAdmin, policy =>
                    policy.RequireClaim("app:role", "Admin", "Support"));

                if (authOptions.EnforceLogin)
                {
                    options.FallbackPolicy = new AuthorizationPolicyBuilder()
                        .RequireAuthenticatedUser()
                        .Build();
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
        services.AddScoped<SimulatorAutoHardeningService>();
        services.AddSingleton<ISimulatorAutoHardeningIdempotencyStore, InMemorySimulatorAutoHardeningIdempotencyStore>();
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

        if (authOptions.EnableOidc || authOptions.EnableLocalAuth)
        {
            app.UseAuthentication();
            app.UseAuthorization();
        }

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
            endpoints.MapBlazorHub();
            endpoints.MapFallbackToPage("/_Host");
        });
    }
}
