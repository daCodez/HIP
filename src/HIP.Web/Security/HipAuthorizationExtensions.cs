using Microsoft.AspNetCore.Authentication;

namespace HIP.Web.Security;

public static class HipAuthorizationExtensions
{
    public static IServiceCollection AddHipAdminAuthorization(this IServiceCollection services)
    {
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = HipDevHeaderAuthenticationHandler.SchemeName;
            options.DefaultChallengeScheme = HipDevHeaderAuthenticationHandler.SchemeName;
        })
        .AddScheme<AuthenticationSchemeOptions, HipDevHeaderAuthenticationHandler>(
            HipDevHeaderAuthenticationHandler.SchemeName,
            options => { });

        services.AddAuthorization(options =>
        {
            options.AddPolicy(AdminPolicies.CanManageRules, policy =>
                policy.RequireRole(AdminRoles.Owner, AdminRoles.Admin));
            options.AddPolicy(AdminPolicies.CanReviewReports, policy =>
                policy.RequireRole(AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Moderator));
            options.AddPolicy(AdminPolicies.CanApproveOverrides, policy =>
                policy.RequireRole(AdminRoles.Owner, AdminRoles.Admin));
            options.AddPolicy(AdminPolicies.CanViewAuditLogs, policy =>
                policy.RequireRole(AdminRoles.Owner, AdminRoles.Admin, AdminRoles.ReadOnly));
            options.AddPolicy(AdminPolicies.CanManageLicenses, policy =>
                policy.RequireRole(AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Support));
            options.AddPolicy(AdminPolicies.CanViewAdminDashboard, policy =>
                policy.RequireRole(AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Moderator, AdminRoles.Support, AdminRoles.ReadOnly));
            options.AddPolicy(ConsumerPolicies.CanUseConsumerPortal, policy =>
                policy.RequireAuthenticatedUser());
        });

        return services;
    }
}
