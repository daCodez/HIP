using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Web.Security;

public static class HipAuthorizationExtensions
{
    public static IServiceCollection AddHipAdminAuthorization(this IServiceCollection services)
    {
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IAuthorizationHandler, PrivilegedMfaRequirementHandler>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IAuthorizationHandler, RecentPrivilegedMfaRequirementHandler>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IAuthorizationHandler, UniqueHipIdentityClaimRequirementHandler>());
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IAuthorizationHandler, ActiveHudDeviceRequirementHandler>());

        services.AddAuthorization(options =>
        {
            AddAdminPolicy(options, AdminPolicies.CanManageRules, [AdminRoles.Owner, AdminRoles.Admin]);
            AddAdminPolicy(
                options,
                AdminPolicies.CanReviewReports,
                [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Moderator]);
            AddAdminPolicy(
                options,
                AdminPolicies.CanViewReviews,
                [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Moderator, AdminRoles.Support, AdminRoles.ReadOnly]);
            AddAdminPolicy(
                options,
                AdminPolicies.CanDecideReviews,
                [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Moderator]);
            AddAdminPolicy(
                options,
                AdminPolicies.CanViewAppeals,
                [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Moderator, AdminRoles.ReadOnly]);
            AddAdminPolicy(
                options,
                AdminPolicies.CanDecideAppeals,
                [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Moderator]);
            AddAdminPolicy(options, AdminPolicies.CanApproveOverrides, [AdminRoles.Owner, AdminRoles.Admin]);
            AddAdminPolicy(options, AdminPolicies.CanManageReputation, [AdminRoles.Owner, AdminRoles.Admin]);
            AddAdminPolicy(
                options,
                AdminPolicies.CanViewAuditLogs,
                [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.ReadOnly]);
            AddAdminPolicy(
                options,
                AdminPolicies.CanManageLicenses,
                [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Support]);
            AddAdminPolicy(
                options,
                AdminPolicies.CanViewLicenses,
                [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Support, AdminRoles.ReadOnly]);
            AddAdminPolicy(
                options,
                AdminPolicies.CanSupportLicenses,
                [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Support]);
            AddAdminPolicy(
                options,
                AdminPolicies.CanAdministerLicenses,
                [AdminRoles.Owner, AdminRoles.Admin]);
            AddAdminPolicy(options, AdminPolicies.CanManagePlatforms, [AdminRoles.Owner, AdminRoles.Admin]);
            AddAdminPolicy(options, AdminPolicies.CanViewServiceClients, [AdminRoles.Owner, AdminRoles.Admin]);
            AddAdminPolicy(options, AdminPolicies.CanManageServiceClients, [AdminRoles.Owner, AdminRoles.Admin]);
            AddAdminPolicy(
                options,
                AdminPolicies.CanViewAdminDashboard,
                [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Moderator, AdminRoles.Support, AdminRoles.ReadOnly]);
            AddAdminPolicy(
                options,
                AdminPolicies.CanManageDomainVerifications,
                [AdminRoles.Owner, AdminRoles.Admin]);
            AddAdminPolicy(options, AdminPolicies.CanRevokeDomainVerifications, [AdminRoles.Owner]);
            options.AddPolicy(AdminPolicies.CanRequestPrivilegedStepUp, policy =>
            {
                policy.RequireRole(AdminRoles.Owner, AdminRoles.Admin);
                policy.AddRequirements(new UniqueHipIdentityClaimRequirement(
                    HipAuthenticationClaimTypes.ActorId));
            });
            AddAdminPolicy(
                options,
                AdminPolicies.RecentPrivilegedAuthentication,
                [AdminRoles.Owner, AdminRoles.Admin],
                new RecentPrivilegedMfaRequirement());
            options.AddPolicy(ConsumerPolicies.CanUseConsumerPortal, policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.AddRequirements(new UniqueHipIdentityClaimRequirement(
                    HipAuthenticationClaimTypes.ConsumerId));
            });
            options.AddPolicy(HudPolicies.CanUseActiveDevice, policy =>
                policy.AddRequirements(new ActiveHudDeviceRequirement()));
        });

        return services;
    }

    private static void AddAdminPolicy(
        AuthorizationOptions options,
        string policyName,
        IReadOnlyCollection<string> roles,
        params IAuthorizationRequirement[] additionalRequirements)
    {
        options.AddPolicy(policyName, policy =>
        {
            policy.RequireRole(roles);
            policy.AddRequirements(new PrivilegedMfaRequirement());
            policy.AddRequirements(new UniqueHipIdentityClaimRequirement(
                HipAuthenticationClaimTypes.ActorId));
            policy.AddRequirements(additionalRequirements);
        });
    }
}
