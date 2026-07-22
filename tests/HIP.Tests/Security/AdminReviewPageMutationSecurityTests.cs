using System.Security.Claims;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies direct review and appeal page mutations fail closed when circuit authorization or actor binding is invalid.
/// </summary>
[TestFixture]
public sealed class AdminReviewPageMutationSecurityTests
{
    private const string TestMutationPolicy = "TestAdminMutationPolicy";

    /// <summary>
    /// Confirms a production circuit without a HIP actor cannot invoke a mutation service callback.
    /// </summary>
    [Test]
    public async Task Missing_actor_fails_closed_without_invoking_mutation()
    {
        var callbackCount = 0;
        var authorization = new StubAuthorizationService(succeeds: true);

        var result = await HipAdminPageAccess.ExecuteAuthorizedAsync(
            Principal(),
            authorization,
            new StubHostEnvironment(Environments.Production),
            TestMutationPolicy,
            _ => ++callbackCount);

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(callbackCount, Is.Zero);
            Assert.That(authorization.CallCount, Is.Zero);
        });
    }

    /// <summary>
    /// Confirms actor-shaped claims from an unauthenticated identity cannot invoke a mutation callback.
    /// </summary>
    [Test]
    public async Task Unauthenticated_actor_claim_fails_closed_without_invoking_mutation()
    {
        var callbackCount = 0;
        var authorization = new StubAuthorizationService(succeeds: true);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(HipAuthenticationClaimTypes.ActorId, "untrusted-actor")],
            null,
            ClaimTypes.Name,
            ClaimTypes.Role));

        var result = await HipAdminPageAccess.ExecuteAuthorizedAsync(
            principal,
            authorization,
            new StubHostEnvironment(Environments.Production),
            TestMutationPolicy,
            _ => ++callbackCount);

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(callbackCount, Is.Zero);
            Assert.That(authorization.CallCount, Is.Zero);
        });
    }

    /// <summary>
    /// Confirms ambiguous HIP actor claims cannot invoke a mutation service callback.
    /// </summary>
    [Test]
    public async Task Duplicate_actor_claims_fail_closed_without_invoking_mutation()
    {
        var callbackCount = 0;
        var authorization = new StubAuthorizationService(succeeds: true);
        var principal = Principal(
            new Claim(HipAuthenticationClaimTypes.ActorId, "actor-one"),
            new Claim(HipAuthenticationClaimTypes.ActorId, "actor-two"));

        var result = await HipAdminPageAccess.ExecuteAuthorizedAsync(
            principal,
            authorization,
            new StubHostEnvironment(Environments.Development),
            TestMutationPolicy,
            _ => ++callbackCount);

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(callbackCount, Is.Zero);
            Assert.That(authorization.CallCount, Is.Zero);
        });
    }

    /// <summary>
    /// Confirms a blank HIP actor claim cannot be replaced by the Development identity fallback.
    /// </summary>
    [Test]
    public async Task Blank_actor_claim_fails_closed_without_invoking_mutation()
    {
        var callbackCount = 0;
        var authorization = new StubAuthorizationService(succeeds: true);
        var principal = Principal(
            new Claim(HipAuthenticationClaimTypes.ActorId, "   "),
            new Claim(ClaimTypes.Name, "development-reviewer"));

        var result = await HipAdminPageAccess.ExecuteAuthorizedAsync(
            principal,
            authorization,
            new StubHostEnvironment(Environments.Development),
            TestMutationPolicy,
            _ => ++callbackCount);

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(callbackCount, Is.Zero);
            Assert.That(authorization.CallCount, Is.Zero);
        });
    }

    /// <summary>
    /// Confirms a denied active-circuit policy cannot invoke a mutation service callback.
    /// </summary>
    [Test]
    public async Task Denied_policy_fails_closed_without_invoking_mutation()
    {
        var callbackCount = 0;
        var authorization = new StubAuthorizationService(succeeds: false);

        var result = await HipAdminPageAccess.ExecuteAuthorizedAsync(
            Principal(new Claim(HipAuthenticationClaimTypes.ActorId, "denied-actor")),
            authorization,
            new StubHostEnvironment(Environments.Production),
            TestMutationPolicy,
            _ => ++callbackCount);

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(callbackCount, Is.Zero);
            Assert.That(authorization.CallCount, Is.EqualTo(1));
            Assert.That(authorization.LastPolicyName, Is.EqualTo(TestMutationPolicy));
        });
    }

    /// <summary>
    /// Confirms sample-data actions cannot invoke service callbacks outside Development.
    /// </summary>
    [Test]
    public async Task Production_sample_action_fails_closed_without_invoking_mutation()
    {
        var callbackCount = 0;
        var authorization = new StubAuthorizationService(succeeds: true);

        var result = await HipAdminPageAccess.ExecuteAuthorizedAsync(
            Principal(new Claim(HipAuthenticationClaimTypes.ActorId, "production-actor")),
            authorization,
            new StubHostEnvironment(Environments.Production),
            TestMutationPolicy,
            _ => ++callbackCount,
            developmentOnly: true);

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(callbackCount, Is.Zero);
            Assert.That(authorization.CallCount, Is.Zero);
        });
    }

    /// <summary>
    /// Confirms an authorized callback receives the unique server-authenticated HIP actor.
    /// </summary>
    [Test]
    public async Task Allowed_mutation_receives_authenticated_hip_actor()
    {
        string? callbackActor = null;
        var authorization = new StubAuthorizationService(succeeds: true);

        var result = await HipAdminPageAccess.ExecuteAuthorizedAsync(
            Principal(new Claim(HipAuthenticationClaimTypes.ActorId, "review-owner")),
            authorization,
            new StubHostEnvironment(Environments.Production),
            TestMutationPolicy,
            actor => callbackActor = actor);

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(callbackActor, Is.EqualTo("review-owner"));
            Assert.That(result.Value, Is.EqualTo("review-owner"));
            Assert.That(authorization.LastPolicyName, Is.EqualTo(TestMutationPolicy));
        });
    }

    /// <summary>
    /// Confirms an asynchronous privileged mutation runs only after every named policy is rechecked in the circuit.
    /// </summary>
    [Test]
    public async Task Async_mutation_requires_every_named_policy_before_receiving_the_actor()
    {
        string? callbackActor = null;
        var authorization = new PerPolicyAuthorizationService(new Dictionary<string, bool>(StringComparer.Ordinal)
        {
            [AdminPolicies.CanManageServiceClients] = true,
            [AdminPolicies.RecentPrivilegedAuthentication] = true
        });

        var result = await HipAdminPageAccess.ExecuteAuthorizedAsync<string>(
            Principal(new Claim(HipAuthenticationClaimTypes.ActorId, "service-client-owner")),
            authorization,
            new StubHostEnvironment(Environments.Production),
            [AdminPolicies.CanManageServiceClients, AdminPolicies.RecentPrivilegedAuthentication],
            (actor, _) =>
            {
                callbackActor = actor;
                return Task.FromResult("completed");
            },
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo("completed"));
            Assert.That(callbackActor, Is.EqualTo("service-client-owner"));
            Assert.That(authorization.Policies, Is.EqualTo(new[]
            {
                AdminPolicies.CanManageServiceClients,
                AdminPolicies.RecentPrivilegedAuthentication
            }));
        });
    }

    /// <summary>Confirms denial of the recent-authentication policy prevents the asynchronous callback.</summary>
    [Test]
    public async Task Async_mutation_fails_closed_when_any_named_policy_is_denied()
    {
        var callbackCount = 0;
        var authorization = new PerPolicyAuthorizationService(new Dictionary<string, bool>(StringComparer.Ordinal)
        {
            [AdminPolicies.CanManageServiceClients] = true,
            [AdminPolicies.RecentPrivilegedAuthentication] = false
        });

        var result = await HipAdminPageAccess.ExecuteAuthorizedAsync<string>(
            Principal(new Claim(HipAuthenticationClaimTypes.ActorId, "service-client-owner")),
            authorization,
            new StubHostEnvironment(Environments.Production),
            [AdminPolicies.CanManageServiceClients, AdminPolicies.RecentPrivilegedAuthentication],
            (_, _) =>
            {
                callbackCount++;
                return Task.FromResult("should-not-run");
            },
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(callbackCount, Is.Zero);
            Assert.That(authorization.Policies, Is.EqualTo(new[]
            {
                AdminPolicies.CanManageServiceClients,
                AdminPolicies.RecentPrivilegedAuthentication
            }));
        });
    }

    /// <summary>
    /// Confirms Development also fails closed when the authenticated identity lacks a HIP actor claim.
    /// </summary>
    [Test]
    public async Task Development_without_hip_actor_fails_closed()
    {
        var callbackCount = 0;
        var authorization = new StubAuthorizationService(succeeds: true);

        var result = await HipAdminPageAccess.ExecuteAuthorizedAsync(
            Principal(new Claim(ClaimTypes.Name, "development-reviewer")),
            authorization,
            new StubHostEnvironment(Environments.Development),
            TestMutationPolicy,
            _ => ++callbackCount);

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(callbackCount, Is.Zero);
            Assert.That(authorization.CallCount, Is.Zero);
        });
    }

    /// <summary>
    /// Confirms both pages route every mutation through the circuit guard and never retain development actor constants.
    /// </summary>
    [Test]
    public void Review_and_appeal_pages_use_guarded_actor_bound_mutations()
    {
        var reviewPage = File.ReadAllText(Path.Combine(
            RepositoryRoot(), "src", "HIP.Web", "Components", "Pages", "AdminReview.razor"));
        var appealPage = File.ReadAllText(Path.Combine(
            RepositoryRoot(), "src", "HIP.Web", "Components", "Pages", "AdminAppeals.razor"));

        Assert.Multiple(() =>
        {
            Assert.That(reviewPage, Does.Not.Contain("admin-dev"));
            Assert.That(appealPage, Does.Not.Contain("admin-dev"));
            Assert.That(reviewPage, Does.Contain("HipAdminPageAccess.ExecuteAuthorizedAsync"));
            Assert.That(appealPage, Does.Contain("HipAdminPageAccess.ExecuteAuthorizedAsync"));
            Assert.That(reviewPage, Does.Contain("Authorize(Policy = AdminPolicies.CanViewReviews)"));
            Assert.That(reviewPage, Does.Contain("Policy=\"@AdminPolicies.CanDecideReviews\""));
            Assert.That(reviewPage, Does.Contain("AdminPolicies.CanDecideReviews,\n            mutation"));
            Assert.That(appealPage, Does.Contain("Authorize(Policy = AdminPolicies.CanViewAppeals)"));
            Assert.That(appealPage, Does.Contain("Policy=\"@AdminPolicies.CanDecideAppeals\""));
            Assert.That(appealPage, Does.Contain("AdminPolicies.CanDecideAppeals,\n            mutation"));
            Assert.That(reviewPage, Does.Contain("@if (HostEnvironment.IsDevelopment())"));
            Assert.That(appealPage, Does.Contain("@if (HostEnvironment.IsDevelopment())"));
            Assert.That(reviewPage, Does.Contain("developmentOnly: true"));
            Assert.That(appealPage, Does.Contain("developmentOnly: true"));
        });
    }

    private static ClaimsPrincipal Principal(params Claim[] claims) =>
        new(new ClaimsIdentity(claims, "test", ClaimTypes.Name, ClaimTypes.Role));

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Could not locate HIP repository root.");
    }

    private sealed class StubAuthorizationService(bool succeeds) : IAuthorizationService
    {
        /// <summary>
        /// Gets the number of policy evaluations performed.
        /// </summary>
        public int CallCount { get; private set; }

        /// <summary>
        /// Gets the last named policy evaluated.
        /// </summary>
        public string? LastPolicyName { get; private set; }

        /// <inheritdoc />
        public Task<AuthorizationResult> AuthorizeAsync(
            ClaimsPrincipal user,
            object? resource,
            IEnumerable<IAuthorizationRequirement> requirements)
        {
            CallCount++;
            return Task.FromResult(succeeds ? AuthorizationResult.Success() : AuthorizationResult.Failed());
        }

        /// <inheritdoc />
        public Task<AuthorizationResult> AuthorizeAsync(
            ClaimsPrincipal user,
            object? resource,
            string policyName)
        {
            CallCount++;
            LastPolicyName = policyName;
            return Task.FromResult(succeeds ? AuthorizationResult.Success() : AuthorizationResult.Failed());
        }
    }

    private sealed class PerPolicyAuthorizationService(IReadOnlyDictionary<string, bool> outcomes)
        : IAuthorizationService
    {
        public List<string> Policies { get; } = [];

        public Task<AuthorizationResult> AuthorizeAsync(
            ClaimsPrincipal user,
            object? resource,
            IEnumerable<IAuthorizationRequirement> requirements) =>
            Task.FromResult(AuthorizationResult.Failed());

        public Task<AuthorizationResult> AuthorizeAsync(
            ClaimsPrincipal user,
            object? resource,
            string policyName)
        {
            Policies.Add(policyName);
            return Task.FromResult(
                outcomes.TryGetValue(policyName, out var succeeds) && succeeds
                    ? AuthorizationResult.Success()
                    : AuthorizationResult.Failed());
        }
    }

    private sealed class StubHostEnvironment(string environmentName) : IHostEnvironment
    {
        /// <inheritdoc />
        public string EnvironmentName { get; set; } = environmentName;

        /// <inheritdoc />
        public string ApplicationName { get; set; } = "HIP.Tests";

        /// <inheritdoc />
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        /// <inheritdoc />
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
