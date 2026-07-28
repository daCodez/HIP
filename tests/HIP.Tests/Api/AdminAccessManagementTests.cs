using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using HIP.Application.Administration;
using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Review;
using HIP.Web.Security;
using Microsoft.Extensions.Logging.Abstractions;

namespace HIP.Tests.Api;

[TestFixture]
public sealed class AdminAccessManagementTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 28, 16, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task First_change_bootstraps_current_owner_and_commits_privacy_safe_audit()
    {
        var repository = new RecordingRepository();
        var result = await Service(repository).ChangeAsync(
            "owner-1", AdminAccessRoleNames.Owner,
            Request("admin-2", AdminAccessRoleNames.Admin, 0), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(AdminAccessChangeStatus.Saved));
            Assert.That(result.Directory!.Version, Is.EqualTo(1));
            Assert.That(result.Directory.Assignments.Select(item => item.ActorId), Is.EquivalentTo(new[] { "owner-1", "admin-2" }));
            Assert.That(repository.LastAudit!.TargetType, Is.EqualTo(TargetType.Administrator));
            Assert.That(repository.LastAudit.TargetId, Is.EqualTo("admin-2"));
            Assert.That(repository.LastAudit.Metadata["reason"], Is.EqualTo("V1 access requirement"));
            Assert.That(repository.LastAudit.AfterMetadata!["role"], Is.EqualTo(AdminAccessRoleNames.Admin));
            Assert.That(repository.LastAudit.Metadata.Values, Has.None.Contains("Operations user"));
        });
    }

    [Test]
    public async Task Stale_version_and_self_demotion_fail_without_writing()
    {
        var repository = new RecordingRepository(Directory(
            new AdminAccessAssignment("owner-1", "Primary owner", AdminAccessRoleNames.Owner, AdminAccessStatus.Active, Now, Now)));
        var service = Service(repository);

        var stale = await service.ChangeAsync(
            "owner-1", AdminAccessRoleNames.Owner,
            Request("admin-2", AdminAccessRoleNames.Admin, 0), CancellationToken.None);
        var selfDemotion = await service.ChangeAsync(
            "owner-1", AdminAccessRoleNames.Owner,
            Request("owner-1", AdminAccessRoleNames.ReadOnly, 1), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(stale.Status, Is.EqualTo(AdminAccessChangeStatus.Conflict));
            Assert.That(selfDemotion.Status, Is.EqualTo(AdminAccessChangeStatus.SelfChangeDenied));
            Assert.That(repository.SaveCalls, Is.Zero);
        });
    }

    [Test]
    public async Task Stale_claim_owner_without_persisted_active_assignment_is_forbidden()
    {
        var repository = new RecordingRepository(Directory(
            new AdminAccessAssignment("owner-1", "Primary owner", AdminAccessRoleNames.Owner, AdminAccessStatus.Active, Now, Now)));

        var result = await Service(repository).ChangeAsync(
            "former-owner", AdminAccessRoleNames.Owner,
            Request("admin-2", AdminAccessRoleNames.Admin, 1), CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(AdminAccessChangeStatus.Forbidden));
        Assert.That(repository.SaveCalls, Is.Zero);
    }

    [Test]
    public async Task Operator_label_rejects_email_addresses()
    {
        var repository = new RecordingRepository();
        var request = Request("admin-2", AdminAccessRoleNames.Admin, 0) with { DisplayLabel = "person@example.com" };

        var result = await Service(repository).ChangeAsync(
            "owner-1", AdminAccessRoleNames.Owner, request, CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(AdminAccessChangeStatus.Invalid));
        Assert.That(repository.SaveCalls, Is.Zero);
    }

    [Test]
    public async Task Null_untrusted_fields_are_rejected_without_a_write()
    {
        var repository = new RecordingRepository();
        var request = Request("admin-2", AdminAccessRoleNames.Admin, 0) with
        {
            DisplayLabel = null!,
            Reason = null!
        };

        var result = await Service(repository).ChangeAsync(
            "owner-1", AdminAccessRoleNames.Owner, request, CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(AdminAccessChangeStatus.Invalid));
        Assert.That(repository.SaveCalls, Is.Zero);
    }
    [Test]
    public async Task Managed_assignment_replaces_external_role_claim()
    {
        var repository = new RecordingRepository(Directory(
            new AdminAccessAssignment("actor-1", "Operator", AdminAccessRoleNames.ReadOnly, AdminAccessStatus.Active, Now, Now)));
        var principal = Principal("actor-1", AdminAccessRoleNames.Owner);

        var transformed = await new ManagedAdminAccessClaimsTransformation(repository, NullLogger<ManagedAdminAccessClaimsTransformation>.Instance).TransformAsync(principal);

        Assert.That(transformed.IsInRole(AdminAccessRoleNames.ReadOnly), Is.True);
        Assert.That(transformed.IsInRole(AdminAccessRoleNames.Owner), Is.False);
    }

    [Test]
    public async Task Unassigned_actor_loses_external_admin_role_after_directory_exists()
    {
        var repository = new RecordingRepository(Directory(
            new AdminAccessAssignment("owner-1", "Primary owner", AdminAccessRoleNames.Owner, AdminAccessStatus.Active, Now, Now)));

        var transformed = await new ManagedAdminAccessClaimsTransformation(repository, NullLogger<ManagedAdminAccessClaimsTransformation>.Instance)
            .TransformAsync(Principal("unknown-actor", AdminAccessRoleNames.Owner));

        Assert.That(AdminAccessRoleNames.All.Any(transformed.IsInRole), Is.False);
    }

    [Test]
    public async Task Owner_can_render_management_and_self_access_pages()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var owner = factory.CreateClient();
        owner.DefaultRequestHeaders.Add("X-HIP-Admin-Role", AdminAccessRoleNames.Owner);
        owner.DefaultRequestHeaders.Add("X-HIP-Admin-User", "page-owner");

        var management = await owner.GetStringAsync("/admin/roles");
        var selfAccess = await owner.GetStringAsync("/access");

        Assert.Multiple(() =>
        {
            Assert.That(management, Does.Contain("<h1>Users and roles</h1>"));
            Assert.That(management, Does.Contain("Add administrator"));
            Assert.That(management, Does.Contain("/access"));
            Assert.That(selfAccess, Does.Contain("<h1>Access status</h1>"));
            Assert.That(selfAccess, Does.Contain("page-owner"));
        });
    }
    [Test]
    public async Task User_management_endpoints_require_owner_access()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var anonymous = factory.CreateClient();
        using var administrator = factory.CreateClient();
        administrator.DefaultRequestHeaders.Add("X-HIP-Admin-Role", AdminAccessRoleNames.Admin);
        administrator.DefaultRequestHeaders.Add("X-HIP-Admin-User", "access-admin");

        using var anonymousSelfResponse = await anonymous.GetAsync("/api/v1/admin/access/me");
        using var anonymousResponse = await anonymous.GetAsync("/api/v1/admin/users");
        using var administratorResponse = await administrator.GetAsync("/api/v1/admin/users");

        Assert.That(anonymousSelfResponse.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(anonymousResponse.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(administratorResponse.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task Owner_can_persist_assignment_and_read_its_audit_record()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var owner = factory.CreateClient();
        owner.DefaultRequestHeaders.Add("X-HIP-Admin-Role", AdminAccessRoleNames.Owner);
        owner.DefaultRequestHeaders.Add("X-HIP-Admin-User", "access-owner");

        using var selfResponse = await owner.GetAsync("/api/v1/admin/access/me");
        var selfBody = await selfResponse.Content.ReadAsStringAsync();
        var initial = await owner.GetFromJsonAsync<AdminAccessDirectory>("/api/v1/admin/users");
        var request = new AdminAccessChangeRequest(
            "access-reader", "Security reviewer", AdminAccessRoleNames.ReadOnly,
            AdminAccessStatus.Active, initial!.Version, "Grant review-only V1 access");
        using var saved = await owner.PutAsJsonAsync("/api/v1/admin/users", request);
        var directory = await owner.GetFromJsonAsync<AdminAccessDirectory>("/api/v1/admin/users");
        var audit = await owner.GetStringAsync("/api/v1/admin/audit");

        Assert.Multiple(() =>
        {
            Assert.That(selfResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(selfResponse.Headers.CacheControl?.NoStore, Is.True);
            Assert.That(selfBody, Does.Contain("access-owner"));
            Assert.That(saved.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(directory!.Assignments.Any(item => item.ActorId == "access-reader" && item.Role == AdminAccessRoleNames.ReadOnly), Is.True);
            Assert.That(audit, Does.Contain("Administrator access granted"));
            Assert.That(audit, Does.Not.Contain("Security reviewer"));
        });
    }
    [Test]
    public async Task Storage_failure_removes_external_admin_role_claims()
    {
        var principal = Principal("actor-1", AdminAccessRoleNames.Owner);
        var transformed = await new ManagedAdminAccessClaimsTransformation(
            new ThrowingRepository(), NullLogger<ManagedAdminAccessClaimsTransformation>.Instance)
            .TransformAsync(principal);

        Assert.That(AdminAccessRoleNames.All.Any(transformed.IsInRole), Is.False);
    }
    private static AdminAccessService Service(RecordingRepository repository) =>
        new(repository, new AuditLogService(new InMemoryAuditLogRepository()), new FixedTimeProvider(Now));

    private static AdminAccessChangeRequest Request(string actorId, string role, long version) =>
        new(actorId, "Operations user", role, AdminAccessStatus.Active, version, "V1 access requirement");

    private static AdminAccessDirectory Directory(params AdminAccessAssignment[] assignments) => new(1, assignments, Now);

    private static ClaimsPrincipal Principal(string actorId, string role) =>
        new(new ClaimsIdentity(
            [new Claim(HipAuthenticationClaimTypes.ActorId, actorId), new Claim(ClaimTypes.Role, role)],
            "test", ClaimTypes.Name, ClaimTypes.Role));

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class ThrowingRepository : IAdminAccessRepository
    {
        public Task<AdminAccessDirectory?> GetAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Storage unavailable.");

        public Task<bool> TrySaveAsync(AdminAccessDirectory directory, long expectedVersion, AuditLogEntry auditEntry, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Storage unavailable.");
    }
    private sealed class RecordingRepository(AdminAccessDirectory? directory = null) : IAdminAccessRepository
    {
        public int SaveCalls { get; private set; }
        public AuditLogEntry? LastAudit { get; private set; }
        public Task<AdminAccessDirectory?> GetAsync(CancellationToken cancellationToken) => Task.FromResult(directory);
        public Task<bool> TrySaveAsync(AdminAccessDirectory updated, long expectedVersion, AuditLogEntry auditEntry, CancellationToken cancellationToken)
        {
            SaveCalls++;
            LastAudit = auditEntry;
            directory = updated;
            return Task.FromResult(true);
        }
    }
}