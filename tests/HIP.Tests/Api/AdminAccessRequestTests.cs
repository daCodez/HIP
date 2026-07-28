using HIP.Application.Administration;
using HIP.Application.Review;
using HIP.Domain.Audit;

namespace HIP.Tests.Api;

[TestFixture]
public sealed class AdminAccessRequestTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 28, 18, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Authenticated_actor_is_persisted_without_email_or_external_identity()
    {
        var requests = new RecordingRequestRepository();
        var result = await Service(requests).SubmitAsync(
            "hip-user:v1:privacy-safe",
            new AdminAccessRequestSubmission("Security operator", "Needs incident review access"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(AdminAccessRequestMutationStatus.Saved));
            Assert.That(requests.Current!.ActorId, Is.EqualTo("hip-user:v1:privacy-safe"));
            Assert.That(requests.Current.DisplayLabel, Is.EqualTo("Security operator"));
            Assert.That(requests.LastAudit!.ActorId, Is.EqualTo("hip-user:v1:privacy-safe"));
            Assert.That(requests.LastAudit.Metadata.Values, Has.None.Contains("Security operator"));
            Assert.That(requests.LastAudit.Metadata.Values, Has.None.Contains("incident review"));
        });
    }

    [Test]
    public async Task Email_label_and_duplicate_pending_request_fail_without_an_extra_write()
    {
        var requests = new RecordingRequestRepository();
        var service = Service(requests);
        var invalid = await service.SubmitAsync(
            "hip-user:v1:one",
            new AdminAccessRequestSubmission("person@example.com", "Needs review access"),
            CancellationToken.None);
        var first = await service.SubmitAsync(
            "hip-user:v1:one",
            new AdminAccessRequestSubmission("Review operator", "Needs review access"),
            CancellationToken.None);
        var duplicate = await service.SubmitAsync(
            "hip-user:v1:one",
            new AdminAccessRequestSubmission("Different label", "Still needs access"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(invalid.Status, Is.EqualTo(AdminAccessRequestMutationStatus.Invalid));
            Assert.That(first.Status, Is.EqualTo(AdminAccessRequestMutationStatus.Saved));
            Assert.That(duplicate.Status, Is.EqualTo(AdminAccessRequestMutationStatus.AlreadyPending));
            Assert.That(requests.SaveCalls, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Only_active_owner_can_list_pending_requests()
    {
        var requests = new RecordingRequestRepository();
        await Service(requests).SubmitAsync(
            "hip-user:v1:requester",
            new AdminAccessRequestSubmission("Requesting operator", "Needs review access"),
            CancellationToken.None);
        var access = new RecordingAccessRepository(Directory(
            new AdminAccessAssignment(
                "hip-user:v1:owner",
                "Primary owner",
                AdminAccessRoleNames.Owner,
                AdminAccessStatus.Active,
                Now,
                Now)));
        var service = Service(requests, access);

        var ownerView = await service.ListPendingAsync(
            "hip-user:v1:owner", AdminAccessRoleNames.Owner, CancellationToken.None);
        var adminView = await service.ListPendingAsync(
            "hip-user:v1:owner", AdminAccessRoleNames.Admin, CancellationToken.None);
        var staleOwnerView = await service.ListPendingAsync(
            "hip-user:v1:other", AdminAccessRoleNames.Owner, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(ownerView.Select(item => item.ActorId), Is.EqualTo(new[] { "hip-user:v1:requester" }));
            Assert.That(adminView, Is.Empty);
            Assert.That(staleOwnerView, Is.Empty);
        });
    }

    [Test]
    public async Task Existing_active_assignment_prevents_request()
    {
        var requests = new RecordingRequestRepository();
        var access = new RecordingAccessRepository(Directory(
            new AdminAccessAssignment(
                "hip-user:v1:assigned",
                "Assigned operator",
                AdminAccessRoleNames.ReadOnly,
                AdminAccessStatus.Active,
                Now,
                Now)));

        var result = await Service(requests, access).SubmitAsync(
            "hip-user:v1:assigned",
            new AdminAccessRequestSubmission("Assigned operator", "Requests duplicate access"),
            CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(AdminAccessRequestMutationStatus.AlreadyAssigned));
        Assert.That(requests.SaveCalls, Is.Zero);
    }

    [Test]
    public async Task Active_owner_can_deny_pending_request_with_versioned_audit()
    {
        var requests = new RecordingRequestRepository();
        await Service(requests).SubmitAsync(
            "hip-user:v1:requester",
            new AdminAccessRequestSubmission("Requesting operator", "Needs review access"),
            CancellationToken.None);
        var access = new RecordingAccessRepository(Directory(
            new AdminAccessAssignment(
                "hip-user:v1:owner",
                "Primary owner",
                AdminAccessRoleNames.Owner,
                AdminAccessStatus.Active,
                Now,
                Now)));

        var result = await Service(requests, access).DenyAsync(
            "hip-user:v1:owner",
            AdminAccessRoleNames.Owner,
            "hip-user:v1:requester",
            1,
            "Role is not required",
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(AdminAccessRequestMutationStatus.Saved));
            Assert.That(result.Request!.Status, Is.EqualTo(AdminAccessRequestStatus.Denied));
            Assert.That(result.Request.Version, Is.EqualTo(2));
            Assert.That(requests.LastAudit!.ActorId, Is.EqualTo("hip-user:v1:owner"));
            Assert.That(requests.LastAudit.Action, Is.EqualTo("Administrator access request denied"));
        });
    }
    private static AdminAccessRequestService Service(
        RecordingRequestRepository requests,
        RecordingAccessRepository? access = null) =>
        new(
            requests,
            access ?? new RecordingAccessRepository(),
            new AuditLogService(new InMemoryAuditLogRepository()),
            new FixedTimeProvider(Now));

    private static AdminAccessDirectory Directory(params AdminAccessAssignment[] assignments) =>
        new(1, assignments, Now);

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class RecordingAccessRepository(AdminAccessDirectory? directory = null) : IAdminAccessRepository
    {
        public Task<AdminAccessDirectory?> GetAsync(CancellationToken cancellationToken) =>
            Task.FromResult(directory);

        public Task<bool> TrySaveAsync(
            AdminAccessDirectory updated,
            long expectedVersion,
            AuditLogEntry auditEntry,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class RecordingRequestRepository : IAdminAccessRequestRepository
    {
        public AdminAccessRequestRecord? Current { get; private set; }
        public AuditLogEntry? LastAudit { get; private set; }
        public int SaveCalls { get; private set; }

        public Task<AdminAccessRequestRecord?> GetForActorAsync(
            string actorId,
            CancellationToken cancellationToken) =>
            Task.FromResult(
                string.Equals(Current?.ActorId, actorId, StringComparison.Ordinal)
                    ? Current
                    : null);

        public Task<IReadOnlyCollection<AdminAccessRequestRecord>> ListAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyCollection<AdminAccessRequestRecord>>(
                Current is null ? [] : [Current]);

        public Task<bool> TrySaveAsync(
            AdminAccessRequestRecord request,
            long expectedVersion,
            AuditLogEntry auditEntry,
            CancellationToken cancellationToken)
        {
            SaveCalls++;
            if ((Current?.Version ?? 0) != expectedVersion)
            {
                return Task.FromResult(false);
            }

            Current = request;
            LastAudit = auditEntry;
            return Task.FromResult(true);
        }
    }
}
