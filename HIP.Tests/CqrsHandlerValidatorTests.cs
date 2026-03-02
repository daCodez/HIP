using FluentValidation;
using HIP.ApiService.Application.Abstractions;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;
using HIP.ApiService.Application.Contracts;
using HIP.ApiService.Features.Identity;
using HIP.ApiService.Features.Reputation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class CqrsHandlerValidatorTests
{
    private sealed class FakeIdentityService : IIdentityService
    {
        public Task<IdentityDto?> GetByIdAsync(string id, CancellationToken cancellationToken)
            => Task.FromResult<IdentityDto?>(id == "hip-system" ? new IdentityDto("hip-system", "pkref:placeholder") : null);
    }

    private sealed class FakeReputationService : IReputationService
    {
        public Task<int> GetScoreAsync(string identityId, CancellationToken cancellationToken)
            => Task.FromResult(identityId == "hip-system" ? 50 : 0);

        public Task<ReputationScoreBreakdown> GetScoreBreakdownAsync(string identityId, CancellationToken cancellationToken)
            => Task.FromResult(new ReputationScoreBreakdown(identityId, 50, 0, 0, 0, 0, 0, 0, DateTimeOffset.UtcNow));

        public Task RecordSecurityEventAsync(string identityId, string eventType, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }

    private sealed class FakeAuditTrail : IAuditTrail
    {
        public Task AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<IReadOnlyList<AuditEvent>> RecentAsync(int count, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<AuditEvent>>(Array.Empty<AuditEvent>());

        public Task<IReadOnlyList<AuditEvent>> QueryAsync(AuditQuery query, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<AuditEvent>>(Array.Empty<AuditEvent>());
    }

    [Test]
    public async Task GetIdentityHandler_KnownId_ReturnsIdentity()
    {
        var handler = new GetIdentityHandler(new FakeIdentityService(), new FakeAuditTrail(), new HttpContextAccessor(), NullLogger<GetIdentityHandler>.Instance);

        var result = await handler.Handle(new GetIdentityQuery("hip-system"), CancellationToken.None);

        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Id, Is.EqualTo("hip-system"));
    }

    [Test]
    public async Task GetReputationHandler_KnownId_ReturnsBaseScore()
    {
        var handler = new GetReputationHandler(new FakeReputationService(), new FakeAuditTrail(), new HttpContextAccessor(), NullLogger<GetReputationHandler>.Instance);

        var result = await handler.Handle(new GetReputationQuery("hip-system"), CancellationToken.None);

        Assert.That(result.IdentityId, Is.EqualTo("hip-system"));
        Assert.That(result.Score, Is.EqualTo(50));
    }

    [Test]
    public void GetIdentityValidator_EmptyId_Fails()
    {
        var validator = new GetIdentityValidator();

        var result = validator.Validate(new GetIdentityQuery(string.Empty));

        Assert.That(result.IsValid, Is.EqualTo(false));
        Assert.That(result.Errors.Count, Is.EqualTo(1));
    }

    [Test]
    public void GetReputationValidator_EmptyIdentityId_Fails()
    {
        var validator = new GetReputationValidator();

        var result = validator.Validate(new GetReputationQuery(string.Empty));

        Assert.That(result.IsValid, Is.EqualTo(false));
        Assert.That(result.Errors.Count, Is.EqualTo(1));
    }
}
