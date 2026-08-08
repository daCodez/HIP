using System.Text.Json;
using System.Text.Json.Serialization;
using HIP.Application.Certificates;
using HIP.Application.Domains;
using HIP.Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>EF Core repository for retained managed-domain certificate applications.</summary>
public sealed class EfManagedDomainCertificateApplicationRepository(HipDbContext dbContext)
    : IManagedDomainCertificateApplicationRepository
{
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public async Task<ManagedDomainCertificateApplication?> GetAsync(string applicationId, CancellationToken cancellationToken) =>
        FromEntity(await dbContext.ManagedDomainCertificateApplications.AsNoTracking()
            .SingleOrDefaultAsync(item => item.ApplicationId == applicationId, cancellationToken));

    public async Task<IReadOnlyCollection<ManagedDomainCertificateApplication>> ListByDomainAsync(string domainId, CancellationToken cancellationToken) =>
        (await dbContext.ManagedDomainCertificateApplications.AsNoTracking()
            .Where(item => item.DomainId == domainId)
            .OrderBy(item => item.CreatedAtUtc)
            .ToListAsync(cancellationToken)).Select(FromEntityRequired).ToArray();

    public async Task<IReadOnlyCollection<ManagedDomainCertificateApplication>> ListPendingReviewAsync(CancellationToken cancellationToken) =>
        (await dbContext.ManagedDomainCertificateApplications.AsNoTracking()
            .Where(item => item.Status == HIP.Domain.Certificates.DomainCertificateApplicationStatus.PendingReview)
            .OrderBy(item => item.SubmittedAtUtc)
            .ThenBy(item => item.ApplicationId)
            .ToListAsync(cancellationToken)).Select(FromEntityRequired).ToArray();

    public async Task AddAsync(ManagedDomainCertificateApplication application, CancellationToken cancellationToken)
    {
        dbContext.ManagedDomainCertificateApplications.Add(ToEntity(application));
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task UpdateAsync(ManagedDomainCertificateApplication application, long expectedVersion, CancellationToken cancellationToken)
    {
        var entity = ToEntity(application);
        dbContext.ManagedDomainCertificateApplications.Attach(entity);
        dbContext.Entry(entity).Property(item => item.Version).OriginalValue = expectedVersion;
        dbContext.Entry(entity).State = EntityState.Modified;
        try { await dbContext.SaveChangesAsync(cancellationToken); }
        catch (DbUpdateConcurrencyException exception)
        {
            throw new InvalidOperationException("The certificate application changed before the operation completed.", exception);
        }
    }

    private static HipManagedDomainCertificateApplicationEntity ToEntity(ManagedDomainCertificateApplication item) => new()
    {
        ApplicationId = item.ApplicationId, DomainId = item.DomainId, DomainName = item.DomainName,
        RequestedLevel = item.RequestedLevel, ApplicantId = item.ApplicantId, OrganizationId = item.OrganizationId,
        Status = item.Status, CreatedAtUtc = item.CreatedAtUtc, SubmittedAtUtc = item.SubmittedAtUtc,
        EligibilityJson = item.Eligibility is null ? null : JsonSerializer.Serialize(item.Eligibility, JsonOptions),
        SecurityFindingsJson = JsonSerializer.Serialize(item.SecurityFindings, JsonOptions),
        RequiredRemediationJson = JsonSerializer.Serialize(item.RequiredRemediation, JsonOptions),
        ReviewerId = item.ReviewerId, ReviewerNotes = item.ReviewerNotes, Decision = item.Decision,
        DecisionAtUtc = item.DecisionAtUtc, Version = item.Version
    };

    private static ManagedDomainCertificateApplication? FromEntity(HipManagedDomainCertificateApplicationEntity? item) =>
        item is null ? null : FromEntityRequired(item);
    private static ManagedDomainCertificateApplication FromEntityRequired(HipManagedDomainCertificateApplicationEntity item) => new(
        item.ApplicationId, item.DomainId, item.DomainName, item.RequestedLevel, item.ApplicantId, item.OrganizationId,
        item.Status, item.CreatedAtUtc, item.SubmittedAtUtc,
        item.EligibilityJson is null ? null : JsonSerializer.Deserialize<DomainCertificatePolicyEvaluationResult>(item.EligibilityJson, JsonOptions),
        DeserializeList(item.SecurityFindingsJson), DeserializeList(item.RequiredRemediationJson),
        item.ReviewerId, item.ReviewerNotes, item.Decision, item.DecisionAtUtc, item.Version);
    private static string[] DeserializeList(string json) => JsonSerializer.Deserialize<string[]>(json, JsonOptions) ?? [];
    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}
