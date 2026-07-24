using System.Security.Cryptography;
using System.Text;
using HIP.Application.Identity;
using HIP.Domain.Certificates;
using HIP.Domain.Identity;

namespace HIP.Application.Certificates;

/// <summary>Owner request to begin one domain-control and certificate enrollment.</summary>
public sealed record DomainCertificateEnrollmentStartRequest(
    string Domain,
    string DisplayName,
    VerificationMethod VerificationMethod);

/// <summary>Safe result of an owner enrollment command.</summary>
public enum DomainCertificateEnrollmentStartStatus
{
    InvalidRequest,
    Conflict,
    PersistenceUnavailable,
    Started,
    Existing
}

/// <summary>Owner-safe challenge response that never includes signing private key material.</summary>
public sealed record DomainCertificateEnrollmentStartResult(
    DomainCertificateEnrollmentStartStatus Status,
    string? Domain = null,
    VerificationMethod? VerificationMethod = null,
    string? ChallengeToken = null,
    DateTimeOffset? ChallengeExpiresAtUtc = null);

/// <summary>Owner-authorized facade for starting formal domain certificate enrollment.</summary>
public interface IDomainCertificateEnrollmentService
{
    Task<DomainCertificateEnrollmentStartResult> StartAsync(
        string ownerId,
        DomainCertificateEnrollmentStartRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Reuses website identity verification and atomically records certificate enrollment.</summary>
public sealed class DomainCertificateEnrollmentService(
    DomainRegistrationNormalizer normalizer,
    IWebsiteIdentityService websiteIdentityService,
    IDomainEnrollmentRepository enrollmentRepository,
    DomainCertificatePolicy policy,
    TimeProvider timeProvider) : IDomainCertificateEnrollmentService
{
    public async Task<DomainCertificateEnrollmentStartResult> StartAsync(
        string ownerId,
        DomainCertificateEnrollmentStartRequest request,
        CancellationToken cancellationToken)
    {
        string domain;
        string displayName;
        try
        {
            ValidateIdentifier(ownerId, 256);
            ArgumentNullException.ThrowIfNull(request);
            domain = normalizer.Normalize(request.Domain);
            displayName = request.DisplayName?.Trim() ?? string.Empty;
            if (displayName.Length is < 1 or > 200 || displayName.Any(char.IsControl) ||
                request.VerificationMethod != VerificationMethod.DnsTxt)
            {
                return Result(DomainCertificateEnrollmentStartStatus.InvalidRequest);
            }
        }
        catch (ArgumentException)
        {
            return Result(DomainCertificateEnrollmentStartStatus.InvalidRequest);
        }

        WebsiteIdentityRegistrationResponse website;
        try
        {
            website = await websiteIdentityService.RegisterAsync(
                new WebsiteIdentityRegistrationRequest(domain, displayName, request.VerificationMethod),
                ownerId,
                "Consumer",
                cancellationToken).ConfigureAwait(false);
        }
        catch (WebsiteIdentityRegistrationConflictException)
        {
            return Result(DomainCertificateEnrollmentStartStatus.Conflict);
        }
        catch (ArgumentException)
        {
            return Result(DomainCertificateEnrollmentStartStatus.InvalidRequest);
        }

        var now = timeProvider.GetUtcNow();
        var identity = Digest($"{ownerId}\n{domain}");
        var start = new DomainEnrollmentStartRecord(
            $"hip-enrollment-{identity}",
            ownerId,
            domain,
            DomainEnrollmentStatus.PendingOwnership,
            policy.Validate().Version,
            now,
            $"certificate-event:{Digest($"enrollment-start\n{identity}")}");
        DomainEnrollmentRepositoryWriteResult write;
        try
        {
            write = await enrollmentRepository.TryStartEnrollmentAsync(start, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateEnrollmentStartStatus.PersistenceUnavailable);
        }

        var status = write.Status switch
        {
            DomainEnrollmentRepositoryWriteStatus.Created => DomainCertificateEnrollmentStartStatus.Started,
            DomainEnrollmentRepositoryWriteStatus.ExistingSame => DomainCertificateEnrollmentStartStatus.Existing,
            _ => DomainCertificateEnrollmentStartStatus.Conflict
        };
        return new DomainCertificateEnrollmentStartResult(
            status,
            domain,
            website.VerificationRequest.Method,
            website.VerificationRequest.Token,
            website.VerificationRequest.ExpiresAtUtc);
    }

    private static string Digest(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static void ValidateIdentifier(string value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value.Any(char.IsControl))
        {
            throw new ArgumentException("Owner identifier is invalid.");
        }
    }

    private static DomainCertificateEnrollmentStartResult Result(DomainCertificateEnrollmentStartStatus status) =>
        new(status);
}
