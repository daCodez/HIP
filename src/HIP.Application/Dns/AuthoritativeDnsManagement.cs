using System.Globalization;
using System.Net;
using System.Net.Sockets;
using HIP.Application.Certificates;
using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Certificates;
using HIP.Domain.Review;

namespace HIP.Application.Dns;

/// <summary>Record types accepted by HIP's first authoritative DNS management milestone.</summary>
public enum AuthoritativeDnsRecordType
{
    A,
    Aaaa,
    Cname,
    Mx,
    Txt
}

/// <summary>Lifecycle state of one HIP-hosted authoritative zone.</summary>
public enum AuthoritativeDnsZoneStatus
{
    PendingPublication,
    Published,
    PublicationFailed,
    Disabled
}

/// <summary>One normalized DNS record set member managed by HIP.</summary>
public sealed record AuthoritativeDnsRecord(
    string Name,
    AuthoritativeDnsRecordType Type,
    string Content,
    int Ttl);

/// <summary>Persisted desired and published state for an authoritative DNS zone.</summary>
public sealed record AuthoritativeDnsZone(
    string Domain,
    long Version,
    AuthoritativeDnsZoneStatus Status,
    bool DnssecEnabled,
    IReadOnlyCollection<string> NameServers,
    IReadOnlyCollection<string> DsRecords,
    IReadOnlyCollection<AuthoritativeDnsRecord> Records,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    string UpdatedBy,
    string? SafeStatusDetail);

/// <summary>Admin input for one DNS record.</summary>
public sealed record AuthoritativeDnsRecordInput(
    string Name,
    AuthoritativeDnsRecordType Type,
    string Content,
    int Ttl = 300);

/// <summary>Admin request to create or replace a complete authoritative zone.</summary>
public sealed record PublishAuthoritativeDnsZoneRequest(
    string Domain,
    IReadOnlyCollection<AuthoritativeDnsRecordInput> Records,
    string Reason);

/// <summary>Result returned by an authoritative DNS provider after publication.</summary>
public sealed record AuthoritativeDnsPublication(
    IReadOnlyCollection<string> NameServers,
    IReadOnlyCollection<string> DsRecords);

/// <summary>Durable boundary for authoritative zone management state.</summary>
public interface IAuthoritativeDnsZoneRepository
{
    Task<AuthoritativeDnsZone?> GetAsync(string domain, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<AuthoritativeDnsZone>> ListAsync(CancellationToken cancellationToken);
    Task<bool> TrySaveAsync(AuthoritativeDnsZone zone, long expectedVersion, CancellationToken cancellationToken);
}

/// <summary>Internal provider boundary used to publish validated zones to the authoritative DNS service.</summary>
public interface IAuthoritativeDnsPublisher
{
    Task<AuthoritativeDnsPublication> PublishAsync(
        string domain,
        IReadOnlyCollection<AuthoritativeDnsRecord> records,
        CancellationToken cancellationToken);

    Task DisableAsync(string domain, CancellationToken cancellationToken);
}

/// <summary>Admin-only authoritative DNS management operations.</summary>
public interface IAuthoritativeDnsManagementService
{
    Task<IReadOnlyCollection<AuthoritativeDnsZone>> ListAsync(CancellationToken cancellationToken);

    Task<AuthoritativeDnsZone> PublishAsync(
        PublishAuthoritativeDnsZoneRequest request,
        string actorId,
        CancellationToken cancellationToken);

    Task<AuthoritativeDnsZone?> DisableAsync(
        string domain,
        string reason,
        string actorId,
        CancellationToken cancellationToken);
}

/// <summary>
/// Validates complete-zone replacements, requires prior HIP domain verification, and publishes through an isolated provider.
/// </summary>
public sealed class AuthoritativeDnsManagementService(
    IAuthoritativeDnsZoneRepository repository,
    IAuthoritativeDnsPublisher publisher,
    IDomainCertificateAdminQuery certificateQuery,
    DomainRegistrationNormalizer domainNormalizer,
    IAuditLogService auditLog,
    TimeProvider timeProvider) : IAuthoritativeDnsManagementService
{
    private const int MaximumRecordsPerZone = 100;

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<AuthoritativeDnsZone>> ListAsync(CancellationToken cancellationToken) =>
        (await repository.ListAsync(cancellationToken).ConfigureAwait(false))
        .OrderBy(zone => zone.Domain, StringComparer.Ordinal)
        .ToArray();

    /// <inheritdoc />
    public async Task<AuthoritativeDnsZone> PublishAsync(
        PublishAuthoritativeDnsZoneRequest request,
        string actorId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var domain = domainNormalizer.Normalize(request.Domain);
        var actor = NormalizeActor(actorId);
        var reason = NormalizeReason(request.Reason);
        var records = NormalizeRecords(domain, request.Records);
        await RequireVerifiedDomainAsync(domain, cancellationToken).ConfigureAwait(false);

        var existing = await repository.GetAsync(domain, cancellationToken).ConfigureAwait(false);
        if (existing?.Status == AuthoritativeDnsZoneStatus.PendingPublication)
        {
            throw new InvalidOperationException("This zone already has a publication in progress.");
        }

        var now = timeProvider.GetUtcNow();
        var pending = new AuthoritativeDnsZone(
            domain,
            (existing?.Version ?? 0) + 1,
            AuthoritativeDnsZoneStatus.PendingPublication,
            DnssecEnabled: true,
            existing?.NameServers ?? [],
            existing?.DsRecords ?? [],
            records,
            existing?.CreatedAtUtc ?? now,
            now,
            actor,
            "Publication is in progress.");
        if (!await repository.TrySaveAsync(pending, existing?.Version ?? 0, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("The zone changed before publication started. Refresh and review its current records.");
        }

        AuthoritativeDnsPublication publication;
        try
        {
            publication = await publisher.PublishAsync(domain, records, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            var failed = pending with
            {
                Version = pending.Version + 1,
                Status = AuthoritativeDnsZoneStatus.PublicationFailed,
                UpdatedAtUtc = timeProvider.GetUtcNow(),
                SafeStatusDetail = "The authoritative DNS provider rejected or could not complete publication."
            };
            _ = await repository.TrySaveAsync(failed, pending.Version, cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException(failed.SafeStatusDetail, exception);
        }

        var published = pending with
        {
            Version = pending.Version + 1,
            Status = AuthoritativeDnsZoneStatus.Published,
            NameServers = publication.NameServers,
            DsRecords = publication.DsRecords,
            UpdatedAtUtc = timeProvider.GetUtcNow(),
            SafeStatusDetail = "The authoritative zone is published. Registrar delegation may still be required."
        };
        if (!await repository.TrySaveAsync(published, pending.Version, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("The zone was published, but HIP could not finalize its local state. Refresh before retrying.");
        }
        await WriteAuditAsync(actor, domain, "AuthoritativeDns.ZonePublished", reason, records.Count, cancellationToken)
            .ConfigureAwait(false);
        return published;
    }

    /// <inheritdoc />
    public async Task<AuthoritativeDnsZone?> DisableAsync(
        string domain,
        string reason,
        string actorId,
        CancellationToken cancellationToken)
    {
        var normalizedDomain = domainNormalizer.Normalize(domain);
        var normalizedReason = NormalizeReason(reason);
        var actor = NormalizeActor(actorId);
        var existing = await repository.GetAsync(normalizedDomain, cancellationToken).ConfigureAwait(false);
        if (existing is null)
        {
            return null;
        }

        await publisher.DisableAsync(normalizedDomain, cancellationToken).ConfigureAwait(false);
        var disabled = existing with
        {
            Version = existing.Version + 1,
            Status = AuthoritativeDnsZoneStatus.Disabled,
            Records = [],
            UpdatedAtUtc = timeProvider.GetUtcNow(),
            UpdatedBy = actor,
            SafeStatusDetail = "The zone is disabled at the authoritative provider."
        };
        if (!await repository.TrySaveAsync(disabled, existing.Version, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("The zone changed before it could be disabled. Refresh and review its current state.");
        }
        await WriteAuditAsync(actor, normalizedDomain, "AuthoritativeDns.ZoneDisabled", normalizedReason, 0, cancellationToken)
            .ConfigureAwait(false);
        return disabled;
    }

    private async Task RequireVerifiedDomainAsync(string domain, CancellationToken cancellationToken)
    {
        const int pageSize = 100;
        for (var offset = 0; offset < 1000; offset += pageSize)
        {
            var page = await certificateQuery.ListForAdminAsync(offset, pageSize, cancellationToken).ConfigureAwait(false);
            var match = page.SingleOrDefault(item => string.Equals(item.Domain, domain, StringComparison.Ordinal));
            if (match is not null)
            {
                if (match.EnrollmentStatus is DomainEnrollmentStatus.OwnershipVerified
                    or DomainEnrollmentStatus.PendingSecurityReview
                    or DomainEnrollmentStatus.Verified
                    or DomainEnrollmentStatus.Monitored)
                {
                    return;
                }

                throw new InvalidOperationException("HIP must verify domain ownership before authoritative DNS can be published.");
            }

            if (page.Count < pageSize)
            {
                break;
            }
        }

        throw new InvalidOperationException("HIP must verify domain ownership before authoritative DNS can be published.");
    }

    private static IReadOnlyCollection<AuthoritativeDnsRecord> NormalizeRecords(
        string domain,
        IReadOnlyCollection<AuthoritativeDnsRecordInput>? inputs)
    {
        if (inputs is null || inputs.Count == 0 || inputs.Count > MaximumRecordsPerZone)
        {
            throw new ArgumentException($"A zone must contain between 1 and {MaximumRecordsPerZone} managed records.", nameof(inputs));
        }

        var records = inputs.Select(input => NormalizeRecord(domain, input)).ToArray();
        if (records.Distinct().Count() != records.Length)
        {
            throw new ArgumentException("Duplicate DNS records are not allowed.", nameof(inputs));
        }

        foreach (var group in records.GroupBy(record => record.Name, StringComparer.Ordinal))
        {
            if (group.Any(record => record.Type == AuthoritativeDnsRecordType.Cname) && group.Count() != 1)
            {
                throw new ArgumentException("A CNAME name cannot contain any other DNS records.", nameof(inputs));
            }
        }

        if (records.GroupBy(record => new { record.Name, record.Type }).Any(group => group.Select(record => record.Ttl).Distinct().Count() != 1))
        {
            throw new ArgumentException("Records with the same name and type must use one TTL.", nameof(inputs));
        }

        return records;
    }

    private static AuthoritativeDnsRecord NormalizeRecord(string domain, AuthoritativeDnsRecordInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (input.Ttl is < 60 or > 86400)
        {
            throw new ArgumentException("DNS TTL must be between 60 and 86400 seconds.", nameof(input));
        }

        var name = NormalizeRecordName(domain, input.Name);
        var content = input.Type switch
        {
            AuthoritativeDnsRecordType.A => NormalizeAddress(input.Content, AddressFamily.InterNetwork),
            AuthoritativeDnsRecordType.Aaaa => NormalizeAddress(input.Content, AddressFamily.InterNetworkV6),
            AuthoritativeDnsRecordType.Cname => NormalizeTarget(input.Content),
            AuthoritativeDnsRecordType.Mx => NormalizeMx(input.Content),
            AuthoritativeDnsRecordType.Txt => NormalizeTxt(input.Content),
            _ => throw new ArgumentException("Unsupported authoritative DNS record type.", nameof(input))
        };

        if (input.Type == AuthoritativeDnsRecordType.Cname && string.Equals(name, domain + ".", StringComparison.Ordinal))
        {
            throw new ArgumentException("The zone apex cannot be a CNAME record.", nameof(input));
        }

        return new AuthoritativeDnsRecord(name, input.Type, content, input.Ttl);
    }

    private static string NormalizeRecordName(string domain, string rawName)
    {
        if (string.IsNullOrWhiteSpace(rawName) || rawName.Any(char.IsControl))
        {
            throw new ArgumentException("A DNS record name is required.", nameof(rawName));
        }

        var candidate = rawName.Trim().TrimEnd('.').ToLowerInvariant();
        if (candidate == "@")
        {
            return domain + ".";
        }

        var fqdn = candidate.Contains('.') ? candidate : $"{candidate}.{domain}";
        if (fqdn.Contains('*', StringComparison.Ordinal) ||
            (!string.Equals(fqdn, domain, StringComparison.Ordinal) &&
             !fqdn.EndsWith('.' + domain, StringComparison.Ordinal)))
        {
            throw new ArgumentException("DNS record names must remain inside the verified zone and cannot be wildcards.", nameof(rawName));
        }

        ValidateDnsName(fqdn);
        return fqdn + ".";
    }

    private static string NormalizeAddress(string content, AddressFamily family)
    {
        if (!IPAddress.TryParse(content?.Trim(), out var address) || address.AddressFamily != family)
        {
            throw new ArgumentException(family == AddressFamily.InterNetwork ? "An IPv4 address is required." : "An IPv6 address is required.", nameof(content));
        }

        return address.ToString();
    }

    private static string NormalizeTarget(string content)
    {
        var target = content?.Trim().TrimEnd('.').ToLowerInvariant() ?? string.Empty;
        ValidateDnsName(target);
        return target + ".";
    }

    private static string NormalizeMx(string content)
    {
        var parts = (content ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || !ushort.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var preference))
        {
            throw new ArgumentException("MX content must use the format 'priority mail.example.com'.", nameof(content));
        }

        return $"{preference.ToString(CultureInfo.InvariantCulture)} {NormalizeTarget(parts[1])}";
    }

    private static string NormalizeTxt(string content)
    {
        var text = content?.Trim() ?? string.Empty;
        if (text.Length is < 1 or > 255 || text.Any(char.IsControl))
        {
            throw new ArgumentException("TXT content must contain 1 to 255 printable characters.", nameof(content));
        }

        return $"\"{text.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal)}\"";
    }

    private static void ValidateDnsName(string name)
    {
        if (name.Length is < 1 or > 253 || Uri.CheckHostName(name) != UriHostNameType.Dns)
        {
            throw new ArgumentException("A valid public DNS name is required.", nameof(name));
        }
    }

    private static string NormalizeReason(string reason)
    {
        var normalized = reason?.Trim() ?? string.Empty;
        if (normalized.Length is < 5 or > 500 || normalized.Any(char.IsControl))
        {
            throw new ArgumentException("A privacy-safe reason of 5 to 500 characters is required.", nameof(reason));
        }

        return normalized;
    }

    private static string NormalizeActor(string actorId)
    {
        var normalized = actorId?.Trim() ?? string.Empty;
        if (normalized.Length is < 1 or > 160 || normalized.Any(char.IsControl))
        {
            throw new ArgumentException("An authenticated admin actor is required.", nameof(actorId));
        }

        return normalized;
    }

    private Task WriteAuditAsync(
        string actor,
        string domain,
        string action,
        string reason,
        int recordCount,
        CancellationToken cancellationToken) =>
        auditLog.WriteAsync(
            actor,
            action,
            TargetType.Domain,
            domain,
            reason,
            AuditSeverity.High,
            cancellationToken,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["recordCount"] = recordCount.ToString(CultureInfo.InvariantCulture),
                ["dnssecEnabled"] = "true"
            },
            actorRole: "Owner");

}
