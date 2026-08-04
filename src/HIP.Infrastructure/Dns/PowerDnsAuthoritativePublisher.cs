using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Dns;
using Microsoft.Extensions.Configuration;

namespace HIP.Infrastructure.AuthoritativeDns;

/// <summary>Validated private PowerDNS API configuration.</summary>
public sealed record PowerDnsAuthoritativeOptions(
    bool Enabled,
    Uri ApiBaseUri,
    string ApiKey,
    IReadOnlyCollection<string> NameServers)
{
    public const string SectionName = "AuthoritativeDns";

    /// <summary>Builds and validates the provider configuration without accepting arbitrary remote API destinations.</summary>
    public static PowerDnsAuthoritativeOptions FromConfiguration(IConfiguration configuration)
    {
        var section = configuration.GetSection(SectionName);
        var enabled = section.GetValue<bool>("Enabled");
        var rawUri = section["ApiBaseUrl"] ?? "http://powerdns:8081/api/v1/";
        var apiKey = section["ApiKey"] ?? string.Empty;
        var nameServers = section.GetSection("NameServers").Get<string[]>() ??
            ["ns1.guardwithhip.com.", "ns2.guardwithhip.com."];

        if (!Uri.TryCreate(rawUri, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttp ||
            (!uri.IsLoopback && uri.Host.Contains('.', StringComparison.Ordinal)))
        {
            throw new InvalidOperationException("AuthoritativeDns:ApiBaseUrl must use HTTP on a loopback or internal service hostname.");
        }

        if (enabled && (apiKey.Length < 32 || apiKey.Contains("replace", StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("AuthoritativeDns:ApiKey must contain at least 32 non-placeholder characters when authoritative DNS is enabled.");
        }

        var normalizedNameServers = nameServers
            .Select(NormalizeNameServer)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (normalizedNameServers.Length != 2)
        {
            throw new InvalidOperationException("AuthoritativeDns:NameServers must contain exactly two distinct public nameserver names.");
        }

        return new PowerDnsAuthoritativeOptions(enabled, uri, apiKey, normalizedNameServers);
    }

    private static string NormalizeNameServer(string nameServer)
    {
        var normalized = nameServer?.Trim().TrimEnd('.').ToLowerInvariant() ?? string.Empty;
        if (Uri.CheckHostName(normalized) != UriHostNameType.Dns)
        {
            throw new InvalidOperationException("Authoritative DNS nameserver names must be valid DNS hosts.");
        }

        return normalized + ".";
    }
}

/// <summary>
/// Publishes complete, prevalidated zone state to a private PowerDNS Authoritative API.
/// The API key never leaves the backend network and response bodies are not logged.
/// </summary>
public sealed class PowerDnsAuthoritativePublisher(
    HttpClient httpClient,
    PowerDnsAuthoritativeOptions options) : IAuthoritativeDnsPublisher
{
    private static readonly IReadOnlySet<string> ManagedTypes =
        new HashSet<string>(["A", "AAAA", "CNAME", "MX", "TXT"], StringComparer.Ordinal);

    /// <inheritdoc />
    public async Task<AuthoritativeDnsPublication> PublishAsync(
        string domain,
        IReadOnlyCollection<AuthoritativeDnsRecord> records,
        CancellationToken cancellationToken)
    {
        EnsureEnabled();
        var zoneId = domain + ".";
        var zonePath = ZonePath(zoneId);
        using var existingResponse = await SendAsync(HttpMethod.Get, zonePath, null, cancellationToken).ConfigureAwait(false);
        JsonDocument? existingZone = null;
        if (existingResponse.StatusCode == HttpStatusCode.NotFound)
        {
            using var createResponse = await SendAsync(
                HttpMethod.Post,
                "servers/localhost/zones",
                new
                {
                    name = zoneId,
                    kind = "Native",
                    dnssec = true,
                    api_rectify = true,
                    nameservers = options.NameServers
                },
                cancellationToken).ConfigureAwait(false);
            await RequireSuccessAsync(createResponse, "create the authoritative zone", cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await RequireSuccessAsync(existingResponse, "read the authoritative zone", cancellationToken).ConfigureAwait(false);
            existingZone = JsonDocument.Parse(await existingResponse.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false));
        }

        using (existingZone)
        {
            var changes = BuildRecordSetChanges(records, existingZone?.RootElement);
            if (changes.Count > 0)
            {
                using var patchResponse = await SendAsync(
                    HttpMethod.Patch,
                    zonePath,
                    new { rrsets = changes },
                    cancellationToken).ConfigureAwait(false);
                await RequireSuccessAsync(patchResponse, "publish authoritative DNS records", cancellationToken).ConfigureAwait(false);
            }
        }

        using (var rectifyResponse = await SendAsync(HttpMethod.Put, $"{zonePath}/rectify", new { }, cancellationToken).ConfigureAwait(false))
        {
            await RequireSuccessAsync(rectifyResponse, "rectify the DNSSEC zone", cancellationToken).ConfigureAwait(false);
        }

        var dsRecords = await ReadDsRecordsAsync(zonePath, cancellationToken).ConfigureAwait(false);
        return new AuthoritativeDnsPublication(options.NameServers, dsRecords);
    }

    /// <inheritdoc />
    public async Task DisableAsync(string domain, CancellationToken cancellationToken)
    {
        EnsureEnabled();
        using var response = await SendAsync(HttpMethod.Delete, ZonePath(domain + "."), null, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.NotFound)
        {
            await RequireSuccessAsync(response, "disable the authoritative zone", cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<IReadOnlyCollection<string>> ReadDsRecordsAsync(string zonePath, CancellationToken cancellationToken)
    {
        using var response = await SendAsync(HttpMethod.Get, $"{zonePath}/cryptokeys", null, cancellationToken).ConfigureAwait(false);
        await RequireSuccessAsync(response, "read DNSSEC delegation records", cancellationToken).ConfigureAwait(false);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false));
        var records = new HashSet<string>(StringComparer.Ordinal);
        var activeKeys = document.RootElement
            .EnumerateArray()
            .Where(key => key.TryGetProperty("active", out var active) && active.GetBoolean())
            .ToArray();
        foreach (var key in activeKeys)
        {
            if (AddDsRecords(key, records))
            {
                continue;
            }

            var keyId = key.GetProperty("id").GetInt32();
            using var keyResponse = await SendAsync(
                HttpMethod.Get,
                $"{zonePath}/cryptokeys/{keyId}/ds",
                null,
                cancellationToken).ConfigureAwait(false);
            await RequireSuccessAsync(keyResponse, "read a DNSSEC delegation record", cancellationToken).ConfigureAwait(false);
            using var keyDocument = JsonDocument.Parse(
                await keyResponse.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false));
            _ = AddDsRecords(keyDocument.RootElement, records);
        }

        return records.ToArray();
    }

    private static bool AddDsRecords(JsonElement key, HashSet<string> records)
    {
        if (!key.TryGetProperty("ds", out var ds) || ds.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (var value in ds.EnumerateArray())
        {
            var record = value.GetString();
            if (!string.IsNullOrWhiteSpace(record))
            {
                records.Add(record);
            }
        }

        return true;
    }

    private static IReadOnlyCollection<object> BuildRecordSetChanges(
        IReadOnlyCollection<AuthoritativeDnsRecord> records,
        JsonElement? existingZone)
    {
        var desired = records
            .GroupBy(record => new { record.Name, Type = ToPowerDnsType(record.Type) })
            .Select(group => new
            {
                name = group.Key.Name,
                type = group.Key.Type,
                ttl = group.First().Ttl,
                changetype = "REPLACE",
                records = group.Select(record => new { content = record.Content, disabled = false }).ToArray()
            })
            .Cast<object>()
            .ToList();

        if (existingZone is not { } zone || !zone.TryGetProperty("rrsets", out var rrsets))
        {
            return desired;
        }

        var desiredKeys = records
            .Select(record => $"{record.Name}\n{ToPowerDnsType(record.Type)}")
            .ToHashSet(StringComparer.Ordinal);
        foreach (var rrset in rrsets.EnumerateArray())
        {
            var name = rrset.GetProperty("name").GetString();
            var type = rrset.GetProperty("type").GetString();
            if (name is null || type is null || !ManagedTypes.Contains(type) || desiredKeys.Contains($"{name}\n{type}"))
            {
                continue;
            }

            desired.Add(new { name, type, changetype = "DELETE" });
        }

        return desired;
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, new Uri(options.ApiBaseUri, path));
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.Add("X-API-Key", options.ApiKey);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
    }

    private static async Task RequireSuccessAsync(
        HttpResponseMessage response,
        string operation,
        CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        _ = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        throw new InvalidOperationException($"The authoritative DNS provider could not {operation}.");
    }

    private void EnsureEnabled()
    {
        if (!options.Enabled)
        {
            throw new InvalidOperationException("Authoritative DNS publication is not enabled for this HIP environment.");
        }
    }

    private static string ZonePath(string zoneId) =>
        $"servers/localhost/zones/{Uri.EscapeDataString(zoneId)}";

    private static string ToPowerDnsType(AuthoritativeDnsRecordType type) => type switch
    {
        AuthoritativeDnsRecordType.A => "A",
        AuthoritativeDnsRecordType.Aaaa => "AAAA",
        AuthoritativeDnsRecordType.Cname => "CNAME",
        AuthoritativeDnsRecordType.Mx => "MX",
        AuthoritativeDnsRecordType.Txt => "TXT",
        _ => throw new InvalidOperationException("Unsupported authoritative DNS record type.")
    };
}
