using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using HIP.Application.Identity;
using HIP.Application.PublicLookup;
using HIP.Domain.Identity;
using HIP.Infrastructure.Security;

namespace HIP.Infrastructure.Identity;

public sealed record WellKnownHipDocumentFetchOptions(
    TimeSpan Timeout,
    int MaximumResponseBytes)
{
    public static WellKnownHipDocumentFetchOptions Default { get; } =
        new(TimeSpan.FromSeconds(10), 64 * 1024);

    public WellKnownHipDocumentFetchOptions Validate()
    {
        if (Timeout < TimeSpan.FromSeconds(1) || Timeout > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(Timeout));
        }
        if (MaximumResponseBytes is < 1024 or > 256 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumResponseBytes));
        }
        return this;
    }
}

/// <summary>
/// Fetches only the fixed HTTPS well-known path, pins the connection to prevalidated public IPs,
/// refuses redirects, and bounds response time and size to contain SSRF and resource-exhaustion risk.
/// </summary>
public sealed class SafeWellKnownHipDocumentFetcher(
    WellKnownHipDocumentFetchOptions? options = null) : IWellKnownHipDocumentFetcher
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 16,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
    private readonly WellKnownHipDocumentFetchOptions fetchOptions =
        (options ?? WellKnownHipDocumentFetchOptions.Default).Validate();

    public async Task<HipWellKnownDocument?> FetchAsync(
        string normalizedDomain,
        CancellationToken cancellationToken)
    {
        var domain = DomainInputValidator.ValidateAndNormalize(normalizedDomain);
        var addresses = await Dns.GetHostAddressesAsync(domain, cancellationToken).ConfigureAwait(false);
        if (addresses.Length == 0 || addresses.Any(address => !IsPublicAddress(address)))
        {
            return null;
        }

        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = fetchOptions.Timeout,
            ConnectCallback = async (context, token) =>
            {
                Exception? lastFailure = null;
                foreach (var address in addresses)
                {
                    var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), token)
                            .ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (Exception exception) when (exception is SocketException or OperationCanceledException)
                    {
                        socket.Dispose();
                        lastFailure = exception;
                        if (exception is OperationCanceledException && token.IsCancellationRequested)
                        {
                            throw;
                        }
                    }
                }

                throw new HttpRequestException("HIP could not connect to a validated public address.", lastFailure);
            }
        };
        using var client = new HttpClient(handler)
        {
            Timeout = fetchOptions.Timeout
        };
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            new UriBuilder(Uri.UriSchemeHttps, domain, -1, "/.well-known/hip.json").Uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("HIP-Domain-Verification/1.0");
        using var response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken)
            .ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK ||
            response.Content.Headers.ContentLength > fetchOptions.MaximumResponseBytes ||
            !IsJson(response.Content.Headers.ContentType?.MediaType))
        {
            return null;
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var bytes = await ReadBoundedAsync(stream, fetchOptions.MaximumResponseBytes, cancellationToken)
            .ConfigureAwait(false);
        return bytes is null
            ? null
            : JsonSerializer.Deserialize<HipWellKnownDocument>(bytes, JsonOptions);
    }

    public static bool IsPublicAddress(IPAddress address)
    {
        return PublicNetworkAddressPolicy.IsPublic(address);
    }

    private static bool IsJson(string? mediaType) =>
        string.Equals(mediaType, "application/json", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(mediaType, "application/hip+json", StringComparison.OrdinalIgnoreCase);

    private static async Task<byte[]?> ReadBoundedAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream(Math.Min(maximumBytes, 16 * 1024));
        var block = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(block.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return buffer.ToArray();
            }
            if (buffer.Length + read > maximumBytes)
            {
                return null;
            }
            buffer.Write(block, 0, read);
        }
    }
}
