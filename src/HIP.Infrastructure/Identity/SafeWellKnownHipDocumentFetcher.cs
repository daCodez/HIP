using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using HIP.Application.Identity;
using HIP.Application.PublicLookup;
using HIP.Domain.Identity;
using HIP.Infrastructure.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

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

/// <summary>Resolves the claimed domain before HIP opens a verification connection.</summary>
public interface IWellKnownHostAddressResolver
{
    Task<IReadOnlyCollection<IPAddress>> ResolveAsync(string domain, CancellationToken cancellationToken);
}

/// <summary>System DNS resolver used by production well-known verification.</summary>
public sealed class SystemWellKnownHostAddressResolver : IWellKnownHostAddressResolver
{
    public async Task<IReadOnlyCollection<IPAddress>> ResolveAsync(
        string domain,
        CancellationToken cancellationToken) =>
        await Dns.GetHostAddressesAsync(domain, cancellationToken).ConfigureAwait(false);
}

/// <summary>Creates an HTTP handler whose sockets are pinned to a prevalidated address set.</summary>
public interface IWellKnownHttpMessageHandlerFactory
{
    HttpMessageHandler Create(IReadOnlyCollection<IPAddress> approvedAddresses, TimeSpan connectTimeout);
}

/// <summary>Production handler factory that prevents redirects, proxies, cookies, and DNS re-resolution.</summary>
public sealed class PinnedWellKnownHttpMessageHandlerFactory : IWellKnownHttpMessageHandlerFactory
{
    public HttpMessageHandler Create(
        IReadOnlyCollection<IPAddress> approvedAddresses,
        TimeSpan connectTimeout)
    {
        ArgumentNullException.ThrowIfNull(approvedAddresses);
        var pinnedAddresses = approvedAddresses.ToArray();
        if (pinnedAddresses.Length == 0 || pinnedAddresses.Any(address => !PublicNetworkAddressPolicy.IsPublic(address)))
        {
            throw new ArgumentException("At least one validated public address is required.", nameof(approvedAddresses));
        }

        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = connectTimeout,
            Credentials = null,
            MaxConnectionsPerServer = 1,
            MaxResponseHeadersLength = 16,
            PreAuthenticate = false,
            UseCookies = false,
            UseProxy = false,
            ConnectCallback = async (context, token) =>
            {
                if (context.DnsEndPoint.Port != 443)
                {
                    throw new HttpRequestException("HIP well-known verification permits HTTPS port 443 only.");
                }

                Exception? lastFailure = null;
                foreach (var address in pinnedAddresses)
                {
                    var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(address, 443), token).ConfigureAwait(false);
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
    }
}

/// <summary>
/// Fetches only the fixed HTTPS well-known path, pins the connection to prevalidated public IPs,
/// refuses redirects, and bounds response time and size to contain SSRF and resource-exhaustion risk.
/// </summary>
public sealed class SafeWellKnownHipDocumentFetcher(
    WellKnownHipDocumentFetchOptions? options = null,
    IWellKnownHostAddressResolver? addressResolver = null,
    IWellKnownHttpMessageHandlerFactory? handlerFactory = null,
    ILogger<SafeWellKnownHipDocumentFetcher>? logger = null) : IWellKnownHipDocumentFetcher
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 16,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
    private readonly IWellKnownHostAddressResolver resolver =
        addressResolver ?? new SystemWellKnownHostAddressResolver();
    private readonly IWellKnownHttpMessageHandlerFactory handlers =
        handlerFactory ?? new PinnedWellKnownHttpMessageHandlerFactory();
    private readonly WellKnownHipDocumentFetchOptions fetchOptions =
        (options ?? WellKnownHipDocumentFetchOptions.Default).Validate();
    private readonly ILogger<SafeWellKnownHipDocumentFetcher> log =
        logger ?? NullLogger<SafeWellKnownHipDocumentFetcher>.Instance;

    public async Task<HipWellKnownDocument?> FetchAsync(
        string normalizedDomain,
        CancellationToken cancellationToken)
    {
        var domain = DomainInputValidator.ValidateAndNormalize(normalizedDomain);
        var addresses = await ResolveAddressesAsync(domain, cancellationToken).ConfigureAwait(false);
        if (addresses is null || addresses.Length == 0 || addresses.Any(address => !IsPublicAddress(address)))
        {
            log.LogWarning("HIP well-known verification rejected an unsafe or empty DNS result for {Domain}.", domain);
            return null;
        }

        using var handler = handlers.Create(addresses, fetchOptions.Timeout);
        using var client = new HttpClient(handler)
        {
            Timeout = fetchOptions.Timeout
        };
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            new UriBuilder(Uri.UriSchemeHttps, domain, -1, "/.well-known/hip.json").Uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("HIP-Domain-Verification/1.0");
        using var response = await SendAsync(client, request, domain, cancellationToken).ConfigureAwait(false);
        if (response is null)
        {
            return null;
        }
        if (response.StatusCode != HttpStatusCode.OK ||
            response.Content.Headers.ContentLength > fetchOptions.MaximumResponseBytes ||
            !IsJson(response.Content.Headers.ContentType?.MediaType))
        {
            log.LogInformation("HIP well-known verification rejected the response metadata for {Domain}.", domain);
            return null;
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var bytes = await ReadBoundedAsync(stream, fetchOptions.MaximumResponseBytes, cancellationToken)
            .ConfigureAwait(false);
        if (bytes is null)
        {
            log.LogWarning("HIP well-known verification rejected an oversized response for {Domain}.", domain);
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<HipWellKnownDocument>(bytes, JsonOptions);
        }
        catch (JsonException exception)
        {
            log.LogWarning(exception, "HIP well-known verification rejected malformed JSON for {Domain}.", domain);
            return null;
        }
    }

    private async Task<IPAddress[]?> ResolveAddressesAsync(
        string domain,
        CancellationToken cancellationToken)
    {
        try
        {
            return (await resolver.ResolveAsync(domain, cancellationToken).ConfigureAwait(false)).ToArray();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            log.LogWarning(exception, "HIP well-known DNS resolution failed for {Domain}.", domain);
            return null;
        }
    }

    private async Task<HttpResponseMessage?> SendAsync(
        HttpClient client,
        HttpRequestMessage request,
        string domain,
        CancellationToken cancellationToken)
    {
        try
        {
            return await client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            log.LogWarning(exception, "HIP well-known HTTPS retrieval failed for {Domain}.", domain);
            return null;
        }
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
