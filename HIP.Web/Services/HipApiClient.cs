using System.Net.Http.Headers;
using System.Text;

namespace HIP.Web.Services;

public sealed class HipApiClient(IHttpClientFactory httpClientFactory, HipEnvelopeSigner signer)
{
    private const string IdentityId = "hip-system";
    private const string KeyId = "hip-system";

    public Task<(int Status, string Body)> GetAsync(string path, CancellationToken cancellationToken)
        => SendAsync(HttpMethod.Get, path, string.Empty, cancellationToken);

    private async Task<(int Status, string Body)> SendAsync(HttpMethod method, string path, string body, CancellationToken cancellationToken)
    {
        var client = httpClientFactory.CreateClient("hip-api");
        var envelope = signer.Build(IdentityId, KeyId, method.Method, path, body);

        using var request = new HttpRequestMessage(method, path);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Add("x-hip-origin", "bff");
        request.Headers.Add("x-hip-identity", IdentityId);
        request.Headers.Add("x-hip-key-id", KeyId);
        request.Headers.Add("x-hip-msg-id", envelope.MessageId);
        request.Headers.Add("x-hip-nonce", envelope.Nonce);
        request.Headers.Add("x-hip-issued-at", envelope.IssuedAtUtc.ToUnixTimeSeconds().ToString());
        request.Headers.Add("x-hip-expires-at", envelope.ExpiresAtUtc.ToUnixTimeSeconds().ToString());
        request.Headers.Add("x-hip-signature", envelope.SignatureBase64);

        if (!string.IsNullOrEmpty(body))
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        using var response = await client.SendAsync(request, cancellationToken);
        var payload = await response.Content.ReadAsStringAsync(cancellationToken);
        return ((int)response.StatusCode, payload);
    }
}
