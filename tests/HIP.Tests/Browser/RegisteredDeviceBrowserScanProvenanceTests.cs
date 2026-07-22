using HIP.Application.Browser;

namespace HIP.Tests.Browser;

[TestFixture]
public sealed class RegisteredDeviceBrowserScanProvenanceTests
{
    [Test]
    public void Registered_device_signature_is_distinct_from_server_authority()
    {
        var record = new BrowserScanResultRecord(
            "scan", "example.com", "sha256:value", null, "BrowserPlugin", 90, "Safe", "Safe",
            [], 1, 0, 0, 0, DateTimeOffset.UtcNow, "Allow",
            new Dictionary<string, string> { [BrowserScanResultProvenance.MetadataKey] = BrowserScanResultProvenance.RegisteredDevice });

        Assert.Multiple(() =>
        {
            Assert.That(BrowserScanResultProvenance.GetSubmissionTrust(record), Is.EqualTo("registered-device"));
            Assert.That(BrowserScanResultProvenance.IsServerAuthoritative(record), Is.False);
        });
    }
}
