using HIP.Application.Dns;
using HIP.Infrastructure.Identity;

namespace HIP.Tests.Infrastructure;

/// <summary>Locks HIP's interpretation of evidence returned by its validating resolver.</summary>
public sealed class DnssecValidationClassificationTests
{
    [TestCase(false, true, 0, DnssecValidationStatus.Indeterminate)]
    [TestCase(true, true, 0, DnssecValidationStatus.Secure)]
    [TestCase(true, false, 0, DnssecValidationStatus.Insecure)]
    [TestCase(true, false, 3, DnssecValidationStatus.Insecure)]
    [TestCase(true, false, 2, DnssecValidationStatus.Indeterminate)]
    public void Resolver_evidence_is_classified_without_overclaiming(
        bool trusted,
        bool authenticData,
        int responseCode,
        DnssecValidationStatus expected)
    {
        var result = DnsClientLookupProvider.ClassifyDnssec(trusted, authenticData, responseCode, []);

        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void DNSSEC_extended_error_marks_the_answer_bogus()
    {
        var result = DnsClientLookupProvider.ClassifyDnssec(true, false, 2, [6]);

        Assert.That(result, Is.EqualTo(DnssecValidationStatus.Bogus));
    }

    [Test]
    public void Extended_error_parser_ignores_other_and_truncated_options()
    {
        byte[] payload = [0, 3, 0, 1, 99, 0, 15, 0, 2, 0, 9, 0, 15, 0, 5, 0];

        Assert.That(DnsClientLookupProvider.ReadExtendedDnsErrorCodes(payload), Is.EqualTo(new ushort[] { 9 }));
    }
}
