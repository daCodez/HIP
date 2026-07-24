using HIP.Domain.Certificates;

namespace HIP.Tests.Certificates;

/// <summary>Locks the formal enrollment and certificate state machines before persistence and UI are added.</summary>
public sealed class DomainCertificateLifecycleTests
{
    [TestCase(DomainEnrollmentStatus.Draft, DomainEnrollmentStatus.PendingOwnership)]
    [TestCase(DomainEnrollmentStatus.PendingOwnership, DomainEnrollmentStatus.OwnershipVerified)]
    [TestCase(DomainEnrollmentStatus.OwnershipVerified, DomainEnrollmentStatus.PendingSecurityReview)]
    [TestCase(DomainEnrollmentStatus.PendingSecurityReview, DomainEnrollmentStatus.Verified)]
    [TestCase(DomainEnrollmentStatus.Verified, DomainEnrollmentStatus.Monitored)]
    [TestCase(DomainEnrollmentStatus.Monitored, DomainEnrollmentStatus.Suspended)]
    [TestCase(DomainEnrollmentStatus.Suspended, DomainEnrollmentStatus.PendingSecurityReview)]
    public void Enrollment_allows_defined_forward_and_recovery_transitions(
        DomainEnrollmentStatus current,
        DomainEnrollmentStatus target)
    {
        Assert.That(DomainEnrollmentLifecycle.CanTransition(current, target), Is.True);
    }

    [TestCase(DomainEnrollmentStatus.Draft, DomainEnrollmentStatus.Monitored)]
    [TestCase(DomainEnrollmentStatus.PendingOwnership, DomainEnrollmentStatus.Verified)]
    [TestCase(DomainEnrollmentStatus.Revoked, DomainEnrollmentStatus.Draft)]
    public void Enrollment_rejects_skipped_or_terminal_transitions(
        DomainEnrollmentStatus current,
        DomainEnrollmentStatus target)
    {
        Assert.That(
            () => DomainEnrollmentLifecycle.RequireTransition(current, target),
            Throws.TypeOf<InvalidOperationException>());
    }

    [TestCase(DomainCertificateStatus.Draft, DomainCertificateStatus.PendingVerification)]
    [TestCase(DomainCertificateStatus.PendingVerification, DomainCertificateStatus.PendingReview)]
    [TestCase(DomainCertificateStatus.PendingVerification, DomainCertificateStatus.Active)]
    [TestCase(DomainCertificateStatus.PendingReview, DomainCertificateStatus.Active)]
    [TestCase(DomainCertificateStatus.Active, DomainCertificateStatus.Suspended)]
    [TestCase(DomainCertificateStatus.Active, DomainCertificateStatus.RenewalRequired)]
    [TestCase(DomainCertificateStatus.Active, DomainCertificateStatus.Expired)]
    [TestCase(DomainCertificateStatus.Suspended, DomainCertificateStatus.Active)]
    [TestCase(DomainCertificateStatus.RenewalRequired, DomainCertificateStatus.PendingVerification)]
    public void Certificate_allows_defined_lifecycle_transitions(
        DomainCertificateStatus current,
        DomainCertificateStatus target)
    {
        Assert.That(DomainCertificateLifecycle.CanTransition(current, target), Is.True);
    }

    [TestCase(DomainCertificateStatus.Draft, DomainCertificateStatus.Active)]
    [TestCase(DomainCertificateStatus.Expired, DomainCertificateStatus.Active)]
    [TestCase(DomainCertificateStatus.Revoked, DomainCertificateStatus.Active)]
    public void Certificate_rejects_skipped_or_terminal_transitions(
        DomainCertificateStatus current,
        DomainCertificateStatus target)
    {
        Assert.That(
            () => DomainCertificateLifecycle.RequireTransition(current, target),
            Throws.TypeOf<InvalidOperationException>());
    }

    [Test]
    public void Manual_suspension_or_revocation_requires_a_reason()
    {
        Assert.Multiple(() =>
        {
            Assert.That(
                () => DomainCertificateLifecycle.RequireReason(
                    DomainCertificateStatus.Suspended,
                    " "),
                Throws.TypeOf<ArgumentException>());
            Assert.That(
                () => DomainCertificateLifecycle.RequireReason(
                    DomainCertificateStatus.Revoked,
                    null),
                Throws.TypeOf<ArgumentException>());
            Assert.That(
                () => DomainCertificateLifecycle.RequireReason(
                    DomainCertificateStatus.Active,
                    null),
                Throws.Nothing);
        });
    }

    [Test]
    public void Versioned_policy_enforces_safe_bounded_values()
    {
        var policy = new DomainCertificatePolicy(
            "hip-domain-certificate-v1",
            TimeSpan.FromDays(90),
            TimeSpan.FromDays(365),
            TimeSpan.FromDays(7),
            70,
            5);

        Assert.That(policy.Validate(), Is.SameAs(policy));
        Assert.That(
            () => (policy with { MinimumMonitoredTrustScore = 101 }).Validate(),
            Throws.TypeOf<InvalidOperationException>());
    }
}
