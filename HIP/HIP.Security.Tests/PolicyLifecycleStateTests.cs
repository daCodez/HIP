using HIP.Security.Domain.Policies;

namespace HIP.Security.Tests;

public class PolicyLifecycleStateTests
{
    [Test]
    public void LifecycleState_ShouldExposeExpectedOrder()
    {
        Assert.Multiple(() =>
        {
            Assert.That((int)PolicyLifecycleState.Draft, Is.EqualTo(0));
            Assert.That((int)PolicyLifecycleState.Simulate, Is.EqualTo(1));
            Assert.That((int)PolicyLifecycleState.Active, Is.EqualTo(2));
            Assert.That((int)PolicyLifecycleState.Disabled, Is.EqualTo(3));
            Assert.That((int)PolicyLifecycleState.Archived, Is.EqualTo(4));
        });
    }
}
