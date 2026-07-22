using System.Globalization;
using Microsoft.AspNetCore.Authentication;

namespace HIP.Web.Security;

/// <summary>
/// Stores server-created, state-protected metadata that binds an OIDC step-up callback to the current HIP session.
/// </summary>
public static class HipStepUpAuthenticationProperties
{
    private const string StepUpMarkerKey = ".hip.step_up.marker";
    private const string ExpectedActorIdKey = ".hip.step_up.expected_actor_id";
    private const string OriginalAbsoluteExpiryKey = ".hip.step_up.original_absolute_expires_utc_ticks";
    private const string StepUpMarkerValue = "true";
    private const int MaximumExpectedActorIdLength = 256;

    /// <summary>Marks authentication properties as a HIP step-up request.</summary>
    public static void SetStepUpMarker(AuthenticationProperties properties)
    {
        ArgumentNullException.ThrowIfNull(properties);
        properties.Items[StepUpMarkerKey] = StepUpMarkerValue;
    }

    /// <summary>Returns whether authentication properties contain HIP's exact protected step-up marker.</summary>
    public static bool IsStepUp(AuthenticationProperties properties)
    {
        ArgumentNullException.ThrowIfNull(properties);
        return properties.Items.TryGetValue(StepUpMarkerKey, out var marker) &&
               string.Equals(marker, StepUpMarkerValue, StringComparison.Ordinal);
    }

    /// <summary>Stores the HIP actor that must return from the step-up callback.</summary>
    public static void SetExpectedActorId(AuthenticationProperties properties, string expectedActorId)
    {
        ArgumentNullException.ThrowIfNull(properties);
        if (!IsValidExpectedActorId(expectedActorId))
        {
            throw new ArgumentException("Expected HIP actor ID must be bounded and nonblank.", nameof(expectedActorId));
        }

        properties.Items[ExpectedActorIdKey] = expectedActorId;
    }

    /// <summary>Reads the HIP actor that must return from the step-up callback.</summary>
    public static bool TryGetExpectedActorId(AuthenticationProperties properties, out string expectedActorId)
    {
        ArgumentNullException.ThrowIfNull(properties);
        if (properties.Items.TryGetValue(ExpectedActorIdKey, out var rawActorId) &&
            IsValidExpectedActorId(rawActorId))
        {
            expectedActorId = rawActorId!;
            return true;
        }

        expectedActorId = string.Empty;
        return false;
    }

    /// <summary>Stores the current session's hard expiry so step-up cannot extend it.</summary>
    public static void SetOriginalAbsoluteExpiry(
        AuthenticationProperties properties,
        DateTimeOffset originalAbsoluteExpiry)
    {
        ArgumentNullException.ThrowIfNull(properties);
        properties.Items[OriginalAbsoluteExpiryKey] =
            originalAbsoluteExpiry.UtcTicks.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>Reads the current session's hard expiry from protected step-up state.</summary>
    public static bool TryGetOriginalAbsoluteExpiry(
        AuthenticationProperties properties,
        out DateTimeOffset originalAbsoluteExpiry)
    {
        ArgumentNullException.ThrowIfNull(properties);
        if (properties.Items.TryGetValue(OriginalAbsoluteExpiryKey, out var rawValue) &&
            long.TryParse(rawValue, NumberStyles.None, CultureInfo.InvariantCulture, out var ticks) &&
            ticks >= DateTimeOffset.MinValue.Ticks &&
            ticks <= DateTimeOffset.MaxValue.Ticks)
        {
            originalAbsoluteExpiry = new DateTimeOffset(ticks, TimeSpan.Zero);
            return true;
        }

        originalAbsoluteExpiry = default;
        return false;
    }

    /// <summary>Removes all one-time step-up metadata before issuing a session cookie.</summary>
    public static void Clear(AuthenticationProperties properties)
    {
        ArgumentNullException.ThrowIfNull(properties);
        properties.Items.Remove(StepUpMarkerKey);
        properties.Items.Remove(ExpectedActorIdKey);
        properties.Items.Remove(OriginalAbsoluteExpiryKey);
    }

    private static bool IsValidExpectedActorId(string? actorId) =>
        !string.IsNullOrWhiteSpace(actorId) &&
        actorId.Length <= MaximumExpectedActorIdLength &&
        actorId.All(character => !char.IsControl(character));
}
