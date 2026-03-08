namespace HIP.Security.Application.Policies.Internal;

public enum PolicyTransitionRejectReasonCode
{
    UnsupportedSourceState = 0,
    RequiresSimulationStage = 1,
    AutoPromotionDisallowed = 2,
    ApprovalMetadataRequired = 3,
    RollbackNotSupported = 4
}
