namespace HIP.Agent.Worker;

public sealed class AgentOptions
{
    public const string SectionName = "Agent";

    public string BaseUrl { get; set; } = "http://localhost:5000";

    public string EnrollmentPath { get; set; } = "/api/agent/enroll";

    public string HeartbeatPath { get; set; } = "/api/agent/heartbeat";

    public int HeartbeatIntervalSeconds { get; set; } = 30;

    public string DeviceId { get; set; } = Environment.MachineName;

    public string? DeviceName { get; set; } = Environment.MachineName;

    public string EnrollmentToken { get; set; } = "REPLACE_WITH_ENROLLMENT_TOKEN";

    public string CredentialStorePath { get; set; } = "";
}
