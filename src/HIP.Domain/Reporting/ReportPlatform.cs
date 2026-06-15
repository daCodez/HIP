namespace HIP.Domain.Reporting;

/// <summary>
/// Identifies the platform context for a privacy-safe HIP report.
/// </summary>
public enum ReportPlatform
{
    /// <summary>
    /// Platform was not provided or could not be safely classified.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Browser or website-originated report.
    /// </summary>
    Web = 1,

    /// <summary>
    /// Second Life HUD or Second Life platform report.
    /// </summary>
    SecondLife = 2,

    /// <summary>
    /// Email-originated report.
    /// </summary>
    Email = 3,

    /// <summary>
    /// Generic chat-originated report when the specific chat platform is unknown.
    /// </summary>
    Chat = 4,

    /// <summary>
    /// Social platform report.
    /// </summary>
    Social = 5,

    /// <summary>
    /// Application-originated report.
    /// </summary>
    App = 6,

    /// <summary>
    /// File or download-originated report.
    /// </summary>
    FileDownload = 7,

    /// <summary>
    /// Discord-originated report using privacy-safe sender hashes and URL/domain evidence only.
    /// </summary>
    Discord = 8
}
