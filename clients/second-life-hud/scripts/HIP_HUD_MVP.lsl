// HIP_HUD_MVP.lsl
// Second Life HUD MVP client for HIP.
//
// HIP is the product. This HUD is only a privacy-safe client that sends
// suspicious link signals to HIP and warns the owner.
//
// Important LSL limitation:
// - This script can listen to nearby/local chat on channels it listens to.
// - It cannot reliably inspect every group chat, private IM, or viewer-click flow.
// - Private IM support requires user/viewer interaction or a separate relay.
// - The HUD warns and routes to HIP safety pages; it cannot enforce browser-style blocking.

string HIP_API_BASE_URL = "https://your-hip-host.example.com";
string HIP_SETUP_CODE = "HIP-DEV-SETUP";
string HIP_HUD_DEVICE_ID = "";
string HIP_HUD_VERSION = "0.1.0";
string HIP_MODE = "Normal"; // Quiet, Normal, Strict, Paranoid.
integer HIP_POPUP_ALERTS_ENABLED = TRUE;
integer HIP_PRIVATE_WARNINGS_ENABLED = TRUE;
integer HIP_SAFETY_ROUTING_ENABLED = TRUE;
integer HIP_DEBUG = FALSE;

integer HIP_DIALOG_CHANNEL = -738412;
integer gListenHandle;
integer gDialogListenHandle;
integer gActivated = FALSE;
string gLicenseStatus = "Inactive";
string gLastRisk = "Low";
string gLastScan = "Starting";
string gPendingSafetyPageUrl = "";
string gPendingRiskReason = "";
string gPendingRiskUrl = "";
string gPendingSenderHash = "";

key gActivateRequest;
key gScanRequest;
key gSettingsGetRequest;
key gSettingsSaveRequest;
key gReportRequest;

default
{
    state_entry()
    {
        if (HIP_HUD_DEVICE_ID == "")
        {
            HIP_HUD_DEVICE_ID = "sl-hud-" + llGetSubString(llSHA256String((string)llGetOwner()), 0, 11);
        }

        gListenHandle = llListen(0, "", NULL_KEY, "");
        gDialogListenHandle = llListen(HIP_DIALOG_CHANNEL, "", llGetOwner(), "");
        UpdateHudStatus("Starting", "Low");
        ActivateHud();
    }

    changed(integer change)
    {
        if (change & CHANGED_OWNER)
        {
            llResetScript();
        }
    }

    listen(integer channel, string name, key id, string message)
    {
        if (channel == HIP_DIALOG_CHANNEL)
        {
            if (message == "Open Safety" && gPendingSafetyPageUrl != "")
            {
                llLoadURL(llGetOwner(), "Open the HIP safety page for this suspicious link.", AbsoluteHipUrl(gPendingSafetyPageUrl));
            }
            return;
        }

        if (!gActivated)
        {
            return;
        }

        ScanLocalChat(name, id, message);
    }

    touch_start(integer totalNumber)
    {
        llOwnerSay("HIP Shield status: " + gLicenseStatus + " | Mode: " + HIP_MODE + " | Last risk: " + gLastRisk);
        LoadSettings();
    }

    http_response(key requestId, integer status, list metadata, string body)
    {
        if (HIP_DEBUG)
        {
            llOwnerSay("HIP HTTP " + (string)status + ": " + llGetSubString(body, 0, 220));
        }

        if (requestId == gActivateRequest)
        {
            HandleActivationResponse(status, body);
            return;
        }

        if (requestId == gSettingsGetRequest || requestId == gSettingsSaveRequest)
        {
            HandleSettingsResponse(status, body);
            return;
        }

        if (requestId == gScanRequest)
        {
            HandleScanResponse(status, body);
            return;
        }

        if (requestId == gReportRequest && status >= 200 && status < 300)
        {
            if (HIP_DEBUG)
            {
                llOwnerSay("HIP report accepted.");
            }
        }
    }
}

// Activates the HUD with HIP using a setup code rather than web login.
ActivateHud()
{
    string payload = "{" +
        JsonPair("setupCode", HIP_SETUP_CODE) + "," +
        JsonPair("hudDeviceId", HIP_HUD_DEVICE_ID) + "," +
        JsonPair("avatarIdHash", OwnerHash()) + "," +
        JsonPair("hudVersion", HIP_HUD_VERSION) +
        "}";

    gActivateRequest = llHTTPRequest(HIP_API_BASE_URL + "/api/v1/sl-hud/activate",
        [HTTP_METHOD, "POST", HTTP_MIMETYPE, "application/json"],
        payload);
}

// Loads device-specific settings from HIP when the owner touches the HUD.
LoadSettings()
{
    gSettingsGetRequest = llHTTPRequest(HIP_API_BASE_URL + "/api/v1/sl-hud/settings/" + llEscapeURL(HIP_HUD_DEVICE_ID),
        [HTTP_METHOD, "GET"],
        "");
}

// Saves the current local HUD settings back to HIP.
SaveSettings()
{
    if (!IsValidMode(HIP_MODE))
    {
        llOwnerSay("HIP settings not saved: invalid mode " + HIP_MODE + ".");
        return;
    }

    string payload = "{" +
        JsonPair("deviceId", HIP_HUD_DEVICE_ID) + "," +
        JsonPair("mode", HIP_MODE) + "," +
        JsonBoolPair("popupAlertsEnabled", HIP_POPUP_ALERTS_ENABLED) + "," +
        JsonBoolPair("privateWarningsEnabled", HIP_PRIVATE_WARNINGS_ENABLED) + "," +
        JsonBoolPair("safetyRoutingEnabled", HIP_SAFETY_ROUTING_ENABLED) +
        "}";

    gSettingsSaveRequest = llHTTPRequest(HIP_API_BASE_URL + "/api/v1/sl-hud/settings/" + llEscapeURL(HIP_HUD_DEVICE_ID),
        [HTTP_METHOD, "POST", HTTP_MIMETYPE, "application/json"],
        payload);
}

// Scans local chat. LSL cannot guarantee access to all group or private IM content.
ScanLocalChat(string senderName, key senderId, string message)
{
    if (!ShouldScanMessage(message))
    {
        UpdateHudStatus("Safe", "Low");
        return;
    }

    string url = HipNormalizeUrl(HipExtractBestEffortUrl(message));
    if (url == "" && HipLooksBrokenUp(message))
    {
        url = HipReconstructBrokenUpUrl(message);
    }

    gPendingRiskUrl = url;
    gPendingSenderHash = llSHA256String((string)senderId);

    string payload = "{" +
        JsonPair("deviceId", HIP_HUD_DEVICE_ID) + "," +
        JsonPair("source", "LocalChat") + "," +
        JsonPair("messageText", LimitedSuspiciousSnippet(message)) + "," +
        "\"detectedUrls\":[" + JsonString(url) + "]," +
        JsonPair("senderHash", gPendingSenderHash) +
        "}";

    gPendingRiskReason = HipRiskReason(message);
    gScanRequest = llHTTPRequest(HIP_API_BASE_URL + "/api/v1/sl-hud/scan",
        [HTTP_METHOD, "POST", HTTP_MIMETYPE, "application/json"],
        payload);
}

// Sends a privacy-safe finding report after HIP confirms a risky scan.
ReportFinding(string senderHash, string risk, string reason, string url)
{
    string domain = BestEffortDomain(url);
    string payload = "{" +
        JsonPair("hudDeviceId", HIP_HUD_DEVICE_ID) + "," +
        JsonPair("avatarHash", OwnerHash()) + "," +
        JsonPair("domain", domain) + "," +
        JsonPair("riskyUrl", url) + "," +
        JsonPair("urlHash", llSHA256String(url)) + "," +
        JsonPair("senderHash", senderHash) + "," +
        JsonPair("riskLevel", ApiRiskLevel(risk)) + "," +
        JsonPair("reason", reason) + "," +
        JsonPair("detectedAtUtc", llGetTimestamp()) + "," +
        JsonPair("hipSignature", "sl-hud-signature-placeholder") +
        "}";

    gReportRequest = llHTTPRequest(HIP_API_BASE_URL + "/api/v1/sl-hud/report",
        [HTTP_METHOD, "POST", HTTP_MIMETYPE, "application/json"],
        payload);
}

// Handles activation results and loads remote settings after a successful activation.
HandleActivationResponse(integer status, string body)
{
    if (status >= 200 && status < 300 && ~llSubStringIndex(body, "\"activated\":true"))
    {
        gActivated = TRUE;
        gLicenseStatus = JsonValue(body, "licenseStatus", "DevelopmentActive");
        llOwnerSay("HIP Shield: Active. License: " + gLicenseStatus + ".");
        UpdateHudStatus("Safe", "Low");
        LoadSettings();
        return;
    }

    gActivated = FALSE;
    gLicenseStatus = "Inactive";
    UpdateHudStatus("Activation failed", "Low");
    llOwnerSay("HIP Shield activation failed. Check setup code/license key.");
}

// Handles settings responses using conservative defaults when fields are absent.
HandleSettingsResponse(integer status, string body)
{
    if (status < 200 || status >= 300)
    {
        llOwnerSay("HIP settings unavailable. Using local HUD settings.");
        return;
    }

    string mode = JsonValue(body, "mode", HIP_MODE);
    if (IsValidMode(mode))
    {
        HIP_MODE = mode;
    }

    HIP_POPUP_ALERTS_ENABLED = JsonBoolValue(body, "popupAlertsEnabled", HIP_POPUP_ALERTS_ENABLED);
    HIP_PRIVATE_WARNINGS_ENABLED = JsonBoolValue(body, "privateWarningsEnabled", HIP_PRIVATE_WARNINGS_ENABLED);
    HIP_SAFETY_ROUTING_ENABLED = JsonBoolValue(body, "safetyRoutingEnabled", HIP_SAFETY_ROUTING_ENABLED);
    UpdateHudStatus(gLastScan, gLastRisk);
}

// Handles HIP scan results and chooses owner warning/popup behavior.
HandleScanResponse(integer status, string body)
{
    if (status < 200 || status >= 300)
    {
        llOwnerSay("HIP scan unavailable. Local warning: " + gPendingRiskReason);
        UpdateHudStatus("Local warning", "Medium");
        return;
    }

    string risk = JsonValue(body, "riskLevel", "Low");
    string action = JsonValue(body, "recommendedHudAction", "StatusOnly");
    string safetyPageUrl = JsonValue(body, "safetyPageUrl", "");
    string reason = FirstJsonArrayString(body, "reasons", gPendingRiskReason);

    gPendingSafetyPageUrl = safetyPageUrl;
    UpdateHudStatus(reason, risk);

    if (risk == "Low")
    {
        return;
    }

    WarnOwner(risk, reason, action, safetyPageUrl);
    ReportFinding(gPendingSenderHash, risk, reason, gPendingRiskUrl);
}

// Warns only the HUD owner. This avoids exposing risk decisions in public chat.
WarnOwner(string risk, string reason, string action, string safetyPageUrl)
{
    if (!HIP_PRIVATE_WARNINGS_ENABLED && risk != "Critical")
    {
        return;
    }

    string warning = "HIP Warning:\n" +
        "Message from sender looks suspicious.\n" +
        "Risk: " + risk + "\n" +
        "Reason: " + reason + "\n" +
        "Action: " + action;

    llOwnerSay(warning);

    if (HIP_SAFETY_ROUTING_ENABLED && safetyPageUrl != "")
    {
        llOwnerSay("HIP Safety: " + AbsoluteHipUrl(safetyPageUrl));
    }

    if ((risk == "High" || risk == "Critical") && HIP_POPUP_ALERTS_ENABLED)
    {
        llDialog(llGetOwner(), warning, ["Open Safety", "Dismiss"], HIP_DIALOG_CHANNEL);
    }
}

// Updates floating HUD status text with a short owner-visible state.
UpdateHudStatus(string lastScan, string risk)
{
    gLastScan = lastScan;
    gLastRisk = risk;
    llSetText("HIP Shield: " + (gActivated ? "Active" : "Inactive") +
        "\nMode: " + HIP_MODE +
        "\nLast Scan: " + llGetSubString(gLastScan, 0, 36) +
        "\nRisk: " + gLastRisk +
        "\nLicense: " + gLicenseStatus, <0.2, 0.9, 0.8>, 1.0);
}

// Determines whether a message has a suspicious link signal worth sending to HIP.
integer ShouldScanMessage(string message)
{
    string lower = llToLower(message);
    if (HipExtractBestEffortUrl(message) != "") return TRUE;
    if (HipLooksShortened(lower)) return TRUE;
    if (HipLooksBrokenUp(message)) return TRUE;
    if (HipLooksObfuscated(lower)) return TRUE;
    if (HIP_MODE == "Paranoid" && HipLooksRewardScam(lower)) return TRUE;
    return FALSE;
}

// Validates HUD modes before saving or applying settings.
integer IsValidMode(string mode)
{
    return mode == "Quiet" || mode == "Normal" || mode == "Strict" || mode == "Paranoid";
}

// Returns a short snippet only after suspicious local detection has already happened.
string LimitedSuspiciousSnippet(string message)
{
    return llGetSubString(message, 0, 159);
}

// Maps HUD scan risk levels into API report risk levels used by HIP.
string ApiRiskLevel(string risk)
{
    if (risk == "Critical") return "Critical";
    if (risk == "High") return "HighRisk";
    if (risk == "Medium") return "Caution";
    return "Unknown";
}

// Generates an owner hash so reports avoid sending real avatar names.
string OwnerHash()
{
    return llSHA256String((string)llGetOwner());
}

// Converts relative HIP safety URLs into absolute links for llLoadURL/owner chat.
string AbsoluteHipUrl(string value)
{
    if (~llSubStringIndex(value, "http://") || ~llSubStringIndex(value, "https://"))
    {
        return value;
    }

    return HIP_API_BASE_URL + value;
}

// Extracts a best-effort domain for privacy-safe reporting.
string BestEffortDomain(string url)
{
    string lower = llToLower(url);
    lower = llDumpList2String(llParseString2List(lower, ["https://"], []), "");
    lower = llDumpList2String(llParseString2List(lower, ["http://"], []), "");
    list parts = llParseString2List(lower, ["/", "?", "#"], []);
    if (llGetListLength(parts) > 0) return llList2String(parts, 0);
    return "";
}

// Detects common URL shorteners locally so harmless chat is not sent to HIP.
integer HipLooksShortened(string lowerText)
{
    return ~llSubStringIndex(lowerText, "bit.ly/") ||
        ~llSubStringIndex(lowerText, "tinyurl.com/") ||
        ~llSubStringIndex(lowerText, "t.co/") ||
        ~llSubStringIndex(lowerText, "goo.gl/") ||
        ~llSubStringIndex(lowerText, "is.gd/") ||
        ~llSubStringIndex(lowerText, "ow.ly/");
}

// Detects broken-up URL text such as hxxps or dot-separated domains.
integer HipLooksBrokenUp(string text)
{
    string lowerText = llToLower(text);
    return ~llSubStringIndex(lowerText, "hxxp://") ||
        ~llSubStringIndex(lowerText, "hxxps://") ||
        ~llSubStringIndex(lowerText, " dot ") ||
        ~llSubStringIndex(lowerText, "[dot]") ||
        ~llSubStringIndex(lowerText, "(dot)");
}

// Detects URL obfuscation used to avoid simple scanners.
integer HipLooksObfuscated(string lowerText)
{
    return HipLooksBrokenUp(lowerText) ||
        ~llSubStringIndex(lowerText, "[.]") ||
        ~llSubStringIndex(lowerText, "(.)") ||
        ~llSubStringIndex(lowerText, "http :");
}

// Detects reward/prize wording only when paired with link-like content.
integer HipLooksRewardScam(string lowerText)
{
    return (~llSubStringIndex(lowerText, "free") ||
        ~llSubStringIndex(lowerText, "prize") ||
        ~llSubStringIndex(lowerText, "reward") ||
        ~llSubStringIndex(lowerText, "limited time") ||
        ~llSubStringIndex(lowerText, "claim")) &&
        (~llSubStringIndex(lowerText, "http") || HipLooksObfuscated(lowerText));
}

// Extracts the first URL-like token from a suspicious message.
string HipExtractBestEffortUrl(string text)
{
    list parts = llParseString2List(text, [" ", "\n", "\t"], []);
    integer count = llGetListLength(parts);
    integer index;

    for (index = 0; index < count; ++index)
    {
        string part = llList2String(parts, index);
        string lower = llToLower(part);
        if (~llSubStringIndex(lower, "http://") || ~llSubStringIndex(lower, "https://") ||
            ~llSubStringIndex(lower, "hxxp://") || ~llSubStringIndex(lower, "hxxps://"))
        {
            return llStringTrim(part, STRING_TRIM);
        }
    }

    return "";
}

// Reconstructs simple broken-up URL patterns for safety-page routing.
string HipReconstructBrokenUpUrl(string text)
{
    string lower = llToLower(text);
    lower = llDumpList2String(llParseString2List(lower, ["hxxps://"], []), "https://");
    lower = llDumpList2String(llParseString2List(lower, ["hxxp://"], []), "http://");
    lower = llDumpList2String(llParseString2List(lower, [" dot "], []), ".");
    lower = llDumpList2String(llParseString2List(lower, ["[dot]"], []), ".");
    lower = llDumpList2String(llParseString2List(lower, ["(dot)"], []), ".");
    return HipExtractBestEffortUrl(lower);
}

// Normalizes URL obfuscation markers before sending risk URLs to HIP.
string HipNormalizeUrl(string url)
{
    string normalized = llStringTrim(url, STRING_TRIM);
    normalized = llDumpList2String(llParseString2List(normalized, ["hxxps://"], []), "https://");
    normalized = llDumpList2String(llParseString2List(normalized, ["hxxp://"], []), "http://");
    normalized = llDumpList2String(llParseString2List(normalized, ["[.]"], []), ".");
    normalized = llDumpList2String(llParseString2List(normalized, ["(.)"], []), ".");
    return normalized;
}

// Produces a short plain-English reason for owner warnings and reports.
string HipRiskReason(string message)
{
    string lower = llToLower(message);
    if (HipLooksShortened(lower)) return "Shortened link pattern.";
    if (HipLooksBrokenUp(message)) return "Broken-up URL pattern.";
    if (HipLooksObfuscated(lower)) return "Obfuscated URL pattern.";
    if (HipLooksRewardScam(lower)) return "Reward or prize wording near a link.";
    return "Suspicious link pattern.";
}

// Creates a JSON string property.
string JsonPair(string name, string value)
{
    return JsonString(name) + ":" + JsonString(value);
}

// Creates a JSON boolean property.
string JsonBoolPair(string name, integer value)
{
    if (value)
    {
        return JsonString(name) + ":true";
    }

    return JsonString(name) + ":false";
}

// Escapes a string for simple JSON payload construction.
string JsonString(string value)
{
    return "\"" + JsonEscape(value) + "\"";
}

// Escapes JSON metacharacters and removes line breaks from privacy-safe snippets.
string JsonEscape(string value)
{
    value = llDumpList2String(llParseString2List(value, ["\\"], []), "\\\\");
    value = llDumpList2String(llParseString2List(value, ["\""], []), "\\\"");
    value = llDumpList2String(llParseString2List(value, ["\n"], []), " ");
    value = llDumpList2String(llParseString2List(value, ["\r"], []), " ");
    return value;
}

// Extracts a simple string value from JSON without adding a full JSON parser.
string JsonValue(string body, string name, string fallback)
{
    string marker = "\"" + name + "\":\"";
    integer start = llSubStringIndex(body, marker);
    if (!~start) return fallback;
    start += llStringLength(marker);
    integer end = llSubStringIndex(llGetSubString(body, start, -1), "\"");
    if (!~end) return fallback;
    return llGetSubString(body, start, start + end - 1);
}

// Extracts a JSON boolean value using the existing value when absent.
integer JsonBoolValue(string body, string name, integer fallback)
{
    if (~llSubStringIndex(body, "\"" + name + "\":true")) return TRUE;
    if (~llSubStringIndex(body, "\"" + name + "\":false")) return FALSE;
    return fallback;
}

// Extracts the first string in a small JSON array such as reasons.
string FirstJsonArrayString(string body, string name, string fallback)
{
    string marker = "\"" + name + "\":[\"";
    integer start = llSubStringIndex(body, marker);
    if (!~start) return fallback;
    start += llStringLength(marker);
    integer end = llSubStringIndex(llGetSubString(body, start, -1), "\"");
    if (!~end) return fallback;
    return llGetSubString(body, start, start + end - 1);
}
