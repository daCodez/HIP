// HIP Chat Shield HUD MVP foundation.
// HIP is the product; this HUD is a privacy-safe HIP client for Second Life.
//
// hip_link_detector.lsl contains the same detector helpers as a reusable reference.
// Configure values from hip_config.example.lsl before packaging.

string HIP_API_BASE_URL = "https://your-hip-host.example.com";
string HIP_SETUP_CODE = "HIP-DEV-SETUP";
string HIP_HUD_DEVICE_ID = "hip-sl-hud-dev-device";
string HIP_MODE = "Normal"; // Quiet, Normal, Strict, Paranoid
integer HIP_POPUP_ALERTS = TRUE;
integer HIP_DEBUG = FALSE;

integer gListenHandle;
integer gActivated = FALSE;
string gLicenseStatus = "Inactive";
string gLastRisk = "Low";
string gLastScan = "Safe";

default
{
    state_entry()
    {
        llSetText("HIP Shield: Starting\nLast Scan: Pending\nRisk: Low", <0.2, 0.9, 0.8>, 1.0);
        gListenHandle = llListen(0, "", NULL_KEY, "");
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
        if (!gActivated)
        {
            return;
        }

        ScanMessage(name, id, message, FALSE);
    }

    http_response(key requestId, integer status, list metadata, string body)
    {
        if (HIP_DEBUG)
        {
            llOwnerSay("HIP HTTP " + (string)status + ": " + llGetSubString(body, 0, 180));
        }

        if (status >= 200 && status < 300)
        {
            if (~llSubStringIndex(body, "\"activated\":true"))
            {
                gActivated = TRUE;
                gLicenseStatus = "DevelopmentActive";
                UpdateStatus("Safe", "Low");
                llOwnerSay("HIP Shield: Active.");
            }
            else if (~llSubStringIndex(body, "\"accepted\":true"))
            {
                llOwnerSay("HIP report accepted. Use the HIP safety page before opening suspicious links.");
            }
        }
        else
        {
            llOwnerSay("HIP service unavailable or request rejected. HUD warnings remain local.");
        }
    }
}

ActivateHud()
{
    string payload = "{" +
        JsonPair("setupCode", HIP_SETUP_CODE) + "," +
        JsonPair("hudDeviceId", HIP_HUD_DEVICE_ID) + "," +
        JsonPair("avatarHash", OwnerHash()) +
        "}";

    llHTTPRequest(HIP_API_BASE_URL + "/api/v1/sl-hud/activate",
        [HTTP_METHOD, "POST", HTTP_MIMETYPE, "application/json"],
        payload);
}

ScanMessage(string senderName, key senderId, string message, integer privateIm)
{
    string lower = llToLower(message);
    string url = HipExtractBestEffortUrl(message);
    integer suspicious = (url != "") || HipLooksObfuscated(lower) || HipLooksRewardScam(lower);

    if (!suspicious)
    {
        UpdateStatus("Safe", "Low");
        return;
    }

    string reason = HipRiskReason(message);
    string normalizedUrl = HipNormalizeUrl(url);
    string risk = LocalRiskLevel(lower);
    string senderHash = llSHA256String((string)senderId);

    WarnOwner(senderHash, risk, reason, normalizedUrl);
    ReportFinding(senderHash, risk, reason, normalizedUrl);
    UpdateStatus("Suspicious link detected", risk);
}

string LocalRiskLevel(string lower)
{
    if (HipLooksObfuscated(lower) && HipLooksRewardScam(lower)) return "HighRisk";
    if (HipLooksObfuscated(lower)) return "HighRisk";
    if (HipLooksShortened(lower)) return "HighRisk";
    if (HIP_MODE == "Paranoid") return "Caution";
    return "Caution";
}

WarnOwner(string senderHash, string risk, string reason, string url)
{
    string warning = "HIP Warning: A message from this sender looks suspicious.\n" +
        "Reason: " + reason + "\n" +
        "Sender hash: " + llGetSubString(senderHash, 0, 11) + "\n" +
        "Action: Use the HIP safety page before opening.";

    if (risk == "Caution")
    {
        if (HIP_MODE != "Quiet") llOwnerSay(warning);
        return;
    }

    llOwnerSay(warning);

    if (HIP_POPUP_ALERTS)
    {
        llDialog(llGetOwner(), warning, ["Open Safety", "Dismiss"], 987321);
    }
}

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
        JsonPair("riskLevel", risk) + "," +
        JsonPair("reason", reason) + "," +
        JsonPair("detectedAtUtc", llGetTimestamp()) + "," +
        JsonPair("hipSignature", "sl-hud-signature-placeholder") +
        "}";

    llHTTPRequest(HIP_API_BASE_URL + "/api/v1/sl-hud/report-finding",
        [HTTP_METHOD, "POST", HTTP_MIMETYPE, "application/json"],
        payload);
}

UpdateStatus(string lastScan, string risk)
{
    gLastScan = lastScan;
    gLastRisk = risk;
    llSetText("HIP Shield: " + (gActivated ? "Active" : "Inactive") +
        "\nLast Scan: " + gLastScan +
        "\nRisk: " + gLastRisk +
        "\nLicense: " + gLicenseStatus, <0.2, 0.9, 0.8>, 1.0);
}

string OwnerHash()
{
    return llSHA256String((string)llGetOwner());
}

string BestEffortDomain(string url)
{
    string lower = llToLower(url);
    lower = llDumpList2String(llParseString2List(lower, ["https://"], []), "");
    lower = llDumpList2String(llParseString2List(lower, ["http://"], []), "");
    list parts = llParseString2List(lower, ["/", "?", "#"], []);
    if (llGetListLength(parts) > 0) return llList2String(parts, 0);
    return "";
}

string JsonPair(string name, string value)
{
    return "\"" + JsonEscape(name) + "\":\"" + JsonEscape(value) + "\"";
}

string JsonEscape(string value)
{
    value = llDumpList2String(llParseString2List(value, ["\\"], []), "\\\\");
    value = llDumpList2String(llParseString2List(value, ["\""], []), "\\\"");
    value = llDumpList2String(llParseString2List(value, ["\n"], []), " ");
    return value;
}

integer HipLooksShortened(string lowerText)
{
    return ~llSubStringIndex(lowerText, "bit.ly/") ||
        ~llSubStringIndex(lowerText, "tinyurl.com/") ||
        ~llSubStringIndex(lowerText, "t.co/") ||
        ~llSubStringIndex(lowerText, "goo.gl/") ||
        ~llSubStringIndex(lowerText, "is.gd/");
}

integer HipLooksObfuscated(string lowerText)
{
    return ~llSubStringIndex(lowerText, "hxxp://") ||
        ~llSubStringIndex(lowerText, "hxxps://") ||
        ~llSubStringIndex(lowerText, " dot com") ||
        ~llSubStringIndex(lowerText, "[.]") ||
        ~llSubStringIndex(lowerText, "(.)");
}

integer HipLooksRewardScam(string lowerText)
{
    return (~llSubStringIndex(lowerText, "free") ||
        ~llSubStringIndex(lowerText, "prize") ||
        ~llSubStringIndex(lowerText, "reward") ||
        ~llSubStringIndex(lowerText, "limited time")) &&
        (~llSubStringIndex(lowerText, "http") || HipLooksObfuscated(lowerText));
}

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

string HipNormalizeUrl(string url)
{
    string normalized = llStringTrim(url, STRING_TRIM);
    normalized = llDumpList2String(llParseString2List(normalized, ["hxxps://"], []), "https://");
    normalized = llDumpList2String(llParseString2List(normalized, ["hxxp://"], []), "http://");
    normalized = llDumpList2String(llParseString2List(normalized, ["[.]"], []), ".");
    normalized = llDumpList2String(llParseString2List(normalized, ["(.)"], []), ".");
    return normalized;
}

string HipRiskReason(string message)
{
    string lower = llToLower(message);
    if (HipLooksShortened(lower)) return "Shortened link pattern.";
    if (HipLooksObfuscated(lower)) return "Broken-up or obfuscated URL pattern.";
    if (HipLooksRewardScam(lower)) return "Reward or prize wording near a link.";
    return "Suspicious link pattern.";
}
