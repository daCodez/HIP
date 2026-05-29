// HIP link detector helper for Second Life LSL.
// This is intentionally local and privacy-safe: it detects link-like patterns
// without sending full chat or IM logs to HIP.

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
