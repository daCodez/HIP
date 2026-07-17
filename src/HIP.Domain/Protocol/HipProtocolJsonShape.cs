using System.Text.Json;

namespace HIP.Domain.Protocol;

internal static class HipProtocolJsonShape
{
    public static void ValidateClaimValue(JsonElement value, string parameterName, int depth = 0)
    {
        if (depth > HipProtocolClaim.MaximumValueDepth)
        {
            throw new ArgumentException(
                $"HIP protocol claim values cannot exceed {HipProtocolClaim.MaximumValueDepth} nested JSON levels.",
                parameterName);
        }

        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new ArgumentException("HIP protocol claim objects cannot contain duplicate properties.", parameterName);
                }

                ValidateClaimValue(property.Value, parameterName, depth + 1);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray())
            {
                ValidateClaimValue(item, parameterName, depth + 1);
            }
        }
    }
}
