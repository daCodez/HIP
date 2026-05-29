using System.Text.Json;
using System.Text.Json.Serialization;

namespace HIP.Infrastructure.Persistence;

internal static class HipJsonSerializer
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string Serialize<T>(T value) =>
        JsonSerializer.Serialize(value, Options);

    public static T Deserialize<T>(string json) =>
        JsonSerializer.Deserialize<T>(json, Options) ?? throw new InvalidOperationException($"Unable to deserialize {typeof(T).Name}.");
}
