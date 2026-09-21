namespace HideNSneak;

public sealed class HideNSneakLimits
{
    public const long DefaultMaxPayloadBytes = 512L * 1024 * 1024;
    public const int DefaultMaxMetadataBytes = 4096;

    public long MaxPayloadBytes { get; init; } = DefaultMaxPayloadBytes;

    public int MaxMetadataBytes { get; init; } = DefaultMaxMetadataBytes;

    public static HideNSneakLimits FromEnvironment()
    {
        return new HideNSneakLimits
        {
            MaxPayloadBytes = ReadLong("HNS_MAX_PAYLOAD_BYTES", DefaultMaxPayloadBytes),
            MaxMetadataBytes = (int)ReadLong("HNS_MAX_METADATA_BYTES", DefaultMaxMetadataBytes)
        };
    }

    private static long ReadLong(string variableName, long defaultValue)
    {
        var rawValue = Environment.GetEnvironmentVariable(variableName);
        return long.TryParse(rawValue, out var parsedValue) && parsedValue > 0
            ? parsedValue
            : defaultValue;
    }
}
