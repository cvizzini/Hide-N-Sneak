namespace HideNSneak;

public sealed record InspectionResult(
    bool PayloadPresent,
    long PayloadLength,
    string? OriginalFileName,
    string? OriginalExtension,
    string? Sha256Hex,
    bool ChecksumValid)
{
    public static InspectionResult NoPayload { get; } = new(false, 0, null, null, null, false);
}

public sealed record RevealResult(long PayloadLength, string? OriginalFileName, string? OriginalExtension);
