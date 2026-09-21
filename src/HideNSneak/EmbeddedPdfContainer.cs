using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace HideNSneak;

public static class EmbeddedPdfContainer
{
    public const string HeaderMagicText = "HNSPDF01";
    public const string FooterMagicText = "HNSFTR01";
    public const byte FormatVersion = 1;
    public const int FixedHeaderLength = 58;
    public const int FooterLength = 16;

    private static readonly byte[] HeaderMagic = Encoding.ASCII.GetBytes(HeaderMagicText);
    private static readonly byte[] FooterMagic = Encoding.ASCII.GetBytes(FooterMagicText);
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static byte[] BuildHeader(string originalFileName, string originalExtension, long payloadLength, byte[] sha256, HideNSneakLimits limits)
    {
        ArgumentNullException.ThrowIfNull(originalFileName);
        ArgumentNullException.ThrowIfNull(originalExtension);
        ArgumentNullException.ThrowIfNull(sha256);

        if (sha256.Length != 32)
        {
            throw new ArgumentException("SHA-256 must be exactly 32 bytes.", nameof(sha256));
        }

        var fileNameBytes = Utf8.GetBytes(originalFileName);
        var extensionBytes = Utf8.GetBytes(originalExtension);
        var metadataLength = checked(fileNameBytes.Length + extensionBytes.Length);

        if (metadataLength > limits.MaxMetadataBytes)
        {
            throw new InvalidDataException($"Metadata exceeds the configured limit of {limits.MaxMetadataBytes} bytes.");
        }

        if (fileNameBytes.Length > ushort.MaxValue || extensionBytes.Length > ushort.MaxValue)
        {
            throw new InvalidDataException("Metadata values are too long to store in the container header.");
        }

        var headerLength = checked(FixedHeaderLength + metadataLength);
        var header = new byte[headerLength];
        HeaderMagic.CopyTo(header, 0);
        header[8] = FormatVersion;
        header[9] = 0;
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(10, 4), headerLength);
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(14, 8), payloadLength);
        sha256.CopyTo(header, 22);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(54, 2), (ushort)fileNameBytes.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(56, 2), (ushort)extensionBytes.Length);
        fileNameBytes.CopyTo(header, FixedHeaderLength);
        extensionBytes.CopyTo(header, FixedHeaderLength + fileNameBytes.Length);
        return header;
    }

    public static byte[] BuildFooter(long containerLength)
    {
        var footer = new byte[FooterLength];
        FooterMagic.CopyTo(footer, 0);
        BinaryPrimitives.WriteInt64LittleEndian(footer.AsSpan(8, 8), containerLength);
        return footer;
    }

    public static async Task<ContainerDescriptor?> LocateAsync(Stream stream, HideNSneakLimits limits, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(limits);

        if (!stream.CanSeek)
        {
            throw new ArgumentException("The input stream must support seeking.", nameof(stream));
        }

        if (stream.Length < FooterLength)
        {
            return null;
        }

        stream.Seek(-FooterLength, SeekOrigin.End);
        var footer = await ReadExactlyAsync(stream, FooterLength, cancellationToken);
        if (!footer.AsSpan(0, 8).SequenceEqual(FooterMagic))
        {
            return null;
        }

        var containerLength = BinaryPrimitives.ReadInt64LittleEndian(footer.AsSpan(8, 8));
        if (containerLength < FixedHeaderLength + FooterLength)
        {
            throw new InvalidDataException("Embedded container length is invalid.");
        }

        if (containerLength > stream.Length)
        {
            throw new InvalidDataException("Embedded container length exceeds the file size.");
        }

        var containerStart = stream.Length - containerLength;
        if (containerStart <= 0)
        {
            throw new InvalidDataException("Embedded container does not leave room for a PDF carrier.");
        }

        stream.Position = containerStart;
        var fixedHeader = await ReadExactlyAsync(stream, FixedHeaderLength, cancellationToken);
        if (!fixedHeader.AsSpan(0, 8).SequenceEqual(HeaderMagic))
        {
            throw new InvalidDataException("Invalid embedded payload marker.");
        }

        var version = fixedHeader[8];
        if (version != FormatVersion)
        {
            throw new InvalidDataException($"Unsupported embedded payload version '{version}'.");
        }

        var headerLength = BinaryPrimitives.ReadInt32LittleEndian(fixedHeader.AsSpan(10, 4));
        var payloadLength = BinaryPrimitives.ReadInt64LittleEndian(fixedHeader.AsSpan(14, 8));

        if (headerLength < FixedHeaderLength)
        {
            throw new InvalidDataException("Embedded header length is invalid.");
        }

        if (payloadLength < 0)
        {
            throw new InvalidDataException("Embedded payload length is invalid.");
        }

        if (payloadLength > limits.MaxPayloadBytes)
        {
            throw new InvalidDataException($"Embedded payload exceeds the configured limit of {limits.MaxPayloadBytes} bytes.");
        }

        var fileNameLength = BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader.AsSpan(54, 2));
        var extensionLength = BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader.AsSpan(56, 2));
        var expectedMetadataLength = checked(fileNameLength + extensionLength);
        var metadataLength = headerLength - FixedHeaderLength;

        if (metadataLength != expectedMetadataLength)
        {
            throw new InvalidDataException("Embedded metadata lengths do not match the recorded header length.");
        }

        if (metadataLength > limits.MaxMetadataBytes)
        {
            throw new InvalidDataException($"Embedded metadata exceeds the configured limit of {limits.MaxMetadataBytes} bytes.");
        }

        var expectedContainerLength = checked((long)headerLength + payloadLength + FooterLength);
        if (expectedContainerLength != containerLength)
        {
            throw new InvalidDataException("Embedded container length does not match the recorded payload and header sizes.");
        }

        var metadataBytes = metadataLength == 0
            ? []
            : await ReadExactlyAsync(stream, metadataLength, cancellationToken);

        var originalFileName = fileNameLength == 0
            ? string.Empty
            : Utf8.GetString(metadataBytes, 0, fileNameLength);
        var originalExtension = extensionLength == 0
            ? string.Empty
            : Utf8.GetString(metadataBytes, fileNameLength, extensionLength);

        var payloadOffset = stream.Position;
        var expectedHash = fixedHeader.AsSpan(22, 32).ToArray();

        return new ContainerDescriptor(
            containerStart,
            payloadOffset,
            payloadLength,
            headerLength,
            containerLength,
            originalFileName,
            originalExtension,
            expectedHash);
    }

    public static async Task<byte[]> ComputeHashAsync(Stream stream, long offset, long length, CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await ProcessPayloadAsync(stream, offset, length, null, hash, cancellationToken);
        return hash.GetHashAndReset();
    }

    public static async Task<byte[]> CopyPayloadAsync(Stream input, long offset, long length, Stream output, CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await ProcessPayloadAsync(input, offset, length, output, hash, cancellationToken);
        return hash.GetHashAndReset();
    }

    public static string ToHex(byte[] hash)
    {
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static async Task ProcessPayloadAsync(Stream input, long offset, long length, Stream? output, IncrementalHash hash, CancellationToken cancellationToken)
    {
        input.Position = offset;
        var remaining = length;
        var buffer = new byte[81920];

        while (remaining > 0)
        {
            var bytesToRead = remaining > buffer.Length ? buffer.Length : (int)remaining;
            var bytesRead = await input.ReadAsync(buffer.AsMemory(0, bytesToRead), cancellationToken);
            if (bytesRead == 0)
            {
                throw new InvalidDataException("Embedded payload is truncated.");
            }

            hash.AppendData(buffer, 0, bytesRead);

            if (output is not null)
            {
                await output.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
            }

            remaining -= bytesRead;
        }
    }

    private static async Task<byte[]> ReadExactlyAsync(Stream stream, int length, CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        var read = 0;

        while (read < length)
        {
            var bytesRead = await stream.ReadAsync(buffer.AsMemory(read, length - read), cancellationToken);
            if (bytesRead == 0)
            {
                throw new InvalidDataException("Embedded container is truncated.");
            }

            read += bytesRead;
        }

        return buffer;
    }
}

public sealed record ContainerDescriptor(
    long ContainerStart,
    long PayloadOffset,
    long PayloadLength,
    int HeaderLength,
    long ContainerLength,
    string OriginalFileName,
    string OriginalExtension,
    byte[] ExpectedSha256);
