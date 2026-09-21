using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace HideNSneak;

public static class EmbeddedPdfContainer
{
    private const byte CompressedFlag = 1 << 0;
    private const byte EncryptedFlag = 1 << 1;

    public const string LegacyHeaderMagicText = "HNSPDF01";
    public const string LegacyFooterMagicText = "HNSFTR01";
    public const byte LegacyFormatVersion = 1;

    public const byte FormatVersion = 2;
    public const int FixedHeaderLength = 74;
    public const int FooterLength = 16;

    private static readonly byte[] HeaderMagic = [0xC7, 0x6D, 0xA2, 0x51, 0x99, 0x04, 0xBE, 0x33];
    private static readonly byte[] FooterMagic = [0x34, 0x8A, 0xD4, 0x60, 0x13, 0xEE, 0x75, 0x2C];
    private static readonly byte[] LegacyHeaderMagic = Encoding.ASCII.GetBytes(LegacyHeaderMagicText);
    private static readonly byte[] LegacyFooterMagic = Encoding.ASCII.GetBytes(LegacyFooterMagicText);
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public const string HeaderMagicText = "HNSPDF01";
    public const string FooterMagicText = "HNSFTR01";
    public const byte V1FormatVersion = LegacyFormatVersion;
    public const int V1FixedHeaderLength = 58;

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

        var headerLength = checked(V1FixedHeaderLength + metadataLength);
        var header = new byte[headerLength];
        LegacyHeaderMagic.CopyTo(header, 0);
        header[8] = LegacyFormatVersion;
        header[9] = 0;
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(10, 4), headerLength);
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(14, 8), payloadLength);
        sha256.CopyTo(header, 22);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(54, 2), (ushort)fileNameBytes.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(56, 2), (ushort)extensionBytes.Length);
        fileNameBytes.CopyTo(header, V1FixedHeaderLength);
        extensionBytes.CopyTo(header, V1FixedHeaderLength + fileNameBytes.Length);
        return header;
    }

    public static byte[] BuildHeaderV2(
        string originalFileName,
        string originalExtension,
        long storedPayloadLength,
        long originalPayloadLength,
        byte[] originalSha256,
        bool isCompressed,
        bool isEncrypted,
        int kdfIterations,
        byte[]? salt,
        byte[]? nonce,
        byte[]? tag,
        HideNSneakLimits limits)
    {
        ArgumentNullException.ThrowIfNull(originalFileName);
        ArgumentNullException.ThrowIfNull(originalExtension);
        ArgumentNullException.ThrowIfNull(originalSha256);

        if (originalSha256.Length != 32)
        {
            throw new ArgumentException("SHA-256 must be exactly 32 bytes.", nameof(originalSha256));
        }

        salt ??= [];
        nonce ??= [];
        tag ??= [];

        if (!isEncrypted && (salt.Length != 0 || nonce.Length != 0 || tag.Length != 0))
        {
            throw new InvalidDataException("Encryption metadata cannot be set when encryption is disabled.");
        }

        if (salt.Length > byte.MaxValue || nonce.Length > byte.MaxValue || tag.Length > byte.MaxValue)
        {
            throw new InvalidDataException("Encryption metadata exceeds supported size.");
        }

        var fileNameBytes = Utf8.GetBytes(originalFileName);
        var extensionBytes = Utf8.GetBytes(originalExtension);
        var metadataLength = checked(fileNameBytes.Length + extensionBytes.Length + salt.Length + nonce.Length + tag.Length);

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
        header[9] = GetFlags(isCompressed, isEncrypted);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(10, 4), headerLength);
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(14, 8), storedPayloadLength);
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(22, 8), originalPayloadLength);
        originalSha256.CopyTo(header, 30);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(62, 4), kdfIterations);
        header[66] = (byte)salt.Length;
        header[67] = (byte)nonce.Length;
        header[68] = (byte)tag.Length;
        header[69] = 0;
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(70, 2), (ushort)fileNameBytes.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(72, 2), (ushort)extensionBytes.Length);

        var metadataOffset = FixedHeaderLength;
        fileNameBytes.CopyTo(header, metadataOffset);
        metadataOffset += fileNameBytes.Length;
        extensionBytes.CopyTo(header, metadataOffset);
        metadataOffset += extensionBytes.Length;
        salt.CopyTo(header, metadataOffset);
        metadataOffset += salt.Length;
        nonce.CopyTo(header, metadataOffset);
        metadataOffset += nonce.Length;
        tag.CopyTo(header, metadataOffset);
        return header;
    }

    public static byte[] BuildFooter(long containerLength)
    {
        var footer = new byte[FooterLength];
        LegacyFooterMagic.CopyTo(footer, 0);
        BinaryPrimitives.WriteInt64LittleEndian(footer.AsSpan(8, 8), containerLength);
        return footer;
    }

    public static byte[] BuildFooterV2(long containerLength)
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
        var isLegacyFooter = footer.AsSpan(0, 8).SequenceEqual(LegacyFooterMagic);
        var isCurrentFooter = footer.AsSpan(0, 8).SequenceEqual(FooterMagic);
        if (!isLegacyFooter && !isCurrentFooter)
        {
            return null;
        }

        var containerLength = BinaryPrimitives.ReadInt64LittleEndian(footer.AsSpan(8, 8));
        if (containerLength < V1FixedHeaderLength + FooterLength)
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
        var baseHeader = await ReadExactlyAsync(stream, 14, cancellationToken);
        var version = baseHeader[8];
        if (version == LegacyFormatVersion)
        {
            return await ParseLegacyAsync(stream, limits, containerStart, containerLength, baseHeader, cancellationToken);
        }

        if (version == FormatVersion)
        {
            return await ParseV2Async(stream, limits, containerStart, containerLength, baseHeader, cancellationToken);
        }

        throw new InvalidDataException($"Unsupported embedded payload version '{version}'.");
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

    private static async Task<ContainerDescriptor> ParseLegacyAsync(
        Stream stream,
        HideNSneakLimits limits,
        long containerStart,
        long containerLength,
        byte[] partialHeader,
        CancellationToken cancellationToken)
    {
        if (!partialHeader.AsSpan(0, 8).SequenceEqual(LegacyHeaderMagic))
        {
            throw new InvalidDataException("Invalid embedded payload marker.");
        }

        var fixedHeader = new byte[V1FixedHeaderLength];
        partialHeader.CopyTo(fixedHeader, 0);
        var remainder = await ReadExactlyAsync(stream, V1FixedHeaderLength - partialHeader.Length, cancellationToken);
        remainder.CopyTo(fixedHeader, partialHeader.Length);

        var headerLength = BinaryPrimitives.ReadInt32LittleEndian(fixedHeader.AsSpan(10, 4));
        var payloadLength = BinaryPrimitives.ReadInt64LittleEndian(fixedHeader.AsSpan(14, 8));
        ValidateLengths(headerLength, V1FixedHeaderLength, payloadLength, limits, containerLength);

        var fileNameLength = BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader.AsSpan(54, 2));
        var extensionLength = BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader.AsSpan(56, 2));
        var expectedMetadataLength = checked(fileNameLength + extensionLength);
        var metadataLength = headerLength - V1FixedHeaderLength;
        if (metadataLength != expectedMetadataLength)
        {
            throw new InvalidDataException("Embedded metadata lengths do not match the recorded header length.");
        }

        var expectedContainerLength = checked((long)headerLength + payloadLength + FooterLength);
        if (expectedContainerLength != containerLength)
        {
            throw new InvalidDataException("Embedded container length does not match the recorded payload and header sizes.");
        }

        var metadataBytes = metadataLength == 0 ? [] : await ReadExactlyAsync(stream, metadataLength, cancellationToken);
        var originalFileName = fileNameLength == 0 ? string.Empty : Utf8.GetString(metadataBytes, 0, fileNameLength);
        var originalExtension = extensionLength == 0 ? string.Empty : Utf8.GetString(metadataBytes, fileNameLength, extensionLength);

        return new ContainerDescriptor(
            LegacyFormatVersion,
            containerStart,
            stream.Position,
            payloadLength,
            payloadLength,
            headerLength,
            containerLength,
            originalFileName,
            originalExtension,
            fixedHeader.AsSpan(22, 32).ToArray(),
            false,
            false,
            0,
            [],
            [],
            []);
    }

    private static async Task<ContainerDescriptor> ParseV2Async(
        Stream stream,
        HideNSneakLimits limits,
        long containerStart,
        long containerLength,
        byte[] partialHeader,
        CancellationToken cancellationToken)
    {
        if (!partialHeader.AsSpan(0, 8).SequenceEqual(HeaderMagic))
        {
            throw new InvalidDataException("Invalid embedded payload marker.");
        }

        var fixedHeader = new byte[FixedHeaderLength];
        partialHeader.CopyTo(fixedHeader, 0);
        var remainder = await ReadExactlyAsync(stream, FixedHeaderLength - partialHeader.Length, cancellationToken);
        remainder.CopyTo(fixedHeader, partialHeader.Length);

        var flags = fixedHeader[9];
        var isCompressed = (flags & CompressedFlag) != 0;
        var isEncrypted = (flags & EncryptedFlag) != 0;
        var headerLength = BinaryPrimitives.ReadInt32LittleEndian(fixedHeader.AsSpan(10, 4));
        var payloadLength = BinaryPrimitives.ReadInt64LittleEndian(fixedHeader.AsSpan(14, 8));
        var originalPayloadLength = BinaryPrimitives.ReadInt64LittleEndian(fixedHeader.AsSpan(22, 8));
        ValidateLengths(headerLength, FixedHeaderLength, payloadLength, limits, containerLength);

        if (originalPayloadLength < 0 || originalPayloadLength > limits.MaxPayloadBytes)
        {
            throw new InvalidDataException($"Embedded original payload exceeds the configured limit of {limits.MaxPayloadBytes} bytes.");
        }

        var kdfIterations = BinaryPrimitives.ReadInt32LittleEndian(fixedHeader.AsSpan(62, 4));
        var saltLength = fixedHeader[66];
        var nonceLength = fixedHeader[67];
        var tagLength = fixedHeader[68];
        var fileNameLength = BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader.AsSpan(70, 2));
        var extensionLength = BinaryPrimitives.ReadUInt16LittleEndian(fixedHeader.AsSpan(72, 2));
        var expectedMetadataLength = checked(fileNameLength + extensionLength + saltLength + nonceLength + tagLength);
        var metadataLength = headerLength - FixedHeaderLength;
        if (metadataLength != expectedMetadataLength)
        {
            throw new InvalidDataException("Embedded metadata lengths do not match the recorded header length.");
        }

        if (!isEncrypted && (saltLength != 0 || nonceLength != 0 || tagLength != 0 || kdfIterations != 0))
        {
            throw new InvalidDataException("Encryption metadata is invalid for an unencrypted payload.");
        }

        if (isEncrypted && (saltLength == 0 || nonceLength == 0 || tagLength == 0 || kdfIterations <= 0))
        {
            throw new InvalidDataException("Encrypted payload metadata is incomplete.");
        }

        var expectedContainerLength = checked((long)headerLength + payloadLength + FooterLength);
        if (expectedContainerLength != containerLength)
        {
            throw new InvalidDataException("Embedded container length does not match the recorded payload and header sizes.");
        }

        var metadataBytes = metadataLength == 0 ? [] : await ReadExactlyAsync(stream, metadataLength, cancellationToken);
        var metadataOffset = 0;
        var originalFileName = fileNameLength == 0 ? string.Empty : Utf8.GetString(metadataBytes, metadataOffset, fileNameLength);
        metadataOffset += fileNameLength;
        var originalExtension = extensionLength == 0 ? string.Empty : Utf8.GetString(metadataBytes, metadataOffset, extensionLength);
        metadataOffset += extensionLength;
        var salt = metadataBytes.AsSpan(metadataOffset, saltLength).ToArray();
        metadataOffset += saltLength;
        var nonce = metadataBytes.AsSpan(metadataOffset, nonceLength).ToArray();
        metadataOffset += nonceLength;
        var tag = metadataBytes.AsSpan(metadataOffset, tagLength).ToArray();

        return new ContainerDescriptor(
            FormatVersion,
            containerStart,
            stream.Position,
            payloadLength,
            originalPayloadLength,
            headerLength,
            containerLength,
            originalFileName,
            originalExtension,
            fixedHeader.AsSpan(30, 32).ToArray(),
            isCompressed,
            isEncrypted,
            kdfIterations,
            salt,
            nonce,
            tag);
    }

    private static void ValidateLengths(int headerLength, int minimumHeaderLength, long payloadLength, HideNSneakLimits limits, long containerLength)
    {
        if (headerLength < minimumHeaderLength)
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

        var metadataLength = headerLength - minimumHeaderLength;
        if (metadataLength > limits.MaxMetadataBytes)
        {
            throw new InvalidDataException($"Embedded metadata exceeds the configured limit of {limits.MaxMetadataBytes} bytes.");
        }

        if (containerLength < minimumHeaderLength + FooterLength)
        {
            throw new InvalidDataException("Embedded container length is invalid.");
        }
    }

    private static byte GetFlags(bool isCompressed, bool isEncrypted)
    {
        var flags = (byte)0;
        if (isCompressed)
        {
            flags |= CompressedFlag;
        }

        if (isEncrypted)
        {
            flags |= EncryptedFlag;
        }

        return flags;
    }
}

public sealed record ContainerDescriptor(
    byte FormatVersion,
    long ContainerStart,
    long PayloadOffset,
    long PayloadLength,
    long OriginalPayloadLength,
    int HeaderLength,
    long ContainerLength,
    string OriginalFileName,
    string OriginalExtension,
    byte[] ExpectedSha256,
    bool IsCompressed,
    bool IsEncrypted,
    int KdfIterations,
    byte[] Salt,
    byte[] Nonce,
    byte[] Tag);
