using System.Security.Cryptography;
using System.IO.Compression;
using System.Text;

namespace HideNSneak;

public sealed class PdfZipPackager
{
    private const int Pbkdf2Iterations = 150_000;
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int MinimumCompressionSavingsBytes = 32;

    public async Task HideAsync(
        string inputZipPath,
        string outputPdfPath,
        string? carrierPdfPath,
        string? password,
        HideNSneakLimits limits,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(limits);

        var inputPath = ValidateInputFile(inputZipPath, "ZIP payload");
        var outputPath = ValidateOutputPath(outputPdfPath);
        var carrierPath = string.IsNullOrWhiteSpace(carrierPdfPath) ? null : ValidateInputFile(carrierPdfPath, "PDF carrier");

        EnsureDistinctPath(outputPath, inputPath, "Output PDF path must be different from the input ZIP path.");
        if (carrierPath is not null)
        {
            EnsureDistinctPath(outputPath, carrierPath, "Output PDF path must be different from the carrier PDF path.");
            await ValidateCarrierAsync(carrierPath, cancellationToken);
        }

        EnsureOutputDoesNotExist(outputPath);

        var payloadLength = new FileInfo(inputPath).Length;
        if (payloadLength > limits.MaxPayloadBytes)
        {
            throw new InvalidDataException($"Input ZIP exceeds the configured limit of {limits.MaxPayloadBytes} bytes.");
        }

        var originalPayload = await File.ReadAllBytesAsync(inputPath, cancellationToken);
        var sha256 = SHA256.HashData(originalPayload);

        var compressedPayload = CompressBrotli(originalPayload);
        var isCompressed = compressedPayload.Length <= originalPayload.Length - MinimumCompressionSavingsBytes;
        var payloadToStore = isCompressed ? compressedPayload : originalPayload;

        var isEncrypted = !string.IsNullOrEmpty(password);
        var kdfIterations = 0;
        byte[] salt = [];
        byte[] nonce = [];
        byte[] tag = [];
        if (isEncrypted)
        {
            salt = RandomNumberGenerator.GetBytes(SaltSize);
            nonce = RandomNumberGenerator.GetBytes(NonceSize);
            tag = new byte[TagSize];
            var key = DeriveKey(password!, salt, Pbkdf2Iterations);
            var encryptedPayload = new byte[payloadToStore.Length];
            using (var aesGcm = new AesGcm(key, TagSize))
            {
                aesGcm.Encrypt(nonce, payloadToStore, encryptedPayload, tag);
            }

            CryptographicOperations.ZeroMemory(key);
            payloadToStore = encryptedPayload;
            kdfIterations = Pbkdf2Iterations;
        }

        if (payloadToStore.Length > limits.MaxPayloadBytes)
        {
            throw new InvalidDataException($"Embedded payload exceeds the configured limit of {limits.MaxPayloadBytes} bytes.");
        }

        var originalFileName = Path.GetFileName(inputPath);
        var originalExtension = Path.GetExtension(inputPath);
        var header = EmbeddedPdfContainer.BuildHeaderV2(
            originalFileName,
            originalExtension,
            payloadToStore.Length,
            originalPayload.LongLength,
            sha256,
            isCompressed,
            isEncrypted,
            kdfIterations,
            salt,
            nonce,
            tag,
            limits);
        var footer = EmbeddedPdfContainer.BuildFooterV2(header.Length + payloadToStore.Length + EmbeddedPdfContainer.FooterLength);

        CreateOutputDirectory(outputPath);

        await using var output = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        if (carrierPath is null)
        {
            var pdfBytes = MinimalPdfBuilder.CreatePdf();
            await output.WriteAsync(pdfBytes, cancellationToken);
        }
        else
        {
            await using var carrier = new FileStream(carrierPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            await carrier.CopyToAsync(output, cancellationToken);
        }

        await output.WriteAsync(header, cancellationToken);
        await output.WriteAsync(payloadToStore, cancellationToken);
        await output.WriteAsync(footer, cancellationToken);
    }

    public async Task<RevealResult> RevealAsync(string inputPdfPath, string outputZipPath, string? password, HideNSneakLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(limits);

        var inputPath = ValidateInputFile(inputPdfPath, "PDF input");
        var outputPath = ValidateOutputPath(outputZipPath);

        EnsureDistinctPath(outputPath, inputPath, "Output ZIP path must be different from the input PDF path.");
        EnsureOutputDoesNotExist(outputPath);
        CreateOutputDirectory(outputPath);

        await using var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var descriptor = await EmbeddedPdfContainer.LocateAsync(input, limits, cancellationToken)
            ?? throw new InvalidDataException("No embedded payload was found.");

        var tempOutputPath = CreateTemporaryOutputPath(outputPath);

        try
        {
            var extractedPayload = await ReadPayloadAsync(input, descriptor.PayloadOffset, descriptor.PayloadLength, cancellationToken);
            if (descriptor.IsEncrypted)
            {
                if (string.IsNullOrEmpty(password))
                {
                    throw new InvalidDataException("Embedded payload is encrypted. Supply --password to reveal it.");
                }

                var key = DeriveKey(password, descriptor.Salt, descriptor.KdfIterations);
                try
                {
                    var decryptedPayload = new byte[extractedPayload.Length];
                    using (var aesGcm = new AesGcm(key, descriptor.Tag.Length))
                    {
                        aesGcm.Decrypt(descriptor.Nonce, extractedPayload, descriptor.Tag, decryptedPayload);
                    }

                    extractedPayload = decryptedPayload;
                }
                catch (CryptographicException)
                {
                    throw new InvalidDataException("Unable to decrypt embedded payload. Password is incorrect or payload integrity check failed.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                }
            }

            if (descriptor.IsCompressed)
            {
                extractedPayload = DecompressBrotli(extractedPayload, limits);
            }

            if (extractedPayload.LongLength != descriptor.OriginalPayloadLength)
            {
                throw new InvalidDataException("Embedded payload length does not match the recorded original payload length.");
            }

            var actualHash = SHA256.HashData(extractedPayload);
            if (!actualHash.SequenceEqual(descriptor.ExpectedSha256))
            {
                throw new InvalidDataException("Embedded payload checksum mismatch.");
            }

            await using (var output = new FileStream(tempOutputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                await output.WriteAsync(extractedPayload, cancellationToken);
            }

            File.Move(tempOutputPath, outputPath);
            return new RevealResult(descriptor.OriginalPayloadLength, descriptor.OriginalFileName, descriptor.OriginalExtension);
        }
        catch
        {
            if (File.Exists(tempOutputPath))
            {
                File.Delete(tempOutputPath);
            }

            throw;
        }
    }

    public async Task<InspectionResult> InspectAsync(string inputPdfPath, HideNSneakLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(limits);

        var inputPath = ValidateInputFile(inputPdfPath, "PDF input");

        await using var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var descriptor = await EmbeddedPdfContainer.LocateAsync(input, limits, cancellationToken);
        if (descriptor is null)
        {
            return InspectionResult.NoPayload;
        }

        if (descriptor.IsEncrypted)
        {
            return new InspectionResult(
                true,
                descriptor.OriginalPayloadLength,
                descriptor.OriginalFileName,
                descriptor.OriginalExtension,
                EmbeddedPdfContainer.ToHex(descriptor.ExpectedSha256),
                false);
        }

        var payloadBytes = await ReadPayloadAsync(input, descriptor.PayloadOffset, descriptor.PayloadLength, cancellationToken);
        if (descriptor.IsCompressed)
        {
            payloadBytes = DecompressBrotli(payloadBytes, limits);
        }

        var actualHash = SHA256.HashData(payloadBytes);
        return new InspectionResult(
            true,
            descriptor.OriginalPayloadLength,
            descriptor.OriginalFileName,
            descriptor.OriginalExtension,
            EmbeddedPdfContainer.ToHex(descriptor.ExpectedSha256),
            actualHash.SequenceEqual(descriptor.ExpectedSha256));
    }

    private static string ValidateInputFile(string path, string description)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException($"{description} path is required.");
        }

        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException($"{description} '{fullPath}' was not found.", fullPath);
        }

        return fullPath;
    }

    private static string ValidateOutputPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Output path is required.");
        }

        return Path.GetFullPath(path);
    }

    private static void EnsureDistinctPath(string path, string otherPath, string message)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (string.Equals(path, otherPath, comparison))
        {
            throw new IOException(message);
        }
    }

    private static void CreateOutputDirectory(string outputPath)
    {
        var directory = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    private static void EnsureOutputDoesNotExist(string outputPath)
    {
        if (File.Exists(outputPath))
        {
            throw new IOException($"Refusing to overwrite existing file '{outputPath}'.");
        }
    }

    private static async Task ValidateCarrierAsync(string carrierPath, CancellationToken cancellationToken)
    {
        await using var carrier = new FileStream(carrierPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (carrier.Length < 5)
        {
            throw new InvalidDataException("Carrier PDF is too small to be valid.");
        }

        var header = new byte[5];
        _ = await carrier.ReadAsync(header, cancellationToken);
        if (!header.SequenceEqual(Encoding.ASCII.GetBytes("%PDF-")))
        {
            throw new InvalidDataException("Carrier file does not begin with a PDF signature.");
        }

        var tailLength = (int)Math.Min(2048, carrier.Length);
        carrier.Position = carrier.Length - tailLength;
        var tail = new byte[tailLength];
        _ = await carrier.ReadAsync(tail, cancellationToken);
        if (!Encoding.ASCII.GetString(tail).Contains("%%EOF", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Carrier PDF does not contain a recognizable EOF marker near the end of the file.");
        }
    }

    private static byte[] CompressBrotli(byte[] payload)
    {
        using var output = new MemoryStream();
        using (var brotli = new BrotliStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            brotli.Write(payload, 0, payload.Length);
        }

        return output.ToArray();
    }

    private static byte[] DecompressBrotli(byte[] payload, HideNSneakLimits limits)
    {
        using var input = new MemoryStream(payload, writable: false);
        using var brotli = new BrotliStream(input, CompressionMode.Decompress, leaveOpen: false);
        using var output = new MemoryStream();
        var buffer = new byte[81920];
        while (true)
        {
            var read = brotli.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }

            output.Write(buffer, 0, read);
            if (output.Length > limits.MaxPayloadBytes)
            {
                throw new InvalidDataException($"Embedded payload exceeds the configured limit of {limits.MaxPayloadBytes} bytes.");
            }
        }

        return output.ToArray();
    }

    private static async Task<byte[]> ReadPayloadAsync(Stream input, long offset, long length, CancellationToken cancellationToken)
    {
        input.Position = offset;
        var remaining = length;
        using var output = new MemoryStream();
        var buffer = new byte[81920];
        while (remaining > 0)
        {
            var count = remaining > buffer.Length ? buffer.Length : (int)remaining;
            var read = await input.ReadAsync(buffer.AsMemory(0, count), cancellationToken);
            if (read == 0)
            {
                throw new InvalidDataException("Embedded payload is truncated.");
            }

            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            remaining -= read;
        }

        return output.ToArray();
    }

    private static byte[] DeriveKey(string password, byte[] salt, int iterations)
    {
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, 32);
    }

    private static string CreateTemporaryOutputPath(string outputPath)
    {
        var directory = Path.GetDirectoryName(outputPath) ?? Directory.GetCurrentDirectory();
        var fileName = $"{Path.GetFileName(outputPath)}.{Guid.NewGuid():N}.tmp";
        return Path.Combine(directory, fileName);
    }
}
