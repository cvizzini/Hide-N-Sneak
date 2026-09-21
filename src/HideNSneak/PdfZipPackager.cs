using System.Security.Cryptography;
using System.Text;

namespace HideNSneak;

public sealed class PdfZipPackager
{
    public async Task HideAsync(string inputZipPath, string outputPdfPath, string? carrierPdfPath, HideNSneakLimits limits, CancellationToken cancellationToken = default)
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

        var sha256 = await ComputeSha256Async(inputPath, cancellationToken);
        var originalFileName = Path.GetFileName(inputPath);
        var originalExtension = Path.GetExtension(inputPath);
        var header = EmbeddedPdfContainer.BuildHeader(originalFileName, originalExtension, payloadLength, sha256, limits);
        var footer = EmbeddedPdfContainer.BuildFooter(header.Length + payloadLength + EmbeddedPdfContainer.FooterLength);

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
        await using (var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            await input.CopyToAsync(output, cancellationToken);
        }

        await output.WriteAsync(footer, cancellationToken);
    }

    public async Task<RevealResult> RevealAsync(string inputPdfPath, string outputZipPath, HideNSneakLimits limits, CancellationToken cancellationToken = default)
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
            await using (var output = new FileStream(tempOutputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                var actualHash = await EmbeddedPdfContainer.CopyPayloadAsync(input, descriptor.PayloadOffset, descriptor.PayloadLength, output, cancellationToken);
                if (!actualHash.SequenceEqual(descriptor.ExpectedSha256))
                {
                    throw new InvalidDataException("Embedded payload checksum mismatch.");
                }
            }

            File.Move(tempOutputPath, outputPath);
            return new RevealResult(descriptor.PayloadLength, descriptor.OriginalFileName, descriptor.OriginalExtension);
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

        var actualHash = await EmbeddedPdfContainer.ComputeHashAsync(input, descriptor.PayloadOffset, descriptor.PayloadLength, cancellationToken);
        return new InspectionResult(
            true,
            descriptor.PayloadLength,
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

    private static async Task<byte[]> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var sha256 = SHA256.Create();
        return await sha256.ComputeHashAsync(stream, cancellationToken);
    }

    private static string CreateTemporaryOutputPath(string outputPath)
    {
        var directory = Path.GetDirectoryName(outputPath) ?? Directory.GetCurrentDirectory();
        var fileName = $"{Path.GetFileName(outputPath)}.{Guid.NewGuid():N}.tmp";
        return Path.Combine(directory, fileName);
    }
}
