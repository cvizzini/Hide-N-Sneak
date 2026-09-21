using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using HideNSneak;

namespace HideNSneak.Tests;

public sealed class CliApplicationTests : IDisposable
{
    private readonly string _workspacePath = Path.Combine(Path.GetTempPath(), "hide-n-sneak-tests", Guid.NewGuid().ToString("N"));

    public CliApplicationTests()
    {
        Directory.CreateDirectory(_workspacePath);
    }

    [Fact]
    public async Task HideAndReveal_RoundTripsWithGeneratedCarrier()
    {
        var inputZipPath = WritePayloadZip("generated.zip");
        var outputPdfPath = Path.Combine(_workspacePath, "carrier.pdf");
        var revealedZipPath = Path.Combine(_workspacePath, "revealed.zip");

        var hide = await RunCliAsync("hide", "--input", inputZipPath, "--output", outputPdfPath);
        var reveal = await RunCliAsync("reveal", "--input", outputPdfPath, "--output", revealedZipPath);

        Assert.Equal(0, hide.ExitCode);
        Assert.Equal(0, reveal.ExitCode);
        Assert.StartsWith("%PDF-", Encoding.ASCII.GetString(await File.ReadAllBytesAsync(outputPdfPath)));
        Assert.Equal(await File.ReadAllBytesAsync(inputZipPath), await File.ReadAllBytesAsync(revealedZipPath));
    }

    [Fact]
    public async Task HideAndReveal_RoundTripsWithExistingCarrier()
    {
        var inputZipPath = WritePayloadZip("existing.zip");
        var carrierPath = Path.Combine(_workspacePath, "existing-carrier.pdf");
        var outputPdfPath = Path.Combine(_workspacePath, "combined.pdf");
        var revealedZipPath = Path.Combine(_workspacePath, "revealed-existing.zip");

        await File.WriteAllBytesAsync(carrierPath, MinimalPdfBuilder.CreatePdf());
        var originalCarrierBytes = await File.ReadAllBytesAsync(carrierPath);

        var hide = await RunCliAsync("hide", "--input", inputZipPath, "--output", outputPdfPath, "--carrier", carrierPath);
        var reveal = await RunCliAsync("reveal", "--input", outputPdfPath, "--output", revealedZipPath);

        Assert.Equal(0, hide.ExitCode);
        Assert.Equal(0, reveal.ExitCode);

        var outputBytes = await File.ReadAllBytesAsync(outputPdfPath);
        Assert.True(outputBytes.AsSpan(0, originalCarrierBytes.Length).SequenceEqual(originalCarrierBytes));
        Assert.Equal(await File.ReadAllBytesAsync(inputZipPath), await File.ReadAllBytesAsync(revealedZipPath));
    }

    [Fact]
    public async Task Inspect_ReportsPayloadMetadataAndChecksumStatus()
    {
        var inputZipPath = WritePayloadZip("inspect.zip");
        var outputPdfPath = Path.Combine(_workspacePath, "inspect.pdf");

        await RunCliAsync("hide", "--input", inputZipPath, "--output", outputPdfPath);
        var inspect = await RunCliAsync("inspect", "--input", outputPdfPath);
        await using var inputStream = File.OpenRead(inputZipPath);
        var expectedHash = Convert.ToHexString(await SHA256.HashDataAsync(inputStream)).ToLowerInvariant();

        Assert.Equal(0, inspect.ExitCode);
        Assert.Contains("Payload present: yes", inspect.StdOut);
        Assert.Contains($"Payload size: {new FileInfo(inputZipPath).Length} bytes", inspect.StdOut);
        Assert.Contains("Original file name: inspect.zip", inspect.StdOut);
        Assert.Contains("Original extension: .zip", inspect.StdOut);
        Assert.Contains($"SHA-256: {expectedHash}", inspect.StdOut);
        Assert.Contains("Checksum valid: yes", inspect.StdOut);
    }

    [Fact]
    public async Task Inspect_ReportsChecksumMismatchWithoutExtracting()
    {
        var inputZipPath = WritePayloadZip("checksum.zip");
        var outputPdfPath = Path.Combine(_workspacePath, "checksum.pdf");

        await RunCliAsync("hide", "--input", inputZipPath, "--output", outputPdfPath);
        await CorruptPayloadByteAsync(outputPdfPath);

        var inspect = await RunCliAsync("inspect", "--input", outputPdfPath);

        Assert.Equal(0, inspect.ExitCode);
        Assert.Contains("Payload present: yes", inspect.StdOut);
        Assert.Contains("Checksum valid: no", inspect.StdOut);
    }

    [Fact]
    public async Task Reveal_FailsForInvalidMarker()
    {
        var inputZipPath = WritePayloadZip("marker.zip");
        var outputPdfPath = Path.Combine(_workspacePath, "marker.pdf");
        var revealedZipPath = Path.Combine(_workspacePath, "marker-out.zip");

        await RunCliAsync("hide", "--input", inputZipPath, "--output", outputPdfPath);
        await CorruptHeaderMagicAsync(outputPdfPath);

        var reveal = await RunCliAsync("reveal", "--input", outputPdfPath, "--output", revealedZipPath);

        Assert.Equal(1, reveal.ExitCode);
        Assert.Contains("Invalid embedded payload marker", reveal.StdErr);
        Assert.False(File.Exists(revealedZipPath));
    }

    [Fact]
    public async Task Reveal_FailsForTruncatedContainer()
    {
        var inputZipPath = WritePayloadZip("truncated.zip");
        var outputPdfPath = Path.Combine(_workspacePath, "truncated.pdf");

        await RunCliAsync("hide", "--input", inputZipPath, "--output", outputPdfPath);
        var originalBytes = await File.ReadAllBytesAsync(outputPdfPath);
        await using var originalStream = new MemoryStream(originalBytes, writable: false);
        var descriptor = await EmbeddedPdfContainer.LocateAsync(originalStream, HideNSneakLimits.FromEnvironment(), CancellationToken.None);
        Assert.NotNull(descriptor);

        var truncatedBytes = originalBytes.Take(originalBytes.Length - EmbeddedPdfContainer.FooterLength - 5).ToArray();
        await using var truncatedStream = new MemoryStream(truncatedBytes, writable: false);
        await using var output = new MemoryStream();

        var exception = await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await EmbeddedPdfContainer.CopyPayloadAsync(truncatedStream, descriptor!.PayloadOffset, descriptor.PayloadLength, output, CancellationToken.None));

        Assert.Contains("truncated", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Reveal_FailsForInvalidLengths()
    {
        var inputZipPath = WritePayloadZip("lengths.zip");
        var outputPdfPath = Path.Combine(_workspacePath, "lengths.pdf");
        var revealedZipPath = Path.Combine(_workspacePath, "lengths-out.zip");

        await RunCliAsync("hide", "--input", inputZipPath, "--output", outputPdfPath);
        await CorruptHeaderLengthAsync(outputPdfPath, EmbeddedPdfContainer.FixedHeaderLength - 1);

        var reveal = await RunCliAsync("reveal", "--input", outputPdfPath, "--output", revealedZipPath);

        Assert.Equal(1, reveal.ExitCode);
        Assert.Contains("Embedded header length is invalid", reveal.StdErr);
    }

    [Fact]
    public async Task Reveal_FailsForChecksumMismatchAndDoesNotLeavePartialOutput()
    {
        var inputZipPath = WritePayloadZip("mismatch.zip");
        var outputPdfPath = Path.Combine(_workspacePath, "mismatch.pdf");
        var revealedZipPath = Path.Combine(_workspacePath, "mismatch-out.zip");

        await RunCliAsync("hide", "--input", inputZipPath, "--output", outputPdfPath);
        await CorruptPayloadByteAsync(outputPdfPath);

        var reveal = await RunCliAsync("reveal", "--input", outputPdfPath, "--output", revealedZipPath);

        Assert.Equal(1, reveal.ExitCode);
        Assert.Contains("checksum mismatch", reveal.StdErr, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(revealedZipPath));
    }

    [Fact]
    public async Task HideAndReveal_RefuseOverwriteAndInputConflicts()
    {
        var inputZipPath = WritePayloadZip("conflict.zip");
        var carrierPath = Path.Combine(_workspacePath, "conflict-carrier.pdf");
        var existingOutputPath = Path.Combine(_workspacePath, "already-there.pdf");
        var hiddenPdfPath = Path.Combine(_workspacePath, "hidden.pdf");

        await File.WriteAllBytesAsync(carrierPath, MinimalPdfBuilder.CreatePdf());
        await File.WriteAllTextAsync(existingOutputPath, "existing");
        await RunCliAsync("hide", "--input", inputZipPath, "--output", hiddenPdfPath);

        var outputEqualsInput = await RunCliAsync("hide", "--input", inputZipPath, "--output", inputZipPath);
        var outputEqualsCarrier = await RunCliAsync("hide", "--input", inputZipPath, "--output", carrierPath, "--carrier", carrierPath);
        var overwriteExisting = await RunCliAsync("hide", "--input", inputZipPath, "--output", existingOutputPath);
        var revealConflict = await RunCliAsync("reveal", "--input", hiddenPdfPath, "--output", hiddenPdfPath);

        Assert.Equal(1, outputEqualsInput.ExitCode);
        Assert.Contains("different from the input ZIP path", outputEqualsInput.StdErr);

        Assert.Equal(1, outputEqualsCarrier.ExitCode);
        Assert.Contains("different from the carrier PDF path", outputEqualsCarrier.StdErr);

        Assert.Equal(1, overwriteExisting.ExitCode);
        Assert.Contains("Refusing to overwrite existing file", overwriteExisting.StdErr);

        Assert.Equal(1, revealConflict.ExitCode);
        Assert.Contains("different from the input PDF path", revealConflict.StdErr);
    }

    public void Dispose()
    {
        if (Directory.Exists(_workspacePath))
        {
            Directory.Delete(_workspacePath, recursive: true);
        }
    }

    private string WritePayloadZip(string fileName)
    {
        var path = Path.Combine(_workspacePath, fileName);

        using var fileStream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        using var archive = new ZipArchive(fileStream, ZipArchiveMode.Create, leaveOpen: false);
        var entry = archive.CreateEntry("payload.txt");
        using var entryStream = entry.Open();
        using var writer = new StreamWriter(entryStream, Encoding.UTF8, leaveOpen: false);
        writer.Write($"payload:{Guid.NewGuid():N}");
        return path;
    }

    private async Task<CliResult> RunCliAsync(params string[] args)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var exitCode = await CliApplication.RunAsync(args, stdout, stderr);
        return new CliResult(exitCode, stdout.ToString(), stderr.ToString());
    }

    private static async Task CorruptHeaderMagicAsync(string pdfPath)
    {
        var data = await File.ReadAllBytesAsync(pdfPath);
        var containerStart = GetContainerStart(data);
        data[containerStart] ^= 0x01;
        await File.WriteAllBytesAsync(pdfPath, data);
    }

    private static async Task CorruptPayloadByteAsync(string pdfPath)
    {
        var data = await File.ReadAllBytesAsync(pdfPath);
        var containerStart = GetContainerStart(data);
        var headerLength = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(containerStart + 10, 4));
        var payloadIndex = containerStart + headerLength;
        data[payloadIndex] ^= 0x01;
        await File.WriteAllBytesAsync(pdfPath, data);
    }

    private static async Task CorruptHeaderLengthAsync(string pdfPath, int headerLength)
    {
        var data = await File.ReadAllBytesAsync(pdfPath);
        var containerStart = GetContainerStart(data);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(containerStart + 10, 4), headerLength);
        await File.WriteAllBytesAsync(pdfPath, data);
    }

    private static int GetContainerStart(byte[] data)
    {
        var footerMagic = Encoding.ASCII.GetBytes(EmbeddedPdfContainer.FooterMagicText);
        Assert.True(data.AsSpan(data.Length - EmbeddedPdfContainer.FooterLength, 8).SequenceEqual(footerMagic));
        var containerLength = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(data.Length - 8, 8));
        return data.Length - (int)containerLength;
    }

    private sealed record CliResult(int ExitCode, string StdOut, string StdErr);
}
