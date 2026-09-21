using System.Globalization;

namespace HideNSneak;

public static class CliApplication
{
    public static Task<int> RunAsync(string[] args, TextWriter stdout, TextWriter stderr, CancellationToken cancellationToken = default)
    {
        return new Application(stdout, stderr, cancellationToken).RunAsync(args);
    }

    private sealed class Application(TextWriter stdout, TextWriter stderr, CancellationToken cancellationToken)
    {
        private readonly PdfZipPackager _packager = new();

        public async Task<int> RunAsync(string[] args)
        {
            if (args.Length == 0 || IsHelpArgument(args[0]))
            {
                await WriteHelpAsync();
                return 0;
            }

            var command = args[0].ToLowerInvariant();
            var options = args.Skip(1).ToArray();

            try
            {
                return command switch
                {
                    "hide" => await RunHideAsync(options),
                    "reveal" => await RunRevealAsync(options),
                    "inspect" => await RunInspectAsync(options),
                    _ => await FailAsync($"Unknown command '{args[0]}'.")
                };
            }
            catch (OperationCanceledException)
            {
                return await FailAsync("Operation cancelled.");
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or InvalidDataException or UnauthorizedAccessException)
            {
                return await FailAsync(ex.Message);
            }
        }

        private async Task<int> RunHideAsync(string[] args)
        {
            if (args.Length == 1 && IsHelpArgument(args[0]))
            {
                await WriteHideHelpAsync();
                return 0;
            }

            var options = ParseOptions(args, ["--input", "--output", "--carrier"]);
            var input = GetRequiredOption(options, "--input");
            var output = GetRequiredOption(options, "--output");
            options.TryGetValue("--carrier", out var carrier);

            await _packager.HideAsync(input, output, carrier, HideNSneakLimits.FromEnvironment(), cancellationToken);
            await stdout.WriteLineAsync($"Created '{output}'.");
            return 0;
        }

        private async Task<int> RunRevealAsync(string[] args)
        {
            if (args.Length == 1 && IsHelpArgument(args[0]))
            {
                await WriteRevealHelpAsync();
                return 0;
            }

            var options = ParseOptions(args, ["--input", "--output"]);
            var input = GetRequiredOption(options, "--input");
            var output = GetRequiredOption(options, "--output");

            var result = await _packager.RevealAsync(input, output, HideNSneakLimits.FromEnvironment(), cancellationToken);
            await stdout.WriteLineAsync($"Extracted {result.PayloadLength.ToString(CultureInfo.InvariantCulture)} bytes to '{output}'.");
            return 0;
        }

        private async Task<int> RunInspectAsync(string[] args)
        {
            if (args.Length == 1 && IsHelpArgument(args[0]))
            {
                await WriteInspectHelpAsync();
                return 0;
            }

            var options = ParseOptions(args, ["--input"]);
            var input = GetRequiredOption(options, "--input");
            var result = await _packager.InspectAsync(input, HideNSneakLimits.FromEnvironment(), cancellationToken);

            await stdout.WriteLineAsync($"Payload present: {(result.PayloadPresent ? "yes" : "no")}");

            if (!result.PayloadPresent)
            {
                return 0;
            }

            await stdout.WriteLineAsync($"Payload size: {result.PayloadLength.ToString(CultureInfo.InvariantCulture)} bytes");
            await stdout.WriteLineAsync($"Original file name: {FormatOptionalValue(result.OriginalFileName)}");
            await stdout.WriteLineAsync($"Original extension: {FormatOptionalValue(result.OriginalExtension)}");
            await stdout.WriteLineAsync($"SHA-256: {result.Sha256Hex}");
            await stdout.WriteLineAsync($"Checksum valid: {(result.ChecksumValid ? "yes" : "no")}");
            return 0;
        }

        private static string FormatOptionalValue(string? value)
        {
            return string.IsNullOrWhiteSpace(value) ? "(not recorded)" : value;
        }

        private static bool IsHelpArgument(string value)
        {
            return value is "--help" or "-h" or "/?";
        }

        private static Dictionary<string, string> ParseOptions(string[] args, HashSet<string> supportedOptions)
        {
            var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            for (var index = 0; index < args.Length; index++)
            {
                var argument = args[index];

                if (IsHelpArgument(argument))
                {
                    throw new ArgumentException("Help must be requested immediately after the command.");
                }

                if (!argument.StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ArgumentException($"Unexpected argument '{argument}'.");
                }

                if (!supportedOptions.Contains(argument))
                {
                    throw new ArgumentException($"Unknown option '{argument}'.");
                }

                if (index == args.Length - 1 || args[index + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ArgumentException($"Missing value for option '{argument}'.");
                }

                options[argument] = args[++index];
            }

            return options;
        }

        private static string GetRequiredOption(IReadOnlyDictionary<string, string> options, string optionName)
        {
            return options.TryGetValue(optionName, out var value)
                ? value
                : throw new ArgumentException($"Missing required option '{optionName}'.");
        }

        private async Task<int> FailAsync(string message)
        {
            await stderr.WriteLineAsync($"Error: {message}");
            await stderr.WriteLineAsync("Run with --help for usage information.");
            return 1;
        }

        private async Task WriteHelpAsync()
        {
            await stdout.WriteLineAsync("Hide-N-Sneak PDF ZIP utility");
            await stdout.WriteLineAsync();
            await stdout.WriteLineAsync("Usage:");
            await stdout.WriteLineAsync("  HideNSneak hide --input <zip> --output <pdf> [--carrier <pdf>]");
            await stdout.WriteLineAsync("  HideNSneak reveal --input <pdf> --output <zip>");
            await stdout.WriteLineAsync("  HideNSneak inspect --input <pdf>");
            await stdout.WriteLineAsync();
            await stdout.WriteLineAsync("Warnings:");
            await stdout.WriteLineAsync("  This tool only packages a ZIP inside a PDF carrier.");
            await stdout.WriteLineAsync("  It does not provide security, concealment, or encryption.");
            await stdout.WriteLineAsync("  Password protection is not implemented.");
            await stdout.WriteLineAsync();
            await stdout.WriteLineAsync("Use '<command> --help' for command-specific details.");
        }

        private async Task WriteHideHelpAsync()
        {
            await stdout.WriteLineAsync("Usage:");
            await stdout.WriteLineAsync("  HideNSneak hide --input <zip> --output <pdf> [--carrier <pdf>]");
            await stdout.WriteLineAsync();
            await stdout.WriteLineAsync("Options:");
            await stdout.WriteLineAsync("  --input     Path to the ZIP payload to embed.");
            await stdout.WriteLineAsync("  --output    Path to the PDF file to create.");
            await stdout.WriteLineAsync("  --carrier   Optional existing PDF carrier. When omitted, a minimal PDF is generated.");
        }

        private async Task WriteRevealHelpAsync()
        {
            await stdout.WriteLineAsync("Usage:");
            await stdout.WriteLineAsync("  HideNSneak reveal --input <pdf> --output <zip>");
            await stdout.WriteLineAsync();
            await stdout.WriteLineAsync("Options:");
            await stdout.WriteLineAsync("  --input     Path to the PDF carrier.");
            await stdout.WriteLineAsync("  --output    Path to the ZIP file to create.");
        }

        private async Task WriteInspectHelpAsync()
        {
            await stdout.WriteLineAsync("Usage:");
            await stdout.WriteLineAsync("  HideNSneak inspect --input <pdf>");
            await stdout.WriteLineAsync();
            await stdout.WriteLineAsync("Options:");
            await stdout.WriteLineAsync("  --input     Path to the PDF carrier to inspect.");
        }
    }
}
