# Hide-N-Sneak

Hide-N-Sneak is a .NET 8 command-line proof of concept for packaging a ZIP file inside a valid PDF carrier and later restoring the original ZIP bytes.

> [!WARNING]
> This tool is for authorized local file handling and interoperability testing only.
> It does **not** provide security, concealment, or encryption.
> Appending extra data after `%%EOF` can be detected by forensic tooling and may be rejected by strict PDF validators or some viewers.
> Password protection is **not** implemented.

## What it does

- `hide` embeds a ZIP payload after a visible PDF document.
- `reveal` validates the embedded container and restores the original ZIP bytes.
- `inspect` reports whether an embedded payload is present and whether its SHA-256 checksum still matches.

If you do not supply a carrier PDF, Hide-N-Sneak generates a minimal one-page PDF that opens in common readers.

## Build

```powershell
dotnet build /home/runner/work/Hide-N-Sneak/Hide-N-Sneak/HideNSneak.slnx
```

```bash
dotnet build /home/runner/work/Hide-N-Sneak/Hide-N-Sneak/HideNSneak.slnx
```

## Test

```powershell
dotnet test /home/runner/work/Hide-N-Sneak/Hide-N-Sneak/HideNSneak.slnx
```

```bash
dotnet test /home/runner/work/Hide-N-Sneak/Hide-N-Sneak/HideNSneak.slnx
```

## Usage

Run the CLI from the repository root:

```powershell
dotnet run --project /home/runner/work/Hide-N-Sneak/Hide-N-Sneak/src/HideNSneak/HideNSneak.csproj -- hide --input C:\path\payload.zip --output C:\path\carrier.pdf
dotnet run --project /home/runner/work/Hide-N-Sneak/Hide-N-Sneak/src/HideNSneak/HideNSneak.csproj -- hide --input C:\path\payload.zip --output C:\path\carrier.pdf --carrier C:\path\visible.pdf
dotnet run --project /home/runner/work/Hide-N-Sneak/Hide-N-Sneak/src/HideNSneak/HideNSneak.csproj -- inspect --input C:\path\carrier.pdf
dotnet run --project /home/runner/work/Hide-N-Sneak/Hide-N-Sneak/src/HideNSneak/HideNSneak.csproj -- reveal --input C:\path\carrier.pdf --output C:\path\payload.zip
```

```bash
dotnet run --project /home/runner/work/Hide-N-Sneak/Hide-N-Sneak/src/HideNSneak/HideNSneak.csproj -- hide --input /path/payload.zip --output /path/carrier.pdf
dotnet run --project /home/runner/work/Hide-N-Sneak/Hide-N-Sneak/src/HideNSneak/HideNSneak.csproj -- hide --input /path/payload.zip --output /path/carrier.pdf --carrier /path/visible.pdf
dotnet run --project /home/runner/work/Hide-N-Sneak/Hide-N-Sneak/src/HideNSneak/HideNSneak.csproj -- inspect --input /path/carrier.pdf
dotnet run --project /home/runner/work/Hide-N-Sneak/Hide-N-Sneak/src/HideNSneak/HideNSneak.csproj -- reveal --input /path/carrier.pdf --output /path/payload.zip
```

Use `--help` or `<command> --help` for command-specific help text.

## Embedded format

Hide-N-Sneak appends a custom container after the PDF content:

1. The carrier PDF bytes remain unchanged.
2. A fixed application marker and version identify the embedded container.
3. The header stores explicit lengths for the header and payload, the original filename and extension metadata, and the expected SHA-256 checksum.
4. The original ZIP bytes follow directly after the header.
5. A fixed footer marker stores the total appended-container length so the tool can locate the container from the end of the file.

During `inspect` and `reveal`, the tool validates:

- the header marker and version;
- recorded sizes against configurable limits;
- that the container stays within file bounds;
- that the payload checksum matches the recorded SHA-256 value.

## Limits

The CLI enforces conservative defaults and rejects malformed or oversized containers:

- `HNS_MAX_PAYLOAD_BYTES` (default: `536870912`, or 512 MiB)
- `HNS_MAX_METADATA_BYTES` (default: `4096`)

These environment variables can be set before running the CLI if you need lower or higher bounds in a controlled environment.

## Limitations

- This is packaging/obfuscation only, not secure storage.
- The appended data is outside the formal PDF structure and may be visible to forensic tools.
- Some PDF validators or viewers may reject files with trailing data after `%%EOF`.
- The tool expects the footer marker to remain at the end of the file. If other tools append extra bytes afterwards, extraction will fail.
- No encryption, password protection, or access control is included.

## Safety and legal guidance

Only use this tool with files you are authorized to handle and move. Review your organization’s policies before using appended-container PDFs in workflows that rely on strict file validation, DLP systems, archival tooling, or forensic inspection.
