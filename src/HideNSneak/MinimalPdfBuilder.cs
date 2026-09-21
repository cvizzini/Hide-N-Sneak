using System.Text;

namespace HideNSneak;

public static class MinimalPdfBuilder
{
    public static byte[] CreatePdf()
    {
        var objects = new[]
        {
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
            BuildContentsObject(),
            "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        };

        using var stream = new MemoryStream();
        WriteAscii(stream, "%PDF-1.4\n");
        stream.Write([0x25, 0xE2, 0xE3, 0xCF, 0xD3, 0x0A]);

        var offsets = new List<long>(objects.Length);
        foreach (var pdfObject in objects)
        {
            offsets.Add(stream.Position);
            WriteAscii(stream, pdfObject);
        }

        var xrefPosition = stream.Position;
        WriteAscii(stream, $"xref\n0 {objects.Length + 1}\n");
        WriteAscii(stream, "0000000000 65535 f \n");
        foreach (var offset in offsets)
        {
            WriteAscii(stream, $"{offset:0000000000} 00000 n \n");
        }

        WriteAscii(stream, $"trailer\n<< /Size {objects.Length + 1} /Root 1 0 R >>\n");
        WriteAscii(stream, $"startxref\n{xrefPosition}\n%%EOF\n");
        return stream.ToArray();
    }

    private static string BuildContentsObject()
    {
        const string content = "BT\n/F1 18 Tf\n72 96 Td\n(PDF carrier document) Tj\nET\n";
        var contentLength = Encoding.ASCII.GetByteCount(content);
        return $"4 0 obj\n<< /Length {contentLength} >>\nstream\n{content}endstream\nendobj\n";
    }

    private static void WriteAscii(Stream stream, string value)
    {
        var bytes = Encoding.ASCII.GetBytes(value);
        stream.Write(bytes, 0, bytes.Length);
    }
}
