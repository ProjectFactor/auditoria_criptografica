using System.Globalization;
using System.Text;
namespace Cedula.Core;
// Minimal offline PDF writer: text, pagination and unmodified JPEG image streams.
public static class PdfReport
{
    static byte[] B(string value)=>Encoding.Latin1.GetBytes(value);
    public static byte[] Create(Scan s)
    {
        var objects=new List<byte[]> { Array.Empty<byte>(),Array.Empty<byte>(),B("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>") };
        int Add(byte[] b){objects.Add(b);return objects.Count;}
        var images=new List<(int Id,int Width,int Height,string Name)>();
        foreach(var asset in s.Assets.Where(x=>x.Kind is "portrait" or "signature"))
        {
            try { var (w,h,c)=JpegSize(asset.Bytes);int id=Add(Stream($"/Type /XObject /Subtype /Image /Width {w} /Height {h} /ColorSpace /{(c==1?"DeviceGray":"DeviceRGB")} /BitsPerComponent 8 /Filter /DCTDecode",asset.Bytes));images.Add((id,w,h,asset.Kind)); }
            catch(InvalidDataException) { }
        }
        var lines=new List<(string Text,bool Warning)>();
        void Line(string text,bool warning=false)
        {
            foreach(var row in string.Concat(text.Select(c=>c>255 && c!='—' ? "\\u"+((int)c).ToString("X4") : c.ToString())).Replace("\r","").Split('\n'))
                for(int i=0;i<Math.Max(row.Length,1);i+=88) lines.Add((row.Substring(i,Math.Min(88,row.Length-i)),warning));
        }
        Line("CEDULA READER / DOCUMENT REPORT");Line(s.Label);Line(s.Summary);Line("Scan: "+s.Id+" / "+s.Time.ToString("O"));
        Line("SECURITY FINDINGS");foreach(var f in s.Findings){Line(f.Title,true);Line(f.Source,true);Line(f.Evidence,true);}
        Line("IDENTITY");foreach(var f in s.Fields)Line(f.Name+" ["+f.Source+"]: "+f.Value);
        Line("DATA INVENTORY");foreach(var o in s.Objects)Line($"{o.Identity}: {o.Status}, {o.Bytes.Length} bytes; {o.Detail}\nSHA-256: {o.Sha256}");
        Line("VERIFICATION");foreach(var c in s.Checks)Line($"{c.Source} / {c.Test}: {c.Result}. {c.Detail}");
        Line("CERTIFICATES AND PUBLIC KEYS");foreach(var k in s.Keys){Line(k.Summary,k.Findings.Count>0);Line(k.Details);}
        var pageIds=new List<int>();
        if(images.Count>0)
        {
            var content=new StringBuilder("BT /F1 18 Tf 50 790 Td (Original card images) Tj ET\n");
            int y=730; var resources=new StringBuilder(); int n=0;
            foreach(var img in images.Take(2))
            {
                double scale=Math.Min(220d/img.Width,270d/img.Height);double w=img.Width*scale,h=img.Height*scale;
                content.Append(CultureInfo.InvariantCulture,$"q {w:F2} 0 0 {h:F2} 50 {y-h:F2} cm /I{n} Do Q\n");resources.Append($"/I{n} {img.Id} 0 R ");n++;y-=330;
            }
            int stream=Add(Stream("",B(content.ToString())));
            pageIds.Add(Add(B($"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> /XObject << {resources} >> >> /Contents {stream} 0 R >>")));
        }
        foreach(var batch in lines.Chunk(54))
        {
            var content=new StringBuilder("BT /F1 9 Tf 50 800 Td 14 TL\n");
            foreach(var line in batch)content.Append(line.Warning?"0.75 0 0 rg ":"0 0 0 rg ").Append('(').Append(Escape(line.Text)).Append(") Tj T*\n");
            content.Append("ET");int stream=Add(Stream("",B(content.ToString())));
            pageIds.Add(Add(B($"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {stream} 0 R >>")));
        }
        objects[0]=B("<< /Type /Catalog /Pages 2 0 R >>");objects[1]=B($"<< /Type /Pages /Count {pageIds.Count} /Kids [{string.Join(" ",pageIds.Select(x=>$"{x} 0 R"))}] >>");
        using var output=new MemoryStream();output.Write(B("%PDF-1.4\n%âãÏÓ\n"));var offsets=new List<long>();
        for(int i=0;i<objects.Count;i++){offsets.Add(output.Position);output.Write(B($"{i+1} 0 obj\n"));output.Write(objects[i]);output.Write(B("\nendobj\n"));}
        long xref=output.Position;output.Write(B($"xref\n0 {objects.Count+1}\n0000000000 65535 f \n"));foreach(long offset in offsets)output.Write(B($"{offset:D10} 00000 n \n"));
        output.Write(B($"trailer\n<< /Size {objects.Count+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"));return output.ToArray();
    }
    static byte[] Stream(string dict,byte[] bytes)=>Ber.Join(B($"<< {dict} /Length {bytes.Length} >>\nstream\n"),bytes,B("\nendstream"));
    static string Escape(string text)=>text.Replace("—","-").Replace("·","/").Replace("\u2192","->").Replace("\\","\\\\").Replace("(","\\(").Replace(")","\\)");
    public static (int Width,int Height,int Components) JpegSize(byte[] bytes)
    {
        int p=2;while(p+4<bytes.Length)
        {
            if(bytes[p++]!=255)throw new InvalidDataException("Invalid JPEG marker");byte marker=bytes[p++];if(marker==255){p--;continue;}
            if(marker is 0xd9 or 0xda)break;int len=bytes[p]*256+bytes[p+1];if(len<2||p+len>bytes.Length)throw new InvalidDataException("JPEG length");
            if(marker is 0xc0 or 0xc1 or 0xc2){if(len<8)break;return(bytes[p+5]*256+bytes[p+6],bytes[p+3]*256+bytes[p+4],bytes[p+7]);}p+=len;
        }
        throw new InvalidDataException("Unsupported JPEG");
    }
}
