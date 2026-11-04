using System.Security.Cryptography;
using System.Text.Json;
namespace Cedula.Core;
public static class Format
{
    public static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };
    public static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    public static string Hex(byte[] bytes) => Convert.ToHexString(bytes);
    public static byte[] Bytes(string hex) => Convert.FromHexString(hex.Replace(" ", ""));
}
public record Finding(string Rule, string Severity, string Title, string Evidence, string Source, string Version = "1");
public record Field(string Source, string Tag, string Name, string Value, string RawHex);
public record Chunk(int Offset, byte[] Bytes);
public class CardObject
{
    public string Application { get; set; } = "eMRTD";
    public string Name { get; set; } = "";
    public string Fid { get; set; } = "";
    public string Status { get; set; } = "Read";
    public string Detail { get; set; } = "";
    public int? DeclaredLength { get; set; }
    public byte[] Bytes { get; set; } = [];
    public List<Chunk> Chunks { get; set; } = [];
    public string Sha256 => Format.Hash(Bytes);
    public string Identity => Application + "/" + Name;
}
public record Asset(string Name, string Kind, string Source, int Offset, byte[] Bytes, bool Original = true);
public class KeyInfo
{
    public string Source { get; set; } = "";
    public string Algorithm { get; set; } = "";
    public int Bits { get; set; }
    public string Parameters { get; set; } = "";
    public string Environment { get; set; } = "Unknown";
    public List<Finding> Findings { get; set; } = [];
    public string Summary => $"{Source} · {Algorithm}-{Bits}" + (Findings.Count > 0 ? " · WARNING" : "");
    public string Details { get; set; } = "";
}
public record Check(string Source, string Test, string Result, string Detail);
public class Scan
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string ProfileId { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Time { get; set; } = DateTimeOffset.UtcNow;
    public string Mode { get; set; } = "Recorded evidence";
    // Claims carried by an imported archive are retained as claims, never as a local acquisition.
    public string SourceModeClaim { get; set; } = "";
    public string ImportedArchiveSha256 { get; set; } = "";
    public DateTimeOffset? ImportedAtUtc { get; set; }
    public string Reader { get; set; } = "";
    public string State { get; set; } = "Complete";
    public string Error { get; set; } = "";
    public string ParserVersion { get; set; } = "0.1.0";
    public List<CardObject> Objects { get; set; } = [];
    public List<Field> Fields { get; set; } = [];
    public List<Asset> Assets { get; set; } = [];
    public List<KeyInfo> Keys { get; set; } = [];
    public List<Check> Checks { get; set; } = [];
    public List<Finding> Findings => Keys.SelectMany(x => x.Findings).ToList();
    public string Name => Fields.FirstOrDefault(x => x.Name == "Full name")?.Value ?? Fields.FirstOrDefault(x => x.Name == "Name")?.Value ?? "Unnamed document";
    public string Document => Fields.FirstOrDefault(x => x.Name == "Document number")?.Value ?? "Unknown number";
    public string Issuer => Fields.FirstOrDefault(x => x.Name == "Issuing state")?.Value ?? "Unknown issuer";
    public string Label => $"{Name} · {Document} · {Time:yyyy-MM-dd HH:mm}";
    public List<string>? AdvertisedGroups
    {
        get
        {
            var com=Objects.FirstOrDefault(x=>x.Name=="EF.COM"&&x.Status=="Read");if(com==null)return null;
            try
            {
                var list=Ber.Walk(com.Bytes).Single(x=>x.Tag=="5C").Value;
                var tags=new Dictionary<byte,string>{{0x61,"DG1"},{0x75,"DG2"},{0x63,"DG3"},{0x76,"DG4"},{0x65,"DG5"},{0x66,"DG6"},{0x67,"DG7"},{0x68,"DG8"},{0x69,"DG9"},{0x6a,"DG10"},{0x6b,"DG11"},{0x6c,"DG12"},{0x6d,"DG13"},{0x6e,"DG14"},{0x6f,"DG15"},{0x70,"DG16"}};
                return list.Select(x=>tags.GetValueOrDefault(x,"Unknown tag "+x.ToString("X2"))).ToList();
            }
            catch{return null;}
        }
    }
    public string DataGroupSummary => AdvertisedGroups is { } groups ? $"{groups.Count(g=>Objects.Any(o=>o.Name==g&&o.Application=="eMRTD"&&o.Status=="Read"))} of {groups.Count} advertised data groups acquired." : "Advertised data-group inventory unavailable.";
    public string Summary => $"{Mode} · {State}\n{Objects.Count(x => x.Status == "Read")} objects read · {Objects.Count(x => x.Status != "Read")} unavailable/partial · {Findings.Count} warnings\n{DataGroupSummary}\nIssuer trust unresolved; revocation not checked.";
}
