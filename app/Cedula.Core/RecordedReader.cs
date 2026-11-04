using System.Text.Json;
namespace Cedula.Core;
public record RecordedEntry(string Application,string Name,string Fid,string File,string Status="Read",string Detail="");
public static class RecordedReader
{
    public static Scan Read(string manifest)
    {
        var root=Path.GetDirectoryName(Path.GetFullPath(manifest))!;
        var entries=JsonSerializer.Deserialize<List<RecordedEntry>>(File.ReadAllBytes(manifest),Format.Json)??throw new InvalidDataException("Invalid recorded manifest");
        var scan=new Scan { Mode="RECORDED EVIDENCE — no live card read",Reader="Recorded import" };
        foreach(var e in entries)
        {
            byte[] bytes=e.File.Length==0?[]:File.ReadAllBytes(Repository.SafePath(root,e.File));
            if(bytes.Length>1024*1024)throw new InvalidDataException("Card object size limit");
            scan.Objects.Add(new(){Application=e.Application,Name=e.Name,Fid=e.Fid,Bytes=bytes,DeclaredLength=bytes.Length,Status=e.Status,Detail=e.Detail,Chunks=bytes.Length>0?[new(0,bytes)]:[]});
        }
        Parser.Process(scan);return scan;
    }
}
