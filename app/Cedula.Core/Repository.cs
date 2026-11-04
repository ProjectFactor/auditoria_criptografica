using System.IO.Compression;
using System.Text;
using System.Text.Json;
namespace Cedula.Core;
public record ManifestEntry(string Path, string Role, long Length, string Sha256, string? Source = null, int? Offset = null);
public record Manifest(string Schema, string ProfileId, string ScanId, List<ManifestEntry> Files);
public sealed class Repository : IDisposable
{
    public string Root { get; }
    readonly FileStream gate;
    public Repository(string root)
    {
        Root=Path.GetFullPath(root);Directory.CreateDirectory(Root);
        gate=new FileStream(Path.Combine(Root,".lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
    }
    public void Dispose()=>gate.Dispose();
    public int RecoverAcquisitions()
    {
        int count=0;
        foreach(var directory in Directory.GetDirectories(Root,".acquiring-*"))
        {
            string index=Path.Combine(directory,"acquisition.json");if(!File.Exists(index))continue;
            Scan? scan;
            try{scan=JsonSerializer.Deserialize<Scan>(File.ReadAllBytes(index),Format.Json);}catch(JsonException){continue;}
            if(scan==null||Directory.Exists(ScanPath(scan)))continue;
            scan.State="Incomplete";scan.Error="Recovered interrupted acquisition; retained chunks remain in acquisition folder.";
            Parser.Process(scan);Save(scan);count++;
        }
        return count;
    }
    public List<Scan> List() => Directory.EnumerateFiles(Root,"scan.json",SearchOption.AllDirectories)
        .Where(x=>!Path.GetRelativePath(Root,x).Split(Path.DirectorySeparatorChar).Any(y=>y.StartsWith('.')))
        .Select(x=>
        {
            string folder=Path.GetDirectoryName(x)!;
            var scan=ReadValidated(folder);
            if(!string.Equals(Path.GetFullPath(folder),ScanPath(scan),StringComparison.Ordinal))
                throw new InvalidDataException("Stored scan path does not match its identity");
            return scan;
        }).OrderByDescending(x=>x.Time).ToList();
    public string Save(Scan scan)
    {
        Id(scan.Id); Id(scan.ProfileId);
        string parent=Path.Combine(Root,"profiles",scan.ProfileId,"scans");Directory.CreateDirectory(parent);
        string target=Path.Combine(parent,scan.Id), temp=Path.Combine(parent,".pending-"+scan.Id);
        if(Directory.Exists(target)||Directory.Exists(temp)) throw new IOException("Scan ID already exists; refusing overwrite");
        Parser.Process(scan);
        try
        {
            WriteFolder(scan,temp);
            Directory.Move(temp,target);
            return target;
        }
        finally { if(Directory.Exists(temp))Directory.Delete(temp,true); }
    }
    static Scan ReadValidated(string folder,bool storedProvenance=true)
    {
        ValidateFolder(folder);
        var scan=JsonSerializer.Deserialize<Scan>(File.ReadAllBytes(Path.Combine(folder,"scan.json")),Format.Json)
            ??throw new InvalidDataException("Invalid scan snapshot");
        // Manifest hashes establish consistency, not the truth of imported derived metadata.
        Parser.Process(scan);
        if(storedProvenance&&scan.Mode is not "Imported evidence" and not "Stored evidence")
        {
            // Unsigned cached metadata cannot prove that this process acquired a live card.
            scan.SourceModeClaim=scan.Mode;
            scan.Mode="Stored evidence";
        }
        return scan;
    }
    static void WriteFolder(Scan scan,string folder)
    {
        Directory.CreateDirectory(folder);
        var entries=new List<ManifestEntry>();
        void Write(string path,byte[] bytes,string role,string? source=null,int? offset=null)
        {
            string dest=SafePath(folder,path);Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            using(var f=new FileStream(dest,FileMode.CreateNew,FileAccess.Write,FileShare.None)) { f.Write(bytes); f.Flush(true); }
            entries.Add(new(path,role,bytes.LongLength,Format.Hash(bytes),source,offset));
        }
        foreach(var o in scan.Objects)
        {
            string name=Component(o.Application)+"/"+Component(o.Name);
            if(o.Bytes.Length>0) Write("raw/"+name+".bin",o.Bytes,"original",o.Identity,0);
            foreach(var c in o.Chunks) Write($"chunks/{name}/{c.Offset:D8}.bin",c.Bytes,"original-chunk",o.Identity,c.Offset);
        }
        foreach(var a in scan.Assets.DistinctBy(x=>x.Name)) Write(a.Name,a.Bytes,a.Original?"extracted-original":"derived",a.Source,a.Offset);
        Write("scan.json",JsonSerializer.SerializeToUtf8Bytes(scan,Format.Json),"snapshot");
        Write("acquisition.json",JsonSerializer.SerializeToUtf8Bytes(scan.Objects.Select(x=>new { x.Application,x.Name,x.Fid,x.Status,x.Detail,x.DeclaredLength,Length=x.Bytes.Length,x.Sha256,Chunks=x.Chunks.Select(c=>new{c.Offset,Length=c.Bytes.Length,Sha256=Format.Hash(c.Bytes)})}),Format.Json),"acquisition");
        Write("derived/data.json",JsonSerializer.SerializeToUtf8Bytes(scan.Fields,Format.Json),"derived");
        Write("derived/certificates.json",JsonSerializer.SerializeToUtf8Bytes(scan.Keys,Format.Json),"derived");
        Write("derived/verification.json",JsonSerializer.SerializeToUtf8Bytes(scan.Checks,Format.Json),"derived");
        Write("derived/findings.json",JsonSerializer.SerializeToUtf8Bytes(scan.Findings,Format.Json),"derived");
        Write("report.pdf",PdfReport.Create(scan),"derived");
        Write("README.txt",Encoding.UTF8.GetBytes("Cédula Reader 0.1\nUnencrypted local scan. raw/ contains byte-accurate card payloads after secure-messaging decryption. Images and DER originals are exact slices; PEM/JSON/PDF are derived. Private keys and CAN are not exported.\nMode: "+scan.Mode+"\n"+scan.Summary),"documentation");
        File.WriteAllBytes(Path.Combine(folder,"manifest.json"),JsonSerializer.SerializeToUtf8Bytes(new Manifest("cedula-scan/1",scan.ProfileId,scan.Id,entries),Format.Json));
        ValidateFolder(folder);
    }
    public string ScanPath(Scan scan){Id(scan.ProfileId);Id(scan.Id);return Path.Combine(Root,"profiles",scan.ProfileId,"scans",scan.Id);}
    public void DeleteProfile(string id) { Id(id); var path=Path.Combine(Root,"profiles",id); if(Directory.Exists(path)) Directory.Delete(path,true); }
    public void Export(IEnumerable<Scan> scans,string destination)
    {
        var selected=scans.ToList();if(selected.Count==0)throw new InvalidOperationException("No scans selected");
        string full=Path.GetFullPath(destination);string temp=full+".partial-"+Guid.NewGuid().ToString("N");
        string stage=Path.Combine(Root,".export-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(stage);
        try
        {
            using(var zip=ZipFile.Open(temp,ZipArchiveMode.Create))
            {
                foreach(var scan in selected)
                {
                    var canonical=ReadValidated(ScanPath(scan));
                    var folder=Path.Combine(stage,canonical.ProfileId,canonical.Id);
                    WriteFolder(canonical,folder);
                    foreach(var file in Directory.EnumerateFiles(folder,"*",SearchOption.AllDirectories))
                        zip.CreateEntryFromFile(file,$"profiles/{scan.ProfileId}/scans/{scan.Id}/"+Path.GetRelativePath(folder,file).Replace('\\','/'),CompressionLevel.Optimal);
                }
            }
            using(var zip=ZipFile.OpenRead(temp))
            {
                foreach(var entry in zip.Entries.Where(x=>x.FullName.EndsWith("/manifest.json")))
                {
                    using var stream=entry.Open();var m=JsonSerializer.Deserialize<Manifest>(stream,Format.Json)!;
                    var prefix=entry.FullName[..^"manifest.json".Length];
                    foreach(var f in m.Files)
                    {
                        var e=zip.GetEntry(prefix+f.Path)??throw new InvalidDataException("Missing ZIP entry");
                        using var input=e.Open();using var data=new MemoryStream();input.CopyTo(data);
                        if(e.Length!=f.Length||Format.Hash(data.ToArray())!=f.Sha256)throw new InvalidDataException("ZIP integrity mismatch");
                    }
                }
            }
            File.Move(temp,full,true);
        }
        finally { if(File.Exists(temp))File.Delete(temp);Directory.Delete(stage,true); }
    }
    public void Restore(string archive)
    {
        string stage=Path.Combine(Root,".restore-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(stage);
        string canonicalStage=Path.Combine(Root,".restore-canonical-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(canonicalStage);
        try
        {
            using(var zip=ZipFile.OpenRead(archive))
            {
                if(zip.Entries.Count>10000||zip.Entries.Sum(x=>x.Length)>512L*1024*1024)throw new InvalidDataException("Archive exceeds import limits");
                foreach(var e in zip.Entries)
                {
                    if(e.Length>32L*1024*1024)throw new InvalidDataException("Entry exceeds limit");
                    var dest=SafePath(stage,e.FullName);Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                    using var source=e.Open();using var output=new FileStream(dest,FileMode.CreateNew);source.CopyTo(output);
                }
            }
            var manifests=Directory.GetFiles(stage,"manifest.json",SearchOption.AllDirectories);
            if(manifests.Length==0)throw new InvalidDataException("No scan manifests");
            var moves=new List<(string From,string To)>();
            string archiveHash;
            using(var source=File.OpenRead(archive))archiveHash=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(source)).ToLowerInvariant();
            foreach(var manifest in manifests)
            {
                string folder=Path.GetDirectoryName(manifest)!;
                var scan=ReadValidated(folder,storedProvenance:false);Id(scan.ProfileId);Id(scan.Id);
                var dest=ScanPath(scan);if(Directory.Exists(dest)||moves.Any(x=>x.To==dest))throw new IOException("Existing scan ID; import cancelled without replacing it");
                scan.SourceModeClaim=scan.Mode;
                scan.Mode="Imported evidence";
                scan.ImportedArchiveSha256=archiveHash;
                scan.ImportedAtUtc=DateTimeOffset.UtcNow;
                string canonical=Path.Combine(canonicalStage,scan.ProfileId,scan.Id);
                WriteFolder(scan,canonical);
                moves.Add((canonical,dest));
            }
            foreach(var move in moves){Directory.CreateDirectory(Path.GetDirectoryName(move.To)!);Directory.Move(move.From,move.To);}
        }
        finally { Directory.Delete(stage,true);Directory.Delete(canonicalStage,true); }
    }
    public static void ValidateFolder(string folder)
    {
        var m=JsonSerializer.Deserialize<Manifest>(File.ReadAllBytes(Path.Combine(folder,"manifest.json")),Format.Json)??throw new InvalidDataException("Invalid manifest");
        if(m.Schema!="cedula-scan/1")throw new InvalidDataException("Unsupported manifest schema");
        var actualFiles=Directory.GetFiles(folder,"*",SearchOption.AllDirectories).Select(x=>Path.GetRelativePath(folder,x).Replace('\\','/')).Where(x=>x!="manifest.json").ToHashSet(StringComparer.Ordinal);
        if(!actualFiles.SetEquals(m.Files.Select(x=>x.Path))||!actualFiles.Contains("scan.json"))throw new InvalidDataException("Manifest must cover every payload file");
        Id(m.ProfileId);Id(m.ScanId);
        if(m.Files.Select(x=>x.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count()!=m.Files.Count)throw new InvalidDataException("Duplicate manifest paths");
        foreach(var f in m.Files)
        {
            byte[] data=File.ReadAllBytes(SafePath(folder,f.Path));
            if(data.LongLength!=f.Length||Format.Hash(data)!=f.Sha256)throw new InvalidDataException("Integrity mismatch: "+f.Path);
        }
        var scan=JsonSerializer.Deserialize<Scan>(File.ReadAllBytes(Path.Combine(folder,"scan.json")),Format.Json)!;
        if(scan.Id!=m.ScanId||scan.ProfileId!=m.ProfileId)throw new InvalidDataException("Manifest identity mismatch");
        foreach(var o in scan.Objects.Where(x=>x.Bytes.Length>0))
        {
            var raw="raw/"+Component(o.Application)+"/"+Component(o.Name)+".bin";
            if(!m.Files.Any(x=>x.Path==raw)||!File.ReadAllBytes(SafePath(folder,raw)).SequenceEqual(o.Bytes))throw new InvalidDataException("Snapshot/raw mismatch");
        }
    }
    public static string SafePath(string root,string path)
    {
        if(string.IsNullOrWhiteSpace(path)||path.Contains('\\')||path.Contains(':')||path.StartsWith('/')||path.Split('/').Any(x=>x is ".." or "." or ""))throw new InvalidDataException("Unsafe archive path");
        string full=Path.GetFullPath(Path.Combine(root,path));
        if(!full.StartsWith(Path.GetFullPath(root)+Path.DirectorySeparatorChar,StringComparison.Ordinal))throw new InvalidDataException("Path outside data folder");
        return full;
    }
    static void Id(string id){if(!Guid.TryParseExact(id,"N",out _))throw new InvalidDataException("Invalid ID");}
    static string Component(string s)=>string.Concat(s.Select(c=>char.IsAsciiLetterOrDigit(c)||c is '.' or '-' or '_'?c:'_'));
}
