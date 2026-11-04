using Cedula.Core;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Diagnostics;

int passed=0;
void Assert(bool value,string message){if(!value)throw new Exception(message);passed++;Console.WriteLine("PASS "+message);}
void Reject(Action action,string message){bool rejected=false;try{action();}catch{rejected=true;}Assert(rejected,message);}
string fixture=args[0];string output=args.Length>1?args[1]:Path.Combine(Path.GetTempPath(),"cedula-tests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(output);
var scan=RecordedReader.Read(fixture);
Assert(scan.Objects.Count>=9,"Recorded fixture imported");
Assert(scan.Assets.Count(x=>x.Kind is "portrait" or "signature")==2,"Portrait and signature extracted");
Assert(scan.Keys.Any(x=>x.Algorithm=="RSA"&&x.Bits==1024),"RSA modulus measured at 1024 bits");
Assert(scan.Findings.Any(x=>x.Rule=="RSA_UNDERSIZED"&&x.Severity=="Red"),"RSA insecure finding is red");
Assert(scan.Findings.Any(x=>x.Rule=="DEVELOPMENT_KEY"),"Development certificate flagged");
Assert(scan.Keys.Count(x=>x.Algorithm=="EC")==2,"Both distinct EC keys parsed");
Assert(scan.Checks.Count(x=>x.Test=="SOD hash"&&x.Result=="Match")==7,"All seven acquired DG hashes match SOD");
Assert(scan.Checks.Any(x=>x.Source=="eMRTD/DG3"&&x.Result=="Not acquired"),"DG3 remains not acquired");
Assert(scan.Checks.Count(x=>x.Test=="CMS signature"&&x.Result=="Valid")==2,"Both CMS signatures verify independently");
Assert(scan.Checks.Where(x=>x.Test.EndsWith("check digit")).All(x=>x.Result=="Match"),"TD1 extended MRZ check digits pass");
foreach(var asset in scan.Assets.Where(x=>x.Original))
{
    var raw=scan.Objects.Single(x=>x.Identity==asset.Source).Bytes;
    Assert(raw.AsSpan(asset.Offset,asset.Bytes.Length).SequenceEqual(asset.Bytes),"Exact source slice: "+asset.Kind);
}
var original=scan.Objects.Single(x=>x.Name=="DG1").Bytes;
using(var repo=new Repository(Path.Combine(output,"Data")))
{
    var folder=repo.Save(scan);Repository.ValidateFolder(folder);
    Assert(repo.List().Single().Objects.Single(x=>x.Name=="DG1").Bytes.SequenceEqual(original),"Stored/reopened original is byte-identical");
    Reject(()=>repo.Save(scan),"Scan overwrite rejected");
    Reject(()=>new Repository(repo.Root),"Concurrent writer rejected");
    string zip=Path.Combine(output,"review.zip");repo.Export([scan],zip);
    using(var archive=ZipFile.OpenRead(zip))
    {
        Assert(archive.Entries.Any(x=>x.FullName.EndsWith("report.pdf")),"PDF included in ZIP");
        Assert(archive.Entries.Any(x=>x.FullName.EndsWith("derived/findings.json")),"Findings JSON included in ZIP");
        var entry=archive.Entries.Single(x=>x.FullName.EndsWith("raw/eMRTD/DG1.bin"));using var input=entry.Open();using var bytes=new MemoryStream();input.CopyTo(bytes);Assert(bytes.ToArray().SequenceEqual(original),"ZIP raw payload is byte-identical");
    }
    using(var restored=new Repository(Path.Combine(output,"Restored"))){restored.Restore(zip);Assert(restored.List().Single().Id==scan.Id,"ZIP restores on fresh data folder");Reject(()=>restored.Restore(zip),"Restore collision rejected");}
    File.AppendAllText(Path.Combine(folder,"raw/eMRTD/DG1.bin"),"tamper");Reject(()=>repo.Export([scan],Path.Combine(output,"bad.zip")),"Tampered original blocks export");
}
Reject(()=>Repository.SafePath(output,"../escape"),"Traversal path rejected");Reject(()=>Repository.SafePath(output,"C:/escape"),"Drive path rejected");
string badZip=Path.Combine(output,"traversal.zip");using(var z=ZipFile.Open(badZip,ZipArchiveMode.Create)){using var w=new StreamWriter(z.CreateEntry("../escape.txt").Open());w.Write("bad");}
using(var repo=new Repository(Path.Combine(output,"ImportGuard")))Reject(()=>repo.Restore(badZip),"ZIP traversal rejected");
var malformed=new Scan{Objects=[new(){Name="DG1",Bytes=[0x61,0x82,0xff,0xff]}]};Parser.Process(malformed);Assert(malformed.Checks.Any(x=>x.Result=="Unsupported/error")&&malformed.Objects[0].Bytes.Length==4,"Malformed BER preserves original");
Reject(()=>Ber.Read([0x61,0x80]),"Indefinite BER rejected");
Assert(Format.Hex(Pace.Cmac(Format.Bytes("2b7e151628aed2a6abf7158809cf4f3c"),[]))=="BB1D6929E95937287FA37D129B756746","RFC 4493 CMAC known-answer vector");
Assert(SecureChannel.Unpad(SecureChannel.Pad([1,0,2])).SequenceEqual(new byte[]{1,0,2}),"Secure-message padding roundtrip");
Reject(()=>SecureChannel.Unpad(new byte[16]),"Invalid secure padding rejected");
byte[] SyntheticCertificate(bool ec)
{
    var random=new Org.BouncyCastle.Security.SecureRandom();
    Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair pair;
    if(ec){var generator=new Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator();generator.Init(new Org.BouncyCastle.Crypto.Parameters.ECKeyGenerationParameters(Org.BouncyCastle.Asn1.Sec.SecObjectIdentifiers.SecP256r1,random));pair=generator.GenerateKeyPair();}
    else{var generator=new Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator();generator.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(random,2048));pair=generator.GenerateKeyPair();}
    var builder=new Org.BouncyCastle.X509.X509V3CertificateGenerator();
    var subject=new Org.BouncyCastle.Asn1.X509.X509Name(ec?"CN=Development Test":"CN=Example Authority");
    builder.SetSerialNumber(Org.BouncyCastle.Math.BigInteger.One);builder.SetSubjectDN(subject);builder.SetIssuerDN(subject);builder.SetNotBefore(DateTime.UtcNow.AddDays(-1));builder.SetNotAfter(DateTime.UtcNow.AddDays(1));builder.SetPublicKey(pair.Public);
    builder.AddExtension("1.2.3.4.5",false,new Org.BouncyCastle.Asn1.DerOctetString(new byte[]{1,2,3}));
    return builder.Generate(new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory(ec?"SHA256WITHECDSA":"SHA256WITHRSA",pair.Private,random)).GetEncoded();
}
{
    var strong=new Scan{Objects=[new(){Name="synthetic.cer",Bytes=SyntheticCertificate(false)}]};Parser.Process(strong);
    Assert(strong.Keys.Single().Bits==2048&&!strong.Findings.Any(x=>x.Rule=="RSA_UNDERSIZED"),"RSA-2048 not flagged as RSA-1024");
    Assert(strong.Keys.Single().Environment=="Unknown","No development marker does not imply production provenance");
    Assert(strong.Keys.Single().Details.Contains("1.2.3.4.5"),"Unknown certificate extension preserved in details");
}
{
    var strong=new Scan{Objects=[new(){Name="synthetic.cer",Bytes=SyntheticCertificate(true)}]};Parser.Process(strong);
    Assert(strong.Findings.Any(x=>x.Rule=="DEVELOPMENT_KEY")&&!strong.Findings.Any(x=>x.Rule=="RSA_UNDERSIZED"),"EC development warning independent of RSA threshold");
}
var changed=RecordedReader.Read(fixture);changed.Objects.Single(x=>x.Name=="DG1").Bytes[^1]^=1;Parser.Process(changed);
Assert(changed.Checks.Any(x=>x.Source=="eMRTD/DG1"&&x.Test=="SOD hash"&&x.Result=="MISMATCH"),"Altered data-group hash fails");
using(var invalid=new CounterTransport())Reject(()=>Pace.Establish(invalid,"12345".ToCharArray(),CancellationToken.None),"Invalid CAN rejected before APDUs");
using(var bad=new CounterTransport())
using(var secure=new SecureChannel(bad,new byte[32],new byte[32]))
{
    Reject(()=>secure.Send(0xb0,0,0,null,4),"Malformed protected response rejected");
    int sent=bad.Count;Reject(()=>secure.Send(0xb0,0,0,null,4),"Invalidated secure session refuses further commands");Assert(bad.Count==sent,"No APDU sent after channel invalidation");
}
if(args.Length>2)
{
    using var oracle=new Oracle(args[2]);using var secure=Pace.Establish(oracle,"123456".ToCharArray(),CancellationToken.None);
    Assert(true,"PACE mutually authenticates against independent OpenPACE card oracle");
    var response=secure.Send(0xb0,0,0,null,4);Assert(response.SequenceEqual(new byte[]{1,2,3,4}),"Protected APDU interoperates with OpenPACE");
    Assert(secure.Send(0xa4,4,0x0c,Format.Bytes("A0000002471001")).Length==0,"Encrypted SELECT command interoperates with OpenPACE");
    using var tampered=new TamperingOracle(args[2]);using var secure2=Pace.Establish(tampered,"123456".ToCharArray(),CancellationToken.None);
    Reject(()=>secure2.Send(0xb0,0,0,null,4),"Tampered response MAC rejected against independent oracle");
}
{
    // An archive's plain hashes authenticate neither its author nor its derived claims.
    var synthetic=new Scan{Mode="Synthetic recorded evidence",Objects=[new(){Application="Synthetic",Name="Opaque",Bytes=[0x30,0]}]};
    using var source=new Repository(Path.Combine(output,"MetadataSource"));source.Save(synthetic);
    string honest=Path.Combine(output,"metadata-honest.zip");source.Export([synthetic],honest);
    var entries=new Dictionary<string,byte[]>();
    using(var archive=ZipFile.OpenRead(honest))foreach(var entry in archive.Entries)
    {using var input=entry.Open();using var bytes=new MemoryStream();input.CopyTo(bytes);entries[entry.FullName]=bytes.ToArray();}
    string snapshotPath=entries.Keys.Single(x=>x.EndsWith("/scan.json")),manifestPath=entries.Keys.Single(x=>x.EndsWith("/manifest.json"));
    var node=System.Text.Json.Nodes.JsonNode.Parse(entries[snapshotPath])!.AsObject();
    node["Mode"]="Live card";
    node["Checks"]=JsonSerializer.SerializeToNode(new[]{new Check("Synthetic","CMS signature","Valid","Fabricated")},Format.Json);
    node["Fields"]=JsonSerializer.SerializeToNode(new[]{new Field("Synthetic","","Full name","Fabricated synthetic identity","")},Format.Json);
    node["Keys"]=JsonSerializer.SerializeToNode(new[]{new KeyInfo{Algorithm="RSA",Bits=4096,Environment="Production"}},Format.Json);
    node["Assets"]=JsonSerializer.SerializeToNode(new[]{new Asset("images/fabricated.jpg","portrait","Synthetic/Opaque",0,[1,2,3])},Format.Json);
    entries[snapshotPath]=JsonSerializer.SerializeToUtf8Bytes(node,Format.Json);
    var manifest=JsonSerializer.Deserialize<Manifest>(entries[manifestPath],Format.Json)!;
    manifest=manifest with{Files=manifest.Files.Select(f=>f.Path=="scan.json"?f with{Length=entries[snapshotPath].Length,Sha256=Format.Hash(entries[snapshotPath])}:f).ToList()};
    entries[manifestPath]=JsonSerializer.SerializeToUtf8Bytes(manifest,Format.Json);
    string crafted=Path.Combine(output,"metadata-crafted.zip");
    using(var archive=ZipFile.Open(crafted,ZipArchiveMode.Create))foreach(var entry in entries){using var stream=archive.CreateEntry(entry.Key).Open();stream.Write(entry.Value);}
    string originalArchiveHash=Format.Hash(File.ReadAllBytes(crafted));
    using var imported=new Repository(Path.Combine(output,"MetadataImported"));imported.Restore(crafted);var reloaded=imported.List().Single();
    Assert(!reloaded.Checks.Any(c=>c.Test=="CMS signature"&&c.Result=="Valid"),"Imported verification recomputed from raw bytes");
    Assert(reloaded.Fields.Count==0&&reloaded.Keys.Count==0&&reloaded.Assets.Count==0,"Imported identity, keys and images rederived from raw bytes");
    Assert(reloaded.Mode=="Imported evidence"&&reloaded.SourceModeClaim=="Live card"&&reloaded.ImportedArchiveSha256==originalArchiveHash,"Imported provenance distinguished from unverified source claim");
    Assert(originalArchiveHash==Format.Hash(File.ReadAllBytes(crafted))&&reloaded.Objects.Single().Bytes.SequenceEqual(synthetic.Objects.Single().Bytes),"Import preserves source archive and raw bytes");
    string folder=imported.ScanPath(reloaded);
    var persisted=JsonSerializer.Deserialize<List<Check>>(File.ReadAllBytes(Path.Combine(folder,"derived/verification.json")),Format.Json)!;
    Assert(!persisted.Any(c=>c.Test=="CMS signature"&&c.Result=="Valid"),"Imported derived verification file regenerated");
    string cachedPath=Path.Combine(folder,"scan.json"),cachedManifestPath=Path.Combine(folder,"manifest.json");
    var cached=System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllBytes(cachedPath))!.AsObject();
    cached["Checks"]=JsonSerializer.SerializeToNode(new[]{new Check("Synthetic","CMS signature","Valid","Fabricated cache")},Format.Json);
    File.WriteAllBytes(cachedPath,JsonSerializer.SerializeToUtf8Bytes(cached,Format.Json));
    Reject(()=>imported.List(),"Cached metadata with stale manifest rejected before display");
    var cachedManifest=JsonSerializer.Deserialize<Manifest>(File.ReadAllBytes(cachedManifestPath),Format.Json)!;
    cachedManifest=cachedManifest with{Files=cachedManifest.Files.Select(f=>f.Path=="scan.json"?f with{Length=new FileInfo(cachedPath).Length,Sha256=Format.Hash(File.ReadAllBytes(cachedPath))}:f).ToList()};
    File.WriteAllBytes(cachedManifestPath,JsonSerializer.SerializeToUtf8Bytes(cachedManifest,Format.Json));
    Assert(!imported.List().Single().Checks.Any(c=>c.Test=="CMS signature"&&c.Result=="Valid"),"Rehashed cache still recomputes verification");
    string exported=Path.Combine(output,"metadata-canonical-export.zip");imported.Export([reloaded],exported);
    using var finalArchive=ZipFile.OpenRead(exported);using var finalInput=finalArchive.Entries.Single(x=>x.FullName.EndsWith("/scan.json")).Open();
    var finalScan=JsonSerializer.Deserialize<Scan>(finalInput,Format.Json)!;
    Assert(!finalScan.Checks.Any(c=>c.Test=="CMS signature"&&c.Result=="Valid"),"Export regenerates canonical derived metadata");
    using var legacy=new Repository(Path.Combine(output,"LegacyProvenance"));
    var liveClaim=new Scan{Mode="Live card",Objects=[new(){Application="Synthetic",Name="Opaque",Bytes=[0x30,0]}]};
    legacy.Save(liveClaim);string legacySnapshot=Path.Combine(legacy.ScanPath(liveClaim),"scan.json");
    string before=Format.Hash(File.ReadAllBytes(legacySnapshot));var legacyReopened=legacy.List().Single();
    Assert(liveClaim.Mode=="Live card"&&legacyReopened.Mode=="Stored evidence"&&legacyReopened.SourceModeClaim=="Live card","Reopened unsigned live-acquisition claim becomes stored evidence");
    Assert(before==Format.Hash(File.ReadAllBytes(legacySnapshot)),"Reopening qualifies provenance without rewriting legacy evidence");
}
File.WriteAllText(Path.Combine(output,"test-result.json"),JsonSerializer.Serialize(new{Passed=passed,Failed=0,Runtime=System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription},Format.Json));
Console.WriteLine($"{passed} checks passed");
class Oracle:ICardTransport
{
    readonly Process process;
    public Oracle(string path){process=Process.Start(new ProcessStartInfo(path){RedirectStandardInput=true,RedirectStandardOutput=true,UseShellExecute=false})!;}
    public byte[] Transmit(byte[] command){process.StandardInput.WriteLine(Format.Hex(command));process.StandardInput.Flush();string line=process.StandardOutput.ReadLine()??throw new Exception("Oracle ended");return Format.Bytes(line);}
    public void Dispose(){process.StandardInput.Close();if(!process.WaitForExit(2000))process.Kill();process.Dispose();}
}

class CounterTransport:ICardTransport
{
    public int Count;public byte[] Transmit(byte[] command){Count++;return new byte[]{0x90,0};}public void Dispose(){}
}

class TamperingOracle:ICardTransport
{
    readonly Oracle inner;public TamperingOracle(string path){inner=new(path);}
    public byte[] Transmit(byte[] command){var response=inner.Transmit(command);if(command[0]==0x0c)response[^3]^=1;return response;}
    public void Dispose()=>inner.Dispose();
}
