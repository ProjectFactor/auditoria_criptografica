using Cedula.Core;
const string usage="""
cedula-reader 0.1.0 — read a Dominican cédula over PC/SC (CAN/PACE) and save an exportable scan.

  cedula-reader readers
  cedula-reader read [--reader NAME|INDEX] [--data DIR] [--export FILE.zip]

The six-digit CAN is read from the CEDULA_CAN environment variable, from stdin when it is
piped, or prompted for (hidden). It is never written to disk. Run `readers` first; Linux
needs pcscd and libpcsclite.so.1. Output is unencrypted personal data: protect --data/--export.
""";
if(args.Length==0||args[0] is "-h" or "--help"){Console.WriteLine(usage);return args.Length==0?2:0;}
string? Opt(string name){int i=Array.IndexOf(args,name);return i>=0&&i+1<args.Length?args[i+1]:null;}
try
{
    var readers=CardTransport.Readers();
    if(args[0]=="readers"){if(readers.Count==0)Console.WriteLine("No reader connected");for(int i=0;i<readers.Count;i++)Console.WriteLine($"{i}\t{readers[i]}");return readers.Count==0?1:0;}
    if(args[0]!="read"){Console.Error.WriteLine(usage);return 2;}
    if(readers.Count==0){Console.Error.WriteLine("No reader connected");return 1;}
    string? pick=Opt("--reader");string reader=pick==null?readers[0]:int.TryParse(pick,out int idx)&&idx>=0&&idx<readers.Count?readers[idx]:readers.FirstOrDefault(r=>r==pick)??throw new ArgumentException("Unknown reader: "+pick);
    string text=Environment.GetEnvironmentVariable("CEDULA_CAN")??"";
    if(text==""&&Console.IsInputRedirected)text=(Console.In.ReadLine()??"").Trim();
    else if(text=="")
    {
        Console.Error.Write("CAN (6 digits): ");var sb=new System.Text.StringBuilder();
        while(Console.ReadKey(true) is var k&&k.Key!=ConsoleKey.Enter){if(k.Key==ConsoleKey.Backspace&&sb.Length>0)sb.Length--;else if(!char.IsControl(k.KeyChar))sb.Append(k.KeyChar);}
        Console.Error.WriteLine();text=sb.ToString();
    }
    char[] can=text.ToCharArray();
    if(can.Length!=6||can.Any(c=>c<'0'||c>'9')){Console.Error.WriteLine("The CAN must be six digits");return 2;}
    using var repo=new Repository(Opt("--data")??Path.Combine(AppContext.BaseDirectory,"Data"));
    using var cancel=new CancellationTokenSource();Console.CancelKeyPress+=(_,e)=>{e.Cancel=true;cancel.Cancel();};
    var scan=LiveReader.Read(reader,can,repo.Root,new Progress<string>(s=>Console.Error.WriteLine(s)),cancel.Token);
    if(scan.Objects.Count==0){Console.Error.WriteLine("Read failed: "+scan.Error);return 1;}
    repo.Save(scan);Console.WriteLine(scan.Summary);Console.WriteLine("Saved: "+repo.ScanPath(scan));
    if(Opt("--export") is {} zip){repo.Export([scan],zip);Console.WriteLine("Exported: "+Path.GetFullPath(zip));}
    if(scan.State!="Complete"){Console.Error.WriteLine("Incomplete: "+scan.Error);return 3;}
    return 0;
}
catch(Exception e){Console.Error.WriteLine("Error: "+e.Message);return 1;}
