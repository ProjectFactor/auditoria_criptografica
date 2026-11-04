namespace Cedula.Core;
public static class LiveReader
{
    public static Scan Read(string reader,char[] can,string journalRoot,IProgress<string>? progress,CancellationToken ct)
    {
        var scan=new Scan{Mode="Live card",Reader=reader};
        Directory.CreateDirectory(journalRoot);
        string journal=Path.Combine(journalRoot,".acquiring-"+scan.Id);Directory.CreateDirectory(journal);
        void Persist(CardObject obj)
        {
            string name=obj.Application+"-"+obj.Name;
            foreach(var chunk in obj.Chunks)
            {
                string path=Path.Combine(journal,$"{name}-{chunk.Offset:D8}.bin");
                if(!File.Exists(path)){using var stream=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None);stream.Write(chunk.Bytes);stream.Flush(true);}
            }
            var temporary=Path.Combine(journal,"acquisition.json.tmp");
            using(var file=new FileStream(temporary,FileMode.Create,FileAccess.Write,FileShare.None)){file.Write(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(scan,Format.Json));file.Flush(true);}
            File.Move(temporary,Path.Combine(journal,"acquisition.json"),true);
        }
        try
        {
            ct.ThrowIfCancellationRequested();progress?.Report("Connecting / CAN-PACE");
            using var card=CardTransport.Open(reader);
                Apdu.Checked(card.Transmit(Apdu.Command(0,0xa4,0,0x0c,Format.Bytes("3F00"))));
                Apdu.Checked(card.Transmit(Apdu.Command(0,0xa4,2,0x0c,Format.Bytes("011C"))));
                byte[] access=Apdu.Checked(card.Transmit(Apdu.Command(0,0xb0,0,0,null,22)));
                if(!access.SequenceEqual(Format.Bytes("31143012060A04007F0007020204020402010202010F")))throw new IOException("Unsupported CardAccess profile; no credential attempt made");
                {var obj=new CardObject{Application="MF",Name="EF.CardAccess",Fid="011C",Bytes=access,DeclaredLength=access.Length,Chunks=[new(0,access)]};scan.Objects.Add(obj);Persist(obj);}
                foreach(var (name,fid,length) in new[]{("EF.ATR-INFO","2F01",19),("EF.DIR","2F00",29)})
                {
                    ct.ThrowIfCancellationRequested();
                    var obj=new CardObject{Application="MF",Name=name,Fid=fid,Status="Not acquired"};scan.Objects.Add(obj);
                    try
                    {
                        Apdu.Checked(card.Transmit(Apdu.Command(0,0xa4,2,0x0c,Format.Bytes(fid))));
                        var bytes=Apdu.Checked(card.Transmit(Apdu.Command(0,0xb0,0,0,null,length)));
                        obj.Bytes=bytes;obj.Chunks=[new(0,bytes)];obj.Status=bytes.Length==length?"Read":"Partial";
                        obj.Detail="Bounded public read for supported profile; length not independently declared";Persist(obj);
                    }
                    catch(CardStatusException e){obj.Detail=e.Message;Persist(obj);}
                }
                Apdu.Checked(card.Transmit(Apdu.Command(0,0xa4,0,0x0c,Format.Bytes("3F00"))));
                using var secure=Pace.Establish(card,(char[])can.Clone(),ct);
            foreach(string group in new[]{"eMRTD","MF","PKCS15"})
            {
                ct.ThrowIfCancellationRequested();
                if(group=="MF") secure.Send(0xa4,0,0x0c,Format.Bytes("3F00"));
                if(group!="MF") secure.Send(0xa4,4,0x0c,Format.Bytes(group=="eMRTD"?"A0000002471001":"A000000063504B43532D3135"));
                var files=group switch {
                    "MF"=>new[]{("EF.CardSecurity","011D",0)},
                    "eMRTD"=>new[]{("EF.COM","011E",0),("EF.SOD","011D",0),("DG1","0101",0),("DG2","0102",0),("DG7","0107",0),("DG11","010B",0),("DG12","010C",0),("DG13","010D",0),("DG14","010E",0),("EF.CVCA","011C",0)},
                    _=>new[]{("ODF","5031",0),("TokenInfo","5032",0),("PrivateKeyDescriptors","4400",203),("PublicKeys","4401",0),("TrustedPublicKeys","4402",0),("SecretKeyDescriptors","4403",0),("Certificates","4404",0),("TrustedCertificates","4405",0),("UsefulCertificates","4406",0),("DataObjects","4407",0),("AuthenticationObjects","4408",0),("cardid","6377",0),("cardcf","6378",0),("cardapps","5701",0),("mscp","5702",0),("cmapfile","5703",0)} };
                foreach(var (name,fid,limit) in files)
                {
                    ct.ThrowIfCancellationRequested();progress?.Report("Reading "+name);
                    var obj=new CardObject{Application=group,Name=name,Fid=fid,Status="Partial"};scan.Objects.Add(obj);
                    if(name.StartsWith("DG")&&scan.AdvertisedGroups is {} advertised&&!advertised.Contains(name))
                    {obj.Status="Not advertised";obj.Detail="Not selected because EF.COM does not advertise this data group";Persist(obj);continue;}
                    try
                    {
                        byte[] fci=secure.Send(0xa4,2,0,Format.Bytes(fid),256);
                        var size=Ber.Walk(fci).FirstOrDefault(x=>x.Tag is "80" or "81")?.Value??throw new IOException("No declared file length");
                        if(size.Length>4)throw new IOException("Invalid file length");int length=0;foreach(var b in size)length=checked(length*256+b);
                        if(length is <=0 or >32767)throw new IOException("Unsupported file size");obj.DeclaredLength=length;
                        scan.Objects.Add(new(){Application=group,Name=name+"-FCI",Fid=fid,Bytes=fci,DeclaredLength=fci.Length,Chunks=[new(0,fci)]});
                        int expected=limit>0?Math.Min(limit,length):length;
                        using var output=new MemoryStream();
                        while(output.Length<expected)
                        {
                            ct.ThrowIfCancellationRequested();int offset=(int)output.Length;int request=Math.Min(208,expected-offset);
                            byte[] bytes=secure.Send(0xb0,(byte)(offset>>8),(byte)offset,null,request);
                            if(bytes.Length==0||bytes.Length>request)throw new IOException("Unexpected READ BINARY length");
                            obj.Chunks.Add(new(offset,bytes));output.Write(bytes);obj.Bytes=output.ToArray();Persist(obj);
                        }
                        obj.Status=expected==length?"Read":"Partial";obj.Detail=expected==length?"":"Bounded descriptor prefix; remaining directory not acquired";Persist(obj);
                    }
                    catch(CardStatusException e) when(e.Status is 0x6982 or 0x6a82)
                    {obj.Status=e.Status==0x6982?"Protected":"Not found";obj.Detail=e.Message;Persist(obj);}
                }
            }
            scan.Objects.Add(new(){Name="DG3",Fid="0103",Status=scan.AdvertisedGroups?.Contains("DG3")==true?"Not attempted":"Not advertised",Detail="Protected in established profile; Terminal Authentication not implemented"});
        }
        catch(Exception e)when(e is not OutOfMemoryException){scan.State="Incomplete";scan.Error=e is OperationCanceledException?"Cancelled":e.Message;}
        finally{Array.Clear(can);}
        progress?.Report("Parsing / checking integrity");Parser.Process(scan);
        File.WriteAllBytes(Path.Combine(journal,"acquisition.json"),System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(scan,Format.Json));
        return scan;
    }
}
