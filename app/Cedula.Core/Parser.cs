using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Utilities;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
namespace Cedula.Core;
public static class Parser
{
    public static void Process(Scan scan)
    {
        scan.Fields.Clear(); scan.Assets.Clear(); scan.Keys.Clear(); scan.Checks.Clear();
        foreach (var o in scan.Objects.Where(x => x.Bytes.Length > 0))
        {
            try
            {
                if (o.Status != "Read") { scan.Checks.Add(new(o.Identity, "Parse", "Partial", "Original partial bytes retained")); continue; }
                if (o.Name is "EF.SOD" or "EF.CardSecurity") { Cms(scan, o); continue; }
                if (o.Name.EndsWith(".cer")) { Certificate(scan, o, o.Bytes); continue; }
                var nodes = Ber.Walk(o.Bytes).ToList();
                if (o.Name == "DG1") Mrz(scan, o, nodes.Single(x => x.Tag == "5F1F").Value);
                if (o.Name is "DG11" or "DG12" or "DG13")
                {
                    foreach (var t in nodes.Where(x => x.Tag.StartsWith("5F")))
                    {
                        string name = (o.Name, t.Tag) switch { ("DG11", "5F0E") => "Full name", ("DG11", "5F11") => "Place of birth", ("DG12", "5F19") => "Issuing authority", ("DG12", "5F26") => "Date of issue", _ => "Unmapped " + t.Tag };
                        scan.Fields.Add(new(o.Identity, t.Tag, name, Encoding.UTF8.GetString(t.Value).Replace("<", " ").Trim(), Format.Hex(t.Value)));
                    }
                }
                if (o.Name is "DG2" or "DG7")
                {
                    foreach (var t in nodes.Where(x => o.Name == "DG7" ? x.Tag == "5F43" : x.Tag is "5F2E" or "7F2E"))
                    {
                        int start = t.Value.AsSpan().IndexOf(new byte[] { 0xff, 0xd8, 0xff });
                        if (start < 0) throw new InvalidDataException("Unsupported image encoding; original retained");
                        int end = t.Value.AsSpan(start).LastIndexOf(new byte[] { 0xff, 0xd9 });
                        if (end < 0) throw new InvalidDataException("Truncated JPEG");
                        string kind = o.Name == "DG2" ? "portrait" : "signature";
                        scan.Assets.Add(new($"images/{kind}-{scan.Assets.Count(x=>x.Kind==kind)+1}-original.jpg", kind, o.Identity, t.Offset + t.Header + start, t.Value.AsSpan(start, end + 2).ToArray()));
                    }
                }
                if (o.Name == "DG14")
                {
                    var set = Asn1Set.GetInstance(Asn1Object.FromByteArray(Ber.Read(o.Bytes).Single().Value));
                    foreach (var v in set)
                    {
                        var seq = Asn1Sequence.GetInstance(v);
                        if (seq.Count >= 2 && seq[1] is Asn1Sequence spki)
                        {
                            var raw = spki.GetEncoded();
                            var key = PublicKeyFactory.CreateKey(raw);
                            Key(scan, o, key, raw, "DG14 chip authentication", "", "");
                        }
                    }
                }
                scan.Checks.Add(new(o.Identity, "Parse", "Parsed", o.Bytes.All(x=>x==0) ? "Zero-filled" : "Original bytes preserved"));
            }
            catch (Exception e) when (e is not OutOfMemoryException) { scan.Checks.Add(new(o.Identity, "Parse", "Unsupported/error", e.Message)); }
        }
    }
    static void Mrz(Scan s, CardObject o, byte[] raw)
    {
        string text = Encoding.ASCII.GetString(raw);
        if (text.Length != 90) throw new InvalidDataException("Expected TD1 MRZ");
        void Add(string name, string value) => s.Fields.Add(new(o.Identity, "5F1F", name, value, Format.Hex(raw)));
        string a = text[..30], b = text[30..60], c = text[60..];
        string number = a.Substring(5,9); string numberCheck = a[14].ToString();
        if (a[14] == '<')
        {
            var candidates = Enumerable.Range(16,13).Where(i => a[i+1]=='<' && Digit(a.Substring(5,9)+a[15..i])==a[i]-'0').ToList();
            if(candidates.Count!=1) throw new InvalidDataException("Ambiguous extended document number");
            number += a[15..candidates[0]]; numberCheck = a[candidates[0]].ToString();
        }
        Add("Name", c.Replace("<<", ", ").Replace('<',' ').Trim()); Add("Document number", number.TrimEnd('<'));
        Add("Issuing state", a.Substring(2,3)); Add("Nationality", b.Substring(15,3));
        Add("Birth date (YYMMDD)", b[..6]); Add("Expiry date (YYMMDD)", b.Substring(8,6)); Add("Sex", b[7].ToString());
        Add("Optional data", a[15..]+" / "+b.Substring(18,11)); Add("Original MRZ", a+"\n"+b+"\n"+c);
        CheckDigit(s,o,"Document number",number,numberCheck[0]); CheckDigit(s,o,"Birth date",b[..6],b[6]); CheckDigit(s,o,"Expiry date",b.Substring(8,6),b[14]);
        CheckDigit(s,o,"Composite",a[5..]+b[..7]+b.Substring(8,7)+b.Substring(18,11),b[29]);
    }
    static int Digit(string value)
    {
        int[] w=[7,3,1];int sum=0;
        for(int i=0;i<value.Length;i++){char c=value[i];int n=c=='<'?0:c is >= '0' and <= '9'?c-'0':c is >= 'A' and <= 'Z'?c-'A'+10:throw new InvalidDataException("Invalid MRZ character");sum+=n*w[i%3];}
        return sum%10;
    }
    static void CheckDigit(Scan s, CardObject o, string name, string value, char digit)
    {
        int[] w=[7,3,1]; int sum=0;
        for(int i=0;i<value.Length;i++) { char c=value[i]; int n=c=='<'?0:c is >= '0' and <= '9'?c-'0':c is >= 'A' and <= 'Z'?c-'A'+10:throw new InvalidDataException("Invalid MRZ character"); sum+=n*w[i%3]; }
        s.Checks.Add(new(o.Identity, name+" check digit",digit-'0'==sum%10?"Match":"Mismatch",""));
    }
    static void Cms(Scan s, CardObject o)
    {
        byte[] raw = o.Name == "EF.SOD" && o.Bytes[0]==0x77 ? Ber.Read(o.Bytes).Single().Value : o.Bytes;
        var cms = new CmsSignedData(raw); var certs = cms.GetCertificates();
        foreach(var cert in certs.EnumerateMatches(null)) Certificate(s,o,cert.GetEncoded());
        foreach(SignerInformation signer in cms.GetSignerInfos().GetSigners())
        {
            var cert = certs.EnumerateMatches(signer.SignerID).FirstOrDefault();
            bool valid = cert != null && signer.Verify(cert.GetPublicKey());
            s.Checks.Add(new(o.Identity,"CMS signature",valid?"Valid":"Failed","Internal signature only; issuer trust unresolved"));
        }
        s.Checks.Add(new(o.Identity,"Issuer chain","Unresolved","No independently validated matching trust anchor configured"));
        s.Checks.Add(new(o.Identity,"Revocation","Not checked","Offline"));
        if(o.Name != "EF.SOD") return;
        using var output=new MemoryStream(); cms.SignedContent.Write(output);
        var sequence=Asn1Sequence.GetInstance(Asn1Object.FromByteArray(output.ToArray()));
        string algorithm=DerObjectIdentifier.GetInstance(Asn1Sequence.GetInstance(sequence[1])[0]).Id;
        foreach(var entry in Asn1Sequence.GetInstance(sequence[2]))
        {
            var pair=Asn1Sequence.GetInstance(entry); int n=DerInteger.GetInstance(pair[0]).IntValueExact;
            byte[] hash=Asn1OctetString.GetInstance(pair[1]).GetOctets(); var dg=s.Objects.FirstOrDefault(x=>x.Name=="DG"+n && x.Application=="eMRTD");
            if(dg==null || dg.Status!="Read") { s.Checks.Add(new("eMRTD/DG"+n,"SOD hash","Not acquired","Signed hash: "+Format.Hex(hash))); continue; }
            byte[] actual=DigestUtilities.CalculateDigest(algorithm,dg.Bytes);
            s.Checks.Add(new(dg.Identity,"SOD hash",CryptographicOperations.FixedTimeEquals(hash,actual)?"Match":"MISMATCH","Hash comparison to SOD; see separate CMS/chain results"));
        }
    }
    static void Certificate(Scan s, CardObject o, byte[] raw)
    {
        var cert=new X509CertificateParser().ReadCertificate(raw); string id=Format.Hash(raw)[..16];
        int offset=o.Bytes.AsSpan().IndexOf(raw);
        if(offset<0) throw new InvalidDataException("Certificate encoding is not an exact slice of original");
        s.Assets.Add(new($"certificates/{id}-original.der","certificate",o.Identity,offset,raw));
        s.Assets.Add(new($"certificates/{id}-derived.pem","pem",o.Identity,offset,Encoding.ASCII.GetBytes(PemEncoding.WriteString("CERTIFICATE",raw)),false));
        string details=cert.ToString()+"\nSHA-256: "+Format.Hash(raw)+"\n\nFull ASN.1:\n"+Asn1Dump.DumpAsString(Asn1Object.FromByteArray(raw),true);
        Key(s,o,cert.GetPublicKey(),cert.CertificateStructure.SubjectPublicKeyInfo.GetEncoded(),o.Identity+" certificate "+id,cert.SubjectDN.ToString(),cert.IssuerDN.ToString(),details);
        bool validTime=DateTime.UtcNow>=cert.NotBefore.ToUniversalTime()&&DateTime.UtcNow<=cert.NotAfter.ToUniversalTime();
        s.Checks.Add(new(o.Identity+" certificate "+id,"Validity dates",validTime?"Current":"Outside validity",$"{cert.NotBefore:O} — {cert.NotAfter:O}"));
    }
    static void Key(Scan s, CardObject o, Org.BouncyCastle.Crypto.AsymmetricKeyParameter key, byte[] spki, string source, string subject, string issuer,string details="")
    {
        var k=new KeyInfo { Source=source,Details=details };
        if(key is RsaKeyParameters rsa) { k.Algorithm="RSA";k.Bits=rsa.Modulus.BitLength;k.Parameters=$"Modulus (hex): {rsa.Modulus.ToString(16)}\nExponent: {rsa.Exponent}"; }
        else if(key is ECPublicKeyParameters ec) { k.Algorithm="EC";k.Bits=ec.Parameters.Curve.FieldSize;k.Parameters=$"Public point: {Format.Hex(ec.Q.GetEncoded(false))}\nCurve/order: {ec.Parameters.N.ToString(16)}"; }
        else { k.Algorithm=key.GetType().Name;k.Parameters="See ASN.1"; }
        if(k.Algorithm=="RSA"&&k.Bits<2048) k.Findings.Add(new("RSA_UNDERSIZED","Red",$"INSECURE — RSA-{k.Bits}","Insecure for modern production use; signature verification is a separate result.",source));
        string fingerprint=Format.Hash(spki);
        bool known=fingerprint=="ec77a452c2c5f0b54c2c106c665301eac245cc596e8614e62448365fcafbaabc";
        string markers=subject+" "+issuer;
        bool dev=new[]{"development","test","demo"}.Any(x=>System.Text.RegularExpressions.Regex.IsMatch(markers,@"\b"+x+@"\b",System.Text.RegularExpressions.RegexOptions.IgnoreCase));
        if(known||dev) { k.Environment=known?"Known development":"Suspected development";k.Findings.Add(new("DEVELOPMENT_KEY","Warning",k.Environment+" environment key/certificate",$"Subject: {subject}\nIssuer: {issuer}\nSPKI SHA-256: {fingerprint}",source)); }
        int offset=o.Bytes.AsSpan().IndexOf(spki); string id=fingerprint[..16];
        if(offset>=0) s.Assets.Add(new($"keys/{id}-original.der","key",o.Identity,offset,spki));
        else s.Assets.Add(new($"keys/{id}-derived-spki.der","key",o.Identity,-1,spki,false));
        s.Assets.Add(new($"keys/{id}-derived.pem","pem",o.Identity,offset,Encoding.ASCII.GetBytes(PemEncoding.WriteString("PUBLIC KEY",spki)),false));
        k.Details+=$"\n\n{k.Algorithm}-{k.Bits}\nEnvironment: {k.Environment}\n{k.Parameters}\nSPKI SHA-256: {fingerprint}\n"+string.Join("\n",k.Findings.Select(x=>x.Title+"\n"+x.Evidence));
        s.Keys.Add(k);
    }
}
