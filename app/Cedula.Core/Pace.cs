using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
namespace Cedula.Core;
// Protocol orchestration for the observed CAN/PACE ECDH-GM AES-256, parameter 15.
// Cryptographic primitives and EC operations are provided by .NET and Bouncy Castle.
public static class Pace
{
    public static readonly byte[] Oid=Format.Bytes("04007F00070202040204");
    public static byte[] Kdf(byte[] input,int counter)=>SHA256.HashData(Ber.Join(input,[(byte)(counter>>24),(byte)(counter>>16),(byte)(counter>>8),(byte)counter]));
    public static byte[] Cmac(byte[] key,byte[] data)
    {
        var mac=new CMac(new AesEngine());mac.Init(new KeyParameter(key));mac.BlockUpdate(data,0,data.Length);byte[] output=new byte[16];mac.DoFinal(output,0);return output;
    }
    public static byte[] Crypt(byte[] key,byte[] iv,byte[] data,bool encrypt)
    {
        using var aes=Aes.Create();aes.Key=key;return encrypt?aes.EncryptCbc(data,iv,PaddingMode.None):aes.DecryptCbc(data,iv,PaddingMode.None);
    }
    public static byte[] Token(byte[] key,byte[] point)=>Cmac(key,Ber.Encode("7F49",Ber.Join(Ber.Encode("06",Oid),Ber.Encode("86",point))))[..8];
    public static SecureChannel Establish(ICardTransport card,char[] can,CancellationToken ct)
    {
        if(can.Length!=6||can.Any(c=>c<'0'||c>'9'))throw new ArgumentException("CAN must contain exactly six digits");
        byte[] password=Encoding.ASCII.GetBytes(can), kp=Kdf(password,3), shared=[];
        try
        {
            byte[] Send(byte[] command){ct.ThrowIfCancellationRequested();return Apdu.Checked(card.Transmit(command));}
            byte[] Ga(string? sendTag,byte[] data,string receiveTag,bool last=false)
            {
                byte[] response=Send(Apdu.Command(last?(byte)0:(byte)0x10,0x86,0,0,Ber.Encode("7C",sendTag==null?[]:Ber.Encode(sendTag,data)),256));
                return Ber.Read(Ber.Read(response).Single(x=>x.Tag=="7C").Value).Single(x=>x.Tag==receiveTag).Value;
            }
            Send(Apdu.Command(0,0x22,0xc1,0xa4,Ber.Join(Ber.Encode("80",Oid),Ber.Encode("83",[2]),Ber.Encode("84",[15]))));
            byte[] nonce=Crypt(kp,new byte[16],Ga(null,[],"80"),false);
            var curve=SecNamedCurves.GetByName("secp384r1");var random=new SecureRandom();
            BigInteger Scalar()=>BigIntegers.CreateRandomInRange(BigInteger.One,curve.N.Subtract(BigInteger.One),random);
            Org.BouncyCastle.Math.EC.ECPoint Point(byte[] encoded)
            {
                if(encoded.Length!=97||encoded[0]!=4)throw new IOException("Invalid PACE public point encoding");
                var point=curve.Curve.DecodePoint(encoded).Normalize();if(point.IsInfinity||!point.IsValid()||!point.Multiply(curve.N).IsInfinity)throw new IOException("Invalid PACE point");return point;
            }
            var mapPrivate=Scalar();byte[] mapPublic=curve.G.Multiply(mapPrivate).GetEncoded(false);
            var peerMap=Point(Ga("81",mapPublic,"82"));
            var mapped=curve.G.Multiply(new BigInteger(1,nonce)).Add(peerMap.Multiply(mapPrivate)).Normalize();
            if(mapped.IsInfinity)throw new IOException("Invalid mapped generator");
            var ephemeral=Scalar();byte[] publicKey=mapped.Multiply(ephemeral).GetEncoded(false);
            var peer=Point(Ga("83",publicKey,"84"));if(peer.GetEncoded(false).SequenceEqual(publicKey))throw new IOException("PACE reflected key");
            shared=BigIntegers.AsUnsignedByteArray(48,peer.Multiply(ephemeral).Normalize().AffineXCoord.ToBigInteger());
            byte[] enc=Kdf(shared,1),mac=Kdf(shared,2);
            try
            {
                byte[] received=Ga("85",Token(mac,peer.GetEncoded(false)),"86",true);
                if(!CryptographicOperations.FixedTimeEquals(received,Token(mac,publicKey)))throw new IOException("PACE authentication token failed; verify CAN and card");
                return new SecureChannel(card,enc,mac);
            }
            catch{CryptographicOperations.ZeroMemory(enc);CryptographicOperations.ZeroMemory(mac);throw;}
        }
        finally{CryptographicOperations.ZeroMemory(password);CryptographicOperations.ZeroMemory(kp);CryptographicOperations.ZeroMemory(shared);Array.Clear(can);}
    }
}
public sealed class SecureChannel(ICardTransport card,byte[] enc,byte[] mac):IDisposable
{
    readonly byte[] ssc=new byte[16];bool failed;
    void Increment(){for(int i=15;i>=0;i--){ssc[i]++;if(ssc[i]!=0)return;}throw new IOException("Secure counter exhausted");}
    public static byte[] Pad(byte[] bytes){var padded=new byte[((bytes.Length+1+15)/16)*16];bytes.CopyTo(padded,0);padded[bytes.Length]=128;return padded;}
    public static byte[] Unpad(byte[] bytes){int n=bytes.Length-1;while(n>=0&&bytes[n]==0)n--;if(n<0||bytes[n]!=128)throw new IOException("Invalid secure padding");return bytes[..n];}
    byte[] Iv(){using var aes=Aes.Create();aes.Key=enc;return aes.EncryptEcb(ssc,PaddingMode.None);}
    public byte[] Send(byte ins,byte p1,byte p2,byte[]? data=null,int? le=null)
    {
        if(failed)throw new IOException("Secure session invalidated");
        bool authenticated=false;
        try
        {
            Increment();byte[] header=[0x0c,ins,p1,p2];var parts=new List<byte[]>();
            if(data is {Length:>0})parts.Add(Ber.Encode("87",Ber.Join([1],Pace.Crypt(enc,Iv(),Pad(data),true))));
            if(le!=null)parts.Add(Ber.Encode("97",[(byte)(le.Value==256?0:le.Value)]));
            byte[] objects=Ber.Join(parts.ToArray());byte[] tag=Pace.Cmac(mac,Pad(Ber.Join(ssc,Pad(header),objects)))[..8];
            byte[] response=card.Transmit(Apdu.Command(0x0c,ins,p1,p2,Ber.Join(objects,Ber.Encode("8E",tag)),256));
            byte[] raw=Apdu.Checked(response);Increment();var tlvs=Ber.Read(raw);
            if(tlvs.Count<2||tlvs[^1].Tag!="8E"||tlvs[^1].Value.Length!=8||tlvs[^2].Tag!="99"||tlvs[^2].Value.Length!=2)throw new IOException("Invalid protected response");
            if(tlvs.Any(x=>x.Tag is not ("87" or "99" or "8E"))||tlvs.Count(x=>x.Tag=="87")>1||tlvs.Count(x=>x.Tag=="99")!=1||tlvs.Count(x=>x.Tag=="8E")!=1)throw new IOException("Unexpected secure response object");
            byte[] signed=raw[..tlvs[^1].Offset];byte[] expected=Pace.Cmac(mac,Pad(Ber.Join(ssc,signed)))[..8];
            if(!CryptographicOperations.FixedTimeEquals(expected,tlvs[^1].Value))throw new IOException("Secure response MAC mismatch");
            authenticated=true;
            var status=tlvs[^2].Value;int sw=status[0]*256+status[1];if(sw!=0x9000)throw new CardStatusException(sw);
            var encrypted=tlvs.FirstOrDefault(x=>x.Tag=="87");if(encrypted==null)return [];
            if(encrypted.Value.Length<17||encrypted.Value[0]!=1)throw new IOException("Invalid encrypted response");
            return Unpad(Pace.Crypt(enc,Iv(),encrypted.Value[1..],false));
        }
        catch(CardStatusException){if(!authenticated)failed=true;throw;}
        catch{failed=true;throw;}
    }
    public void Dispose(){CryptographicOperations.ZeroMemory(enc);CryptographicOperations.ZeroMemory(mac);CryptographicOperations.ZeroMemory(ssc);failed=true;}
}
