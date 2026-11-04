using System.Runtime.InteropServices;
namespace Cedula.Core;
public interface ICardTransport : IDisposable { byte[] Transmit(byte[] command); }
public sealed class WinSmartCard : ICardTransport
{
    nint context,card;uint protocol;
    [StructLayout(LayoutKind.Sequential)] struct Pci { public uint Protocol; public uint Length; }
    [DllImport("winscard.dll")] static extern int SCardEstablishContext(uint scope,nint a,nint b,out nint context);
    [DllImport("winscard.dll")] static extern int SCardReleaseContext(nint context);
    [DllImport("winscard.dll",CharSet=CharSet.Unicode)] static extern int SCardListReadersW(nint context,string? groups,char[]? readers,ref uint length);
    [DllImport("winscard.dll",CharSet=CharSet.Unicode)] static extern int SCardConnectW(nint context,string reader,uint share,uint protocols,out nint card,out uint active);
    [DllImport("winscard.dll")] static extern int SCardDisconnect(nint card,uint disposition);
    [DllImport("winscard.dll")] static extern int SCardBeginTransaction(nint card);
    [DllImport("winscard.dll")] static extern int SCardEndTransaction(nint card,uint disposition);
    [DllImport("winscard.dll")] static extern int SCardTransmit(nint card,ref Pci pci,byte[] send,uint length,nint receivePci,byte[] receive,ref uint receiveLength);
    static void Check(int code)
    {
        if(code==0)return;
        string text=(uint)code switch {0x8010001D=>"Windows smart-card service unavailable",0x8010002E=>"No reader connected",0x8010000C=>"Place one card on the reader",0x8010000B=>"Reader is in use",0x80100069=>"Card removed",_=>"Smart-card connection failed"};
        throw new IOException($"{text} (0x{code:X8})");
    }
    public static List<string> Readers()
    {
        Check(SCardEstablishContext(0,0,0,out var ctx));try
        {
            uint n=0;int code=SCardListReadersW(ctx,null,null,ref n);if((uint)code==0x8010002E)return [];Check(code);
            char[] chars=new char[n];Check(SCardListReadersW(ctx,null,chars,ref n));return new string(chars).Split('\0',StringSplitOptions.RemoveEmptyEntries).ToList();
        }finally{SCardReleaseContext(ctx);}
    }
    public WinSmartCard(string reader)
    {
        try { Check(SCardEstablishContext(0,0,0,out context));Check(SCardConnectW(context,reader,2,3,out card,out protocol));Check(SCardBeginTransaction(card)); }
        catch {Dispose();throw;}
    }
    public byte[] Transmit(byte[] command)
    {
        var pci=new Pci {Protocol=protocol,Length=8};byte[] output=new byte[65538];uint n=(uint)output.Length;
        Check(SCardTransmit(card,ref pci,command,(uint)command.Length,0,output,ref n));return output.AsSpan(0,(int)n).ToArray();
    }
    public void Dispose(){if(card!=0){SCardEndTransaction(card,1);SCardDisconnect(card,1);card=0;}if(context!=0){SCardReleaseContext(context);context=0;}}
}
public class CardStatusException(int status):IOException($"Card returned {status:X4}") { public int Status {get;}=status; }
public static class Apdu
{
    public static byte[] Command(byte cla,byte ins,byte p1,byte p2,byte[]? data=null,int? le=null)
    {
        data??=[];if(data.Length>255)throw new InvalidOperationException("Short APDU only");
        var bytes=new List<byte>{cla,ins,p1,p2};if(data.Length>0){bytes.Add((byte)data.Length);bytes.AddRange(data);}if(le!=null)bytes.Add((byte)(le.Value==256?0:le.Value));return bytes.ToArray();
    }
    public static byte[] Checked(byte[] response)
    {
        if(response.Length<2)throw new IOException("Truncated APDU response");int sw=response[^2]*256+response[^1];if(sw!=0x9000)throw new CardStatusException(sw);return response[..^2];
    }
}
