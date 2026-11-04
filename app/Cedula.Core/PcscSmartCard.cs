using System.Runtime.InteropServices;
namespace Cedula.Core;
// PC/SC through pcsc-lite (libpcsclite.so.1) on Linux. DWORD and the context/card handles are pointer-sized there.
public sealed class PcscSmartCard : ICardTransport
{
    nint context,card;nuint protocol;
    [StructLayout(LayoutKind.Sequential)] struct Pci { public nuint Protocol; public nuint Length; }
    const string Lib="libpcsclite.so.1";
    [DllImport(Lib)] static extern nint SCardEstablishContext(nuint scope,nint a,nint b,out nint context);
    [DllImport(Lib)] static extern nint SCardReleaseContext(nint context);
    [DllImport(Lib)] static extern nint SCardListReaders(nint context,string? groups,byte[]? readers,ref nuint length);
    [DllImport(Lib)] static extern nint SCardConnect(nint context,string reader,nuint share,nuint protocols,out nint card,out nuint active);
    [DllImport(Lib)] static extern nint SCardDisconnect(nint card,nuint disposition);
    [DllImport(Lib)] static extern nint SCardBeginTransaction(nint card);
    [DllImport(Lib)] static extern nint SCardEndTransaction(nint card,nuint disposition);
    [DllImport(Lib)] static extern nint SCardTransmit(nint card,ref Pci pci,byte[] send,nuint length,nint receivePci,byte[] receive,ref nuint receiveLength);
    static void Check(nint raw)
    {
        int code=unchecked((int)raw);if(code==0)return;
        string text=(uint)code switch {0x8010001D=>"PC/SC service unavailable (is pcscd running?)",0x8010002E=>"No reader connected",0x8010000C=>"Place one card on the reader",0x8010000B=>"Reader is in use",0x80100069=>"Card removed",_=>"Smart-card connection failed"};
        throw new IOException($"{text} (0x{code:X8})");
    }
    public static List<string> Readers()
    {
        Check(SCardEstablishContext(2,0,0,out var ctx));try
        {
            nuint n=0;nint code=SCardListReaders(ctx,null,null,ref n);if((uint)unchecked((int)code)==0x8010002E)return [];Check(code);
            byte[] bytes=new byte[n];Check(SCardListReaders(ctx,null,bytes,ref n));
            return System.Text.Encoding.UTF8.GetString(bytes,0,(int)n).Split('\0',StringSplitOptions.RemoveEmptyEntries).ToList();
        }finally{SCardReleaseContext(ctx);}
    }
    public PcscSmartCard(string reader)
    {
        try { Check(SCardEstablishContext(2,0,0,out context));Check(SCardConnect(context,reader,2,3,out card,out protocol));Check(SCardBeginTransaction(card)); }
        catch {Dispose();throw;}
    }
    public byte[] Transmit(byte[] command)
    {
        var pci=new Pci {Protocol=protocol,Length=(nuint)(2*nint.Size)};byte[] output=new byte[65538];nuint n=(nuint)output.Length;
        Check(SCardTransmit(card,ref pci,command,(nuint)command.Length,0,output,ref n));return output.AsSpan(0,(int)n).ToArray();
    }
    public void Dispose(){if(card!=0){SCardEndTransaction(card,0);SCardDisconnect(card,0);card=0;}if(context!=0){SCardReleaseContext(context);context=0;}}
}
public static class CardTransport
{
    public static List<string> Readers()=>OperatingSystem.IsWindows()?WinSmartCard.Readers():PcscSmartCard.Readers();
    public static ICardTransport Open(string reader)=>OperatingSystem.IsWindows()?new WinSmartCard(reader):new PcscSmartCard(reader);
}
