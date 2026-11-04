using System.Windows;
namespace Cedula.Desktop;
public partial class App:Application
{
    StartupSession? session;
    internal Cedula.Core.Repository OpenRepository()=>session!.OpenRepository();
    protected override void OnExit(ExitEventArgs e)
    {
        session?.Dispose();base.OnExit(e);
    }
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if(e.Args.Contains("--font-info"))
        {
            var fontInfo=new{SystemFonts=System.Windows.Media.Fonts.SystemFontFamilies.Select(x=>x.Source).ToArray(),Embedded=System.Windows.Media.Fonts.GetFontFamilies(new Uri("pack://application:,,,/"),"./Fonts/").Select(x=>x.Source).ToArray()};
            System.IO.File.WriteAllText(e.Args[^1],System.Text.Json.JsonSerializer.Serialize(fontInfo,Cedula.Core.Format.Json));Shutdown(0);return;
        }
        if(e.Args.Contains("--diagnose-readers"))
        {
            string output=e.Args[^1];
            try{System.IO.File.WriteAllText(output,System.Text.Json.JsonSerializer.Serialize(new{Readers=Cedula.Core.WinSmartCard.Readers()},Cedula.Core.Format.Json));Shutdown(0);}
            catch(Exception ex){System.IO.File.WriteAllText(output,System.Text.Json.JsonSerializer.Serialize(new{Error=ex.Message},Cedula.Core.Format.Json));Shutdown(1);}
            return;
        }
        if(!e.Args.Contains("--smoke"))
        {
            session=new StartupSession();
            if(!session.IsPrimary)
            {
                if(e.Args.Contains("--startup-check"))System.IO.File.WriteAllText(e.Args[^1],"Existing instance activated");
                Shutdown(0);return;
            }
        }
        ShutdownMode=ShutdownMode.OnMainWindowClose;
        var available=System.Windows.Media.Fonts.SystemFontFamilies.ToDictionary(x=>x.Source,StringComparer.OrdinalIgnoreCase);
        var uiName=new[]{"Segoe UI","DejaVu Sans","Liberation Sans","FreeSans"}.FirstOrDefault(available.ContainsKey);
        var monoName=new[]{"Consolas","DejaVu Sans Mono","Liberation Mono","FreeMono"}.FirstOrDefault(available.ContainsKey);
        Resources["AppFont"]=uiName!=null?available[uiName]:new System.Windows.Media.FontFamily("pack://application:,,,/CedulaReader;component/Fonts/#DejaVu Sans");
        Resources["AppMono"]=monoName!=null?available[monoName]:Resources["AppFont"];
        Resources[SystemFonts.MessageFontFamilyKey]=Resources["AppFont"];
        DispatcherUnhandledException+=(s,args)=>{MessageBox.Show(args.Exception.Message,"Cédula Reader");args.Handled=true;};
        try
        {
            var window=new MainWindow(e.Args);MainWindow=window;
            if(e.Args.Contains("--startup-check"))
            {
                window.Loaded+=async(_,_)=>
                {
                    await Task.Delay(4000);
                    System.IO.File.WriteAllText(e.Args[^1],"Opened existing data location; closing normally");
                    window.Close();
                };
            }
            window.Show();session?.WatchActivation(window);
        }
        catch(Exception ex)
        {
            MessageBox.Show("The saved data folder could not be opened. Close any older copy of Cédula Reader and check folder permissions. Your saved profiles have not been moved.\n\n"+ex.Message,"Cannot open saved profiles");
            Shutdown(1);
        }
    }
}
