using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using Cedula.Core;
namespace Cedula.Desktop;

// One interactive instance per portable copy. Smoke/diagnostic runs remain isolated.
sealed class StartupSession : IDisposable
{
    readonly Mutex mutex;
    readonly EventWaitHandle activate;
    readonly bool ownsMutex;
    DispatcherTimer? timer;
    readonly string settingsDirectory;
    public bool IsPrimary => ownsMutex;
    public StartupSession()
    {
        string id=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(AppContext.BaseDirectory).ToUpperInvariant())))[..24];
        mutex=new Mutex(false,@"Local\CedulaReader-"+id);
        try{ownsMutex=mutex.WaitOne(0);}catch(AbandonedMutexException){ownsMutex=true;}
        activate=new EventWaitHandle(false,EventResetMode.AutoReset,@"Local\CedulaReader-Activate-"+id);
        settingsDirectory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"CedulaReader",id);
        if(!ownsMutex)activate.Set();
    }
    public Repository OpenRepository()
    {
        string portable=Path.Combine(AppContext.BaseDirectory,"Data");
        string settings=Path.Combine(settingsDirectory,"data-folder.txt");
        if(File.Exists(settings))return new Repository(File.ReadAllText(settings).Trim());
        // Never silently substitute an empty store for an existing, inaccessible store.
        if(Directory.Exists(portable))return new Repository(portable);
        try{return new Repository(portable);}
        catch(UnauthorizedAccessException)
        {
            Directory.CreateDirectory(settingsDirectory);
            string fallback=Path.Combine(settingsDirectory,"Data");
            var repository=new Repository(fallback);
            try{File.WriteAllText(settings,fallback);}catch{repository.Dispose();throw;}
            return repository;
        }
    }
    public void WatchActivation(Window window)
    {
        timer=new DispatcherTimer{Interval=TimeSpan.FromMilliseconds(300)};
        timer.Tick+=(_,_)=>
        {
            if(!activate.WaitOne(0))return;
            if(window.WindowState==WindowState.Minimized)window.WindowState=WindowState.Maximized;
            window.Show();window.Activate();
        };
        timer.Start();
    }
    public void Dispose()
    {
        timer?.Stop();activate.Dispose();
        if(ownsMutex)mutex.ReleaseMutex();
        mutex.Dispose();
    }
}
