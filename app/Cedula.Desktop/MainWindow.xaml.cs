using System.IO;
using System.Diagnostics;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using Cedula.Core;
namespace Cedula.Desktop;
public partial class MainWindow:Window
{
    Repository repository;
    Scan? current;
    List<Scan> scans=[];
    CancellationTokenSource? cancellation;
    readonly string[] args;
    bool busy;
    public MainWindow(string[] arguments)
    {
        args=arguments;
        // Software rendering keeps the same UI usable in remote desktops and Wine.
        System.Windows.Media.RenderOptions.ProcessRenderMode=System.Windows.Interop.RenderMode.SoftwareOnly;
        InitializeComponent();
        Rsa1024Timeline.ItemsSource=new[]
        {
            new RsaMilestone("NIST (United States)","2011 / 2014","Deprecated in 2011; new signatures disallowed from Jan 2014. Legacy verification is separate.","https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-131a.pdf"),
            new RsaMilestone("ETSI (Europe)","2011","No longer recommended; limited short-term guidance persisted until 2018.","https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/01.05.01_60/ts_119312v010501p.pdf"),
            new RsaMilestone("CA/Browser Forum (international)","2013 / 2014","Public TLS subscriber certificates expiring after Dec 2013 require RSA ≥ 2048 bits.","https://cabforum.org/uploads/BRv1.2.0.pdf"),
            new RsaMilestone("IETF (international)","2015","TLS guidance recommends RSA ≥ 2048 bits; not a universal deprecation date.","https://www.rfc-editor.org/rfc/rfc7525.html#section-4.3")
        };
        repository=args.Contains("--smoke")?new Repository(Path.Combine(args[^1],"Data")):((App)Application.Current).OpenRepository();
        int recovered=repository.RecoverAcquisitions();
        RefreshProfiles();
        if(recovered>0)Status.Text=$"Recovered {recovered} interrupted scan(s)";
        Loaded+=async(_,_)=>{if(args.Contains("--smoke"))await Smoke();else RefreshReader(this,new RoutedEventArgs());};
        Closing+=(_,e)=>{if(busy){cancellation?.Cancel();e.Cancel=true;Status.Text="Cancelling read; close again once saved.";}};
        Closed+=(_,_)=>repository.Dispose();
    }
    void ViewportSizeChanged(object sender,SizeChangedEventArgs e)
    {
        if(WorkspaceScale==null)return;
        // Work in WPF device-independent units: monitor DPI scaling is applied separately.
        // LayoutTransform scales controls, fonts, spacing and images together while the
        // existing Grid/WrapPanel/ScrollViewer layout still fills the available window.
        // Small windows keep the baseline font size instead of shrinking text to fit.
        double scale=Math.Max(1,Math.Min(e.NewSize.Width/1280d,e.NewSize.Height/840d));
        if(Math.Abs(WorkspaceScale.ScaleX-scale)<0.001)return;
        WorkspaceScale.ScaleX=WorkspaceScale.ScaleY=scale;
    }
    record RsaMilestone(string Organization,string Year,string Scope,string Source);
    void OpenStandardSource(object sender,System.Windows.Navigation.RequestNavigateEventArgs e)
    {
        try{Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri){UseShellExecute=true});}
        catch(Exception){Status.Text="Could not open browser. Source: "+e.Uri.AbsoluteUri;}
        e.Handled=true;
    }
    void RefreshProfiles(){scans=repository.List();ApplySearch();}
    void ApplySearch(){if(Profiles==null)return;string term=Search.Text;Profiles.ItemsSource=scans.Where(s=>s.Label.Contains(term,StringComparison.OrdinalIgnoreCase)).ToList();}
    void SearchChanged(object sender,TextChangedEventArgs e)=>ApplySearch();
    void ProfileSelected(object sender,SelectionChangedEventArgs e){if(Profiles.SelectedItem is Scan scan)Show(scan);}
    void Show(Scan scan)
    {
        Rsa1024Notice.Visibility=scan.Keys.Any(k=>k.Algorithm=="RSA"&&k.Bits==1024)?Visibility.Visible:Visibility.Collapsed;
        current=scan;PersonName.Text=scan.Name;Subtitle.Text=scan.Document+" · "+scan.Time.ToLocalTime().ToString("g");Summary.Text=scan.Summary;
        Warnings.Text=string.Join("\n\n",scan.Findings.Select(f=>"⚠ "+f.Title+"\n"+f.Evidence));ScanError.Text=scan.Error;
        IdentityGrid.ItemsSource=scan.Fields;InventoryGrid.ItemsSource=scan.Objects.Select(x=>new InventoryRow(x.Application,x.Name,x.Fid,x.Status,x.Bytes.Length,x.DeclaredLength,x.Detail,x.Sha256)).ToList();ChecksGrid.ItemsSource=scan.Checks;
        KeyList.ItemsSource=scan.Keys;KeyDetails.Clear();if(scan.Keys.Count>0)KeyList.SelectedIndex=0;
        Portrait.Source=LargePortrait.Source=Image(scan,"portrait");Signature.Source=LargeSignature.Source=Image(scan,"signature");
    }
    static BitmapImage? Image(Scan scan,string kind)
    {
        var asset=scan.Assets.FirstOrDefault(x=>x.Kind==kind);if(asset==null)return null;
        try{using var bytes=new MemoryStream(asset.Bytes);var image=new BitmapImage();image.BeginInit();image.CacheOption=BitmapCacheOption.OnLoad;image.StreamSource=bytes;image.EndInit();image.Freeze();return image;}catch{return null;}
    }
    void KeySelected(object sender,SelectionChangedEventArgs e){KeyDetails.Text=(KeyList.SelectedItem as KeyInfo)?.Details??"";}
    record InventoryRow(string Application,string Name,string Fid,string Status,int Bytes,int? DeclaredLength,string Detail,string Sha256);
    void ObjectSelected(object sender,SelectionChangedEventArgs e)
    {
        if(current==null||InventoryGrid.SelectedItem is not InventoryRow row){ObjectDetails.Clear();return;}
        var obj=current.Objects.Single(x=>x.Application==row.Application&&x.Name==row.Name);
        var text=new System.Text.StringBuilder($"{obj.Identity} / {obj.Status} / {obj.Bytes.Length} bytes\n{obj.Detail}\nSHA-256: {obj.Sha256}\n\n");
        for(int i=0;i<obj.Bytes.Length;i+=24)text.Append($"{i:X6}: ").AppendLine(Format.Hex(obj.Bytes.AsSpan(i,Math.Min(24,obj.Bytes.Length-i)).ToArray()));
        try{text.AppendLine("\nASN.1 / BER:").Append(Org.BouncyCastle.Asn1.Utilities.Asn1Dump.DumpAsString(Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(obj.Bytes),true));}catch{/* Exact hex remains available for non-ASN.1 objects. */}
        ObjectDetails.Text=text.ToString();
    }
    void NewProfile(object sender,RoutedEventArgs e)
    {
        if(busy)return;Rsa1024Notice.Visibility=Visibility.Collapsed;current=null;Profiles.SelectedItem=null;Can.Clear();PersonName.Text="New profile";Subtitle.Text="Place a cédula on the reader and enter its CAN.";Summary.Text="No scan loaded";Warnings.Text="";ScanError.Text="";
        Portrait.Source=Signature.Source=LargePortrait.Source=LargeSignature.Source=null;IdentityGrid.ItemsSource=null;InventoryGrid.ItemsSource=null;ChecksGrid.ItemsSource=null;KeyList.ItemsSource=null;KeyDetails.Clear();ObjectDetails.Clear();Tabs.SelectedIndex=0;Can.Focus();
    }
    void RefreshReader(object sender,RoutedEventArgs e)
    {
        if(busy)return;
        try{var readers=WinSmartCard.Readers();Readers.ItemsSource=readers;if(readers.Count>0)Readers.SelectedIndex=0;Status.Text=readers.Count==0?"No reader connected":"Reader ready";}
        catch(Exception ex){Status.Text=ex.Message;}
    }
    async void ReadCard(object sender,RoutedEventArgs e)
    {
        if(busy)return;
        if(Can.Password.Length!=6||Can.Password.Any(c=>c<'0'||c>'9')){MessageBox.Show("Enter the six-digit CAN printed on the card.","CAN required");Can.Focus();return;}
        if(Readers.SelectedItem is not string reader){MessageBox.Show("Connect and select a reader, then refresh.");return;}
        char[] secret=Can.Password.ToCharArray();Can.Clear();cancellation=new();SetBusy(true);
        try
        {
            var previous=current;
            var progress=new Progress<string>(value=>Status.Text=value);
            var scan=await Task.Run(()=>LiveReader.Read(reader,secret,repository.Root,progress,cancellation.Token));
            if(scan.Objects.Count==0){Status.Text=scan.Error;MessageBox.Show(scan.Error,"Read failed");return;}
            AttachProfile(scan,previous);repository.Save(scan);RefreshProfiles();Show(scan);Status.Text=scan.State=="Complete"?"Saved locally":"Incomplete scan saved locally";
        }
        catch(Exception ex){Status.Text="Not saved: "+ex.Message;MessageBox.Show(ex.Message,"Read / save error");}
        finally{Array.Clear(secret);SetBusy(false);cancellation.Dispose();cancellation=null;}
    }
    void AttachProfile(Scan scan,Scan? previous)
    {
        bool Same(Scan a,Scan b)=>a.Document!="Unknown number"&&a.Document==b.Document&&a.Issuer==b.Issuer;
        if(previous!=null&&Same(previous,scan)){scan.ProfileId=previous.ProfileId;return;}
        var match=scans.FirstOrDefault(x=>Same(x,scan));
        if(match!=null&&MessageBox.Show("This document already has a profile. Append this scan to it? Choose No to retain a separate profile.","Existing document",MessageBoxButton.YesNo)==MessageBoxResult.Yes)scan.ProfileId=match.ProfileId;
    }
    void SetBusy(bool value){busy=value;ReadButton.IsEnabled=NewButton.IsEnabled=ImportButton.IsEnabled=Profiles.IsEnabled=!value;CancelButton.IsEnabled=value;}
    void CancelRead(object sender,RoutedEventArgs e)=>cancellation?.Cancel();
    void ImportRecorded(object sender,RoutedEventArgs e)
    {
        if(busy)return;var picker=new OpenFileDialog{Title="Open recorded acquisition manifest (not a live scan)",Filter="Recorded manifest|*.json"};if(picker.ShowDialog()!=true)return;
        try{var scan=RecordedReader.Read(picker.FileName);AttachProfile(scan,null);repository.Save(scan);RefreshProfiles();Show(scan);Status.Text="Recorded evidence imported · no reader used";}catch(Exception ex){MessageBox.Show(ex.Message,"Import failed");}
    }
    void ExportScan(object sender,RoutedEventArgs e)=>Export(false);
    void ExportHistory(object sender,RoutedEventArgs e)=>Export(true);
    void Export(bool history)
    {
        if(current==null||busy)return;var picker=new ExportDialog("cedula-"+current.ProfileId+".zip"){Owner=this};if(picker.ShowDialog()!=true)return;
        try{repository.Export(history?scans.Where(x=>x.ProfileId==current.ProfileId):[current],picker.Destination);Status.Text="ZIP exported and byte hashes verified";}catch(Exception ex){MessageBox.Show(ex.Message,"Export failed");}
    }
    void RestoreZip(object sender,RoutedEventArgs e)
    {
        if(busy)return;var picker=new OpenFileDialog{Filter="ZIP archive|*.zip"};if(picker.ShowDialog()!=true)return;
        try{repository.Restore(picker.FileName);RefreshProfiles();Status.Text="ZIP restored; integrity checked";}catch(Exception ex){MessageBox.Show(ex.Message,"Restore failed");}
    }
    void DeleteProfile(object sender,RoutedEventArgs e)
    {
        if(current==null||busy)return;
        if(new DeleteProfileDialog{Owner=this}.ShowDialog()!=true)return;
        repository.DeleteProfile(current.ProfileId);RefreshProfiles();NewProfile(sender,e);
    }
    void OpenData(object sender,RoutedEventArgs e)=>Process.Start(new ProcessStartInfo(repository.Root){UseShellExecute=true});
    async Task Smoke()
    {
        string output=args[^1];Directory.CreateDirectory(output);
        try
        {
            string fixture=args[Array.IndexOf(args,"--smoke")+1];var scan=RecordedReader.Read(fixture);repository.Save(scan);RefreshProfiles();Show(scan);
            if(scan.Keys.Count==0||scan.Findings.All(x=>x.Rule!="RSA_UNDERSIZED"))throw new Exception("Missing RSA warning in smoke fixture");
            if(Portrait.Source==null||Signature.Source==null)throw new Exception("Images did not decode in WPF");
            if(Rsa1024Notice.Visibility!=Visibility.Visible||Rsa1024Timeline.Items.Count!=4)throw new Exception("Missing RSA-1024 timeline");
            Show(new Scan{Keys=[new KeyInfo{Algorithm="RSA",Bits=2048}]});
            if(Rsa1024Notice.Visibility!=Visibility.Collapsed)throw new Exception("RSA-1024 timeline shown for RSA-2048");
            Show(scan);
            await Task.Delay(700);UpdateLayout();Capture(Path.Combine(output,"overview.png"));
            if(args.Contains("--export-dialog-check"))
            {
                var dialog=new ExportDialog("picker-test.zip"){Owner=this};
                Exception? dialogError=null;
                string target=Path.Combine(output,"picker-test.zip");File.WriteAllText(target,"existing test file");
                dialog.Loaded+=async(_,_)=>
                {
                    try
                    {
                        foreach(var size in new[]{new Size(850,650),new Size(1100,800),new Size(1800,1200)})
                        {
                            dialog.Width=size.Width;dialog.Height=size.Height;await Task.Delay(250);dialog.UpdateLayout();
                            var bounds=dialog.ExportButton.TransformToAncestor(dialog.Viewport).TransformBounds(new Rect(dialog.ExportButton.RenderSize));
                            if(bounds.Right>dialog.Viewport.ActualWidth+1||bounds.Bottom>dialog.Viewport.ActualHeight+1||dialog.Folders.ActualHeight<40)throw new Exception("Export picker clipped");
                            if(size.Width==1800&&dialog.ContentScale.ScaleX<=1)throw new Exception("Export picker did not scale");
                            CaptureWindow(dialog,Path.Combine(output,$"export-{(int)size.Width}.png"));
                        }
                        dialog.FolderPath.Text=output;
                        dialog.ExportButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                        if(dialog.ReplaceExisting.Visibility!=Visibility.Visible||dialog.Destination.Length!=0)throw new Exception("Existing export was not protected");
                        dialog.FileName.Text="new-picker-test";
                        if(dialog.ReplaceExisting.IsChecked==true)throw new Exception("Replacement consent retained after name change");
                        dialog.ExportButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                    }
                    catch(Exception ex){dialogError=ex;dialog.Close();}
                };
                if(dialog.ShowDialog()!=true)throw dialogError??new Exception("Export dialog did not accept destination");
                if(dialog.Destination!=Path.Combine(output,"new-picker-test.zip"))throw new Exception("Wrong export destination");
                repository.Export([scan],dialog.Destination);
                if(File.ReadAllText(target)!="existing test file")throw new Exception("Existing export changed");
            }
            if(args.Contains("--delete-dialog-check"))
            {
                var dialog=new DeleteProfileDialog{Owner=this};
                Exception? dialogError=null;
                var layouts=new List<object>();
                dialog.Loaded+=async(_,_)=>
                {
                    try
                    {
                        foreach(var size in new[]{new Size(560,360),new Size(760,460),new Size(1200,800)})
                        {
                            dialog.Width=size.Width;dialog.Height=size.Height;
                            await Task.Delay(250);dialog.UpdateLayout();
                            var button=dialog.DeleteButton.TransformToAncestor(dialog.Viewport).TransformBounds(new Rect(dialog.DeleteButton.RenderSize));
                            if(button.Bottom>dialog.Viewport.ActualHeight+1||button.Right>dialog.Viewport.ActualWidth+1)throw new Exception("Delete dialog button clipped");
                            if(size.Width==1200&&dialog.ContentScale.ScaleX<=1)throw new Exception("Delete dialog did not scale");
                            layouts.Add(new{Width=dialog.ActualWidth,Height=dialog.ActualHeight,Scale=dialog.ContentScale.ScaleX});
                            CaptureWindow(dialog,Path.Combine(output,$"delete-{(int)size.Width}.png"));
                        }
                        dialog.WindowState=WindowState.Maximized;await Task.Delay(250);dialog.UpdateLayout();
                        CaptureWindow(dialog,Path.Combine(output,"delete-maximized.png"));
                    }
                    catch(Exception ex){dialogError=ex;}
                    finally{dialog.Close();}
                };
                if(dialog.ShowDialog()==true)throw new Exception("Closing dialog authorized deletion");
                if(dialogError!=null)throw dialogError;
                if(!repository.List().Any(x=>x.Id==scan.Id))throw new Exception("Dialog check deleted a profile");
                File.WriteAllText(Path.Combine(output,"delete-dialog-results.json"),JsonSerializer.Serialize(layouts,Format.Json));
            }
            Tabs.SelectedIndex=3;KeyList.SelectedItem=scan.Keys.First(x=>x.Algorithm=="RSA");await Task.Delay(300);UpdateLayout();Capture(Path.Combine(output,"certificates.png"));
            if(args.Contains("--resize-check"))
            {
                var layouts=new List<object>();
                foreach(var size in new[]{new Size(1000,700),new Size(1320,900),new Size(1920,1080),new Size(2560,1440)})
                {
                    WindowState=WindowState.Normal;Width=size.Width;Height=size.Height;Tabs.SelectedIndex=0;
                    await Task.Delay(250);UpdateLayout();
                    var bounds=ReadButton.TransformToAncestor(Viewport).TransformBounds(new Rect(ReadButton.RenderSize));
                    var portrait=Portrait.TransformToAncestor(Viewport).TransformBounds(new Rect(Portrait.RenderSize));
                    if(bounds.Right>Viewport.ActualWidth+1||bounds.Bottom>Viewport.ActualHeight+1)throw new Exception("Read button clipped after resizing");
                    layouts.Add(new{Width=ActualWidth,Height=ActualHeight,Scale=WorkspaceScale.ScaleX,ButtonHeight=bounds.Height,PortraitHeight=portrait.Height});
                    Capture(Path.Combine(output,$"layout-{(int)size.Width}x{(int)size.Height}.png"));
                }
                WindowState=WindowState.Maximized;await Task.Delay(300);UpdateLayout();
                Capture(Path.Combine(output,"layout-maximized.png"));
                layouts.Add(new{State="Maximized",Width=ActualWidth,Height=ActualHeight,Scale=WorkspaceScale.ScaleX});
                File.WriteAllText(Path.Combine(output,"resize-results.json"),JsonSerializer.Serialize(layouts,Format.Json));
                WindowState=WindowState.Normal;Width=1320;Height=900;await Task.Delay(200);
            }
            repository.Export([scan],Path.Combine(output,"scan.zip"));
            for(int i=0;i<Tabs.Items.Count;i++){File.WriteAllText(Path.Combine(output,"smoke-stage.txt"),"Tab "+i);Tabs.SelectedIndex=i;UpdateLayout();await Task.Delay(80);}
            File.WriteAllText(Path.Combine(output,"smoke-stage.txt"),"New profile");
            NewProfile(this,new RoutedEventArgs());
            if(Rsa1024Notice.Visibility!=Visibility.Collapsed||Portrait.Source!=null||Signature.Source!=null||current!=null||KeyList.ItemsSource!=null||Can.Password.Length!=0)throw new Exception("New profile retained old data");
            Show(repository.List().Single(x=>x.Id==scan.Id));
            if(Portrait.Source==null||Signature.Source==null)throw new Exception("Saved profile did not reopen");
            File.WriteAllText(Path.Combine(output,"smoke-result.json"),JsonSerializer.Serialize(new{Passed=true,Runtime=System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,Images=2,Keys=scan.Keys.Count,Warnings=scan.Findings.Count,Checks=scan.Checks,Export="scan.zip"},Format.Json));
            Application.Current.Shutdown(0);
        }
        catch(Exception ex){File.WriteAllText(Path.Combine(output,"smoke-result.json"),JsonSerializer.Serialize(new{Passed=false,Error=ex.ToString()},Format.Json));Application.Current.Shutdown(1);}
    }
    void Capture(string path)
        =>CaptureWindow(this,path);
    static void CaptureWindow(Window window,string path)
    {
        var bitmap=new RenderTargetBitmap((int)window.ActualWidth,(int)window.ActualHeight,96,96,PixelFormats.Pbgra32);bitmap.Render(window);var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(bitmap));using var file=File.Create(path);encoder.Save(file);
    }
}
