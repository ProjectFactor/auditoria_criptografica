using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
namespace Cedula.Desktop;

public partial class ExportDialog : Window
{
    string folder = "";
    string? replacementPath;
    public string Destination { get; private set; } = "";
    public ExportDialog(string fileName)
    {
        InitializeComponent();
        FileName.Text = fileName;
        Drives.ItemsSource = Directory.GetLogicalDrives();
        Navigate(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
        if(folder.Length==0)Navigate(AppContext.BaseDirectory);
    }
    void ResizeContent(object sender, SizeChangedEventArgs e)
    {
        if(ContentScale==null)return;
        double scale=Math.Max(1,Math.Min(e.NewSize.Width/1080d,e.NewSize.Height/760d));
        ContentScale.ScaleX=ContentScale.ScaleY=scale;
    }
    void Navigate(string path)
    {
        try
        {
            string full=Path.GetFullPath(path);
            var items=new DirectoryInfo(full).GetDirectories().OrderBy(x=>x.Name,StringComparer.CurrentCultureIgnoreCase).ToList();
            folder=full;FolderPath.Text=full;Folders.ItemsSource=items;Error.Text="";
            ResetReplacement(this,new TextChangedEventArgs(TextBox.TextChangedEvent,UndoAction.None));
        }
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException){Error.Text="Cannot open folder: "+ex.Message;}
    }
    void Go(object sender,RoutedEventArgs e)=>Navigate(FolderPath.Text);
    void Documents(object sender,RoutedEventArgs e)=>Navigate(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
    void Desktop(object sender,RoutedEventArgs e)=>Navigate(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
    void Up(object sender,RoutedEventArgs e){if(Directory.GetParent(folder) is {} parent)Navigate(parent.FullName);}
    void DriveSelected(object sender,SelectionChangedEventArgs e){if(Drives.SelectedItem is string drive)Navigate(drive);}
    void OpenFolder(object sender,RoutedEventArgs e){if(Folders.SelectedItem is DirectoryInfo directory)Navigate(directory.FullName);}
    void PathKeyDown(object sender,KeyEventArgs e){if(e.Key==Key.Enter){Go(sender,e);e.Handled=true;}}
    void FolderKeyDown(object sender,KeyEventArgs e){if(e.Key==Key.Enter){OpenFolder(sender,e);e.Handled=true;}}
    void ResetReplacement(object sender,TextChangedEventArgs e)
    {
        replacementPath=null;
        if(ReplaceExisting==null)return;
        ReplaceExisting.IsChecked=false;ReplaceExisting.Visibility=Visibility.Collapsed;
    }
    void Confirm(object sender,RoutedEventArgs e)
    {
        try
        {
            if(FolderPath.Text!=folder){Navigate(FolderPath.Text);if(FolderPath.Text!=folder)return;}
            string name=FileName.Text.Trim();
            if(string.IsNullOrWhiteSpace(name)||name.IndexOfAny(Path.GetInvalidFileNameChars())>=0||name is "." or "..")throw new ArgumentException("Enter a valid ZIP file name without a folder path.");
            if(!name.EndsWith(".zip",StringComparison.OrdinalIgnoreCase))name+=".zip";
            string path=Path.Combine(folder,name);
            if(File.Exists(path)&&!(replacementPath==path&&ReplaceExisting.IsChecked==true))
            {
                replacementPath=path;ReplaceExisting.Visibility=Visibility.Visible;
                Error.Text="This ZIP already exists. Choose a different name or confirm replacement above.";return;
            }
            Destination=path;DialogResult=true;
        }
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException){Error.Text=ex.Message;}
    }
}
