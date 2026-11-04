using System.Windows;
namespace Cedula.Desktop;

public partial class DeleteProfileDialog : Window
{
    public DeleteProfileDialog()
    {
        InitializeComponent();
        Loaded += (_, _) => CancelButton.Focus();
    }

    void ViewportSizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (ContentScale == null) return;
        // Scale in device-independent units without shrinking the readable baseline.
        double scale = Math.Max(1, Math.Min(e.NewSize.Width / 740d, e.NewSize.Height / 420d));
        ContentScale.ScaleX = ContentScale.ScaleY = scale;
    }

    void ConfirmDelete(object sender, RoutedEventArgs e) => DialogResult = true;
}
