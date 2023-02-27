using FontAwesome5;
using Notification.Wpf;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Media;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using WpfGuiService.Services;
using WpfGuiService.Services.Notifications;

namespace WpfGuiService
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly IKernelService _kernelService;
        private readonly INotificationService _notificationService;

        public MainWindow()
        {

        }

        private void OnClosing(object sender, CancelEventArgs e)
        {
            e.Cancel = true;
            //Do whatever you want here..
        }

        public MainWindow(IKernelService kernelService, INotificationService notificationService)
        {
            InitializeComponent();
            _notificationService = notificationService;
            _kernelService = kernelService;
        }

        void OnLoad(object sender, RoutedEventArgs e)
        {
            try
            {
                _kernelService.ConnectToDriverAndSubscribeForEvents();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString(), "Unable to connect to driver");
            }

        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            //var a = new YaraEngine();
            //var b = a.Scan("C:\\Users\\truec\\Desktop\\CKIE\\a.txt");
            _notificationService.ShowOasDetectNotification(123, "lolka.exe", "lolka", "kek");
            _notificationService.ShowHipsDetectNotification(123, "lolka.exe", "lolka", "kek");
        }

        private void SelfDefenceToggle_Checked(object sender, RoutedEventArgs e)
        {
            var value = (sender as CheckBox).IsChecked ?? throw new InvalidOperationException("Checkbox is null");
            _kernelService.SelfDefenceStatus = value;
        }

        private void HipsToggle_Checked(object sender, RoutedEventArgs e)
        {
            var value = (sender as CheckBox).IsChecked ?? throw new InvalidOperationException("Checkbox is null");
            _kernelService.HipsStatus = value;
        }

        private void OasToggle_Checked(object sender, RoutedEventArgs e)
        {
            var value = (sender as CheckBox).IsChecked ?? throw new InvalidOperationException("Checkbox is null");
            _kernelService.OasStatus = value;
        }

        private void BackGroundScanToggle_Checked(object sender, RoutedEventArgs e)
        {
            var value = (sender as CheckBox).IsChecked ?? throw new InvalidOperationException("Checkbox is null");
            _kernelService.BackgroundScanStatus = value;
        }
    }
}
