using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using WpfGuiService.Services;
using NLog;
using System.Diagnostics;
using Notification.Wpf;
using WpfGuiService.Services.Notifications;

namespace WpfGuiService
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger _logger = LogManager.GetCurrentClassLogger();

        public App()
        {
            var serviceCollection = new ServiceCollection();
            ConfigureServices(serviceCollection);

            _serviceProvider = serviceCollection.BuildServiceProvider();
        }

        private void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton<IKernelService, KernelService>();
            services.AddSingleton<MainWindow>();
            services.AddSingleton<IYaraEngine, YaraEngine>();
            services.AddSingleton<INotificationManager, NotificationManager>();
            services.AddSingleton<INotificationService, NotificationService>();
        }

        private void App_OnStartup(object sender, StartupEventArgs e)
        {
            _logger.Info("App started");
            _logger.Debug("Process.GetCurrentProcess().Id: " + Process.GetCurrentProcess().Id);
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            var mainWindow = _serviceProvider.GetService<MainWindow>();
            mainWindow.Show();
        }

        private void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            _logger.Error("Unhandled exception: " + e.ExceptionObject);
            MessageBox.Show("Unhandled exception: " + e.ExceptionObject);
        }
    }
}
