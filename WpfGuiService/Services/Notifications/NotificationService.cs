using FontAwesome5;
using Microsoft.Extensions.Logging;
using NLog;
using Notification.Wpf;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Media;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using ILogger = NLog.ILogger;

namespace WpfGuiService.Services.Notifications
{
    internal class NotificationService : INotificationService
    {
        private readonly INotificationManager _notificationManager;
        private readonly ILogger _logger = LogManager.GetCurrentClassLogger();

        public NotificationService(INotificationManager notificationManager)
        {
            _notificationManager = notificationManager;
        }

        public void ShowHipsDetectNotification(int callerPid, string processName, string objectPath, string detectionRule)
        {
            _logger.Debug($"Show hips detect notification: callerPid: {callerPid}, processName: {processName}, " +
                $"objectPath: {objectPath}, detectionRule: {detectionRule}");
            var sb = new StringBuilder();
            sb.AppendLine($"Обнаружено технологией: HIPS");
            sb.AppendLine($"Объект: {objectPath}");
            sb.AppendLine($"Детектирующее правило: {detectionRule}");
            sb.AppendLine($"Процесс: {processName}, Pid: {callerPid}");
            Application.Current.Dispatcher.Invoke(() =>
                _notificationManager.Show(new NotificationContent
                {
                    Title = "Запуск процесса заблокирован, объект удален",
                    Message = sb.ToString(),
                    Type = NotificationType.Information,
                    Background = new BrushConverter().ConvertFromString("#FFB91F1F") as SolidColorBrush,
                    Icon = new SvgAwesome()
                    {
                        Icon = EFontAwesomeIcon.Solid_Radiation,
                        Height = 25,
                        Foreground = new SolidColorBrush(Colors.White)
                    },
                    RowsCount = 10,
                    CloseOnClick = true
                }));
            var sp = new SoundPlayer(@"Sounds\reloading.wav");
            sp.Play();
        }

        public void ShowMemoryScannerDetectNotification(int callerPid, string processName, string objectPath, string detectionRule)
        {
            _logger.Debug($"Show background scanner detect notification: callerPid: {callerPid}, processName: {processName}, " +
                $"objectPath: {objectPath}, detectionRule: {detectionRule}");
            var sb = new StringBuilder();
            sb.AppendLine($"Обнаружено технологией: Memory Scanner");
            sb.AppendLine($"Объект: {objectPath}");
            sb.AppendLine($"Детектирующее правило: {detectionRule}");
            sb.AppendLine($"Процесс: {processName}, Pid: {callerPid}");
            Application.Current.Dispatcher.Invoke(() =>
                _notificationManager.Show(new NotificationContent
                {
                    Title = "Обнаружен вредоносный код в памяти, процесс завершен, объект удален",
                    Message = sb.ToString(),
                    Type = NotificationType.Information,
                    Background = new BrushConverter().ConvertFromString("#FFB91F1F") as SolidColorBrush,
                    Icon = new SvgAwesome()
                    {
                        Icon = EFontAwesomeIcon.Solid_Radiation,
                        Height = 25,
                        Foreground = new SolidColorBrush(Colors.White)
                    },
                    RowsCount = 10,
                    CloseOnClick = true
                }));
            var sp = new SoundPlayer(@"Sounds\reloading.wav");
            sp.Play();
        }

        public void ShowOasDetectNotification(int callerPid, string processName, string objectPath, string detectionRule)
        {
            _logger.Debug($"Show oas detect notification: callerPid: {callerPid}, processName: {processName}, " +
                $"objectPath: {objectPath}, detectionRule: {detectionRule}");
            var sb = new StringBuilder();
            sb.AppendLine($"Обнаружено технологией: On Access Scan");
            sb.AppendLine($"Объект: {objectPath}");
            sb.AppendLine($"Детектирующее правило: {detectionRule}");
            sb.AppendLine($"Процесс: {processName}, Pid: {callerPid}");
            Application.Current.Dispatcher.Invoke(() =>
                _notificationManager.Show(new NotificationContent
                {
                    Title = "Вирус обнаружен в файле и удален",
                    Message = sb.ToString(),
                    Type = NotificationType.Information,
                    Background = new BrushConverter().ConvertFromString("#FFB91F1F") as SolidColorBrush,
                    Icon = new SvgAwesome()
                    {
                        Icon = EFontAwesomeIcon.Solid_Radiation,
                        Height = 25,
                        Foreground = new SolidColorBrush(Colors.White)
                    },
                    RowsCount = 10,
                    CloseOnClick = true
                }));
            var sp = new SoundPlayer(@"Sounds\reloading.wav");
            sp.Play();
        }

        public void ShowSelfDefenceNotification(int callerPid, string processName, string eventAction)
        {
            _logger.Debug($"Show self defence notification: callerPid: {callerPid}, processName: {processName}, eventAction: {eventAction}");

            var sb = new StringBuilder();
            sb.AppendLine($"Обнаружено технологией: Self Defence");
            sb.AppendLine($"Процесс: {processName}, Pid: {callerPid}");
            sb.AppendLine($"Заблокированное действие: {eventAction}");
            Application.Current.Dispatcher.Invoke(() =>
            _notificationManager.Show(new NotificationContent
            {
                Title = "Попытка вмешаться в работу антивируса",
                Message = sb.ToString(),
                Type = NotificationType.Information,
                Background = new BrushConverter().ConvertFromString("#FFB91F1F") as SolidColorBrush,
                Icon = new SvgAwesome()
                {
                    Icon = EFontAwesomeIcon.Solid_Radiation,
                    Height = 25,
                    Foreground = new SolidColorBrush(Colors.White)
                },
                RowsCount = 10,
                CloseOnClick = true,
            }));
            var sp = new SoundPlayer(@"Sounds\reloading.wav");
            sp.Play();
        }
    }
}
