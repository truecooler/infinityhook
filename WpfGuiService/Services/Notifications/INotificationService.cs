using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WpfGuiService.Services.Notifications
{
    public interface INotificationService
    {
        void ShowOasDetectNotification(int callerPid, string processName, string objectPath, string detectionRule);

        void ShowHipsDetectNotification(int calllerPid, string processName, string objectPath, string detectionRule);

        void ShowSelfDefenceNotification(int callerPid, string processName, string eventAction);

        void ShowMemoryScannerDetectNotification(int callerPid, string processName, string objectPath, string detectionRule);
    }
}
