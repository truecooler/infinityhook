using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WpfGuiService.Services
{
    public interface IKernelService
    {
        void ConnectToDriverAndSubscribeForEvents();

        void EndReceiveNotifications();

        //void SetProtectionStatus(ProtectionType protectionType, bool status);

        //bool GetProtectionStatus(ProtectionType protectionType);

        bool OasStatus { get; set; }

        bool HipsStatus { get; set; }

        bool SelfDefenceStatus { get; set; }

        bool BackgroundScanStatus { get; set; }
    }
}
