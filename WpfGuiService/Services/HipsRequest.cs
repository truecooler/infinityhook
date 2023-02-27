using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace WpfGuiService.Services
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct HipsRequest
    {
        public Guid SessionId { get; set; }

        public nuint CallerPid { get; set; }
        
        public nuint CalleePid { get; set; }

        [field: MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
        public string ObjectPath { get; set; }

        public override string ToString() => $"SessionId: {SessionId}, CallerPid: {CallerPid}, CalleePid: {CalleePid}, ObjectPath: {ObjectPath}";
    }
}
