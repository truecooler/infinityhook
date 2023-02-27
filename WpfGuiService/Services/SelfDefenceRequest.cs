using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace WpfGuiService.Services
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SelfDefenceRequest
    {
        public Guid SessionId { get; set; }

        public nuint CallerPid { get; set; }

        public nuint CalleePid { get; set; }

        public nuint CalleeTid { get; set; }

        public ulong DesiredAccess { get; set; }

        public SelfDefenceEvent SelfDefenceEvent;

        public override string ToString() =>
            $"SessionId: {SessionId}, CallerPid: {CallerPid}, CalleePid: {CalleePid}, CalleeTid: {CalleeTid}, " +
            $"DesiredAccess: {DesiredAccess}, SelfDefenceEvent: {SelfDefenceEvent}";
    }
}
