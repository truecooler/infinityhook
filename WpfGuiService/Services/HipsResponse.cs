using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace WpfGuiService.Services
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct HipsResponse
    {
        public Guid SessionId { get; set; }
        
        public Verdict Verdict { get; set; }

        public override string ToString() => "SessionId: " + SessionId + ", Verdict: " + Verdict;
    }
}
