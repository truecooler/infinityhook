using dnYara;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WpfGuiService.Services
{
    public interface IYaraEngine : IDisposable
    {
        IEnumerable<ScanResult> ScanProcess(int pid);

        IEnumerable<ScanResult> ScanFile(string filePath, out bool isCacheMiss);
    }
}
