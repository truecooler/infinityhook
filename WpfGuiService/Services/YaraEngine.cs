using dnYara;
using Microsoft.Extensions.Caching.Memory;
using NLog;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.ObjectiveC;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace WpfGuiService.Services
{
    internal class YaraEngine : IYaraEngine
    {
        YaraContext _ctx = null;

        CompiledRules _rules = null;

        Scanner _scanner = null;

        ILogger _logger = LogManager.GetCurrentClassLogger();

        private readonly MemoryCache _fileScanCache = new MemoryCache(new MemoryCacheOptions());
        private readonly MemoryCacheEntryOptions _fileScanCacheEntryOptions = new MemoryCacheEntryOptions()
        .SetSlidingExpiration(TimeSpan.FromMinutes(5)); // Entity will be expired, if it didn't request in period more than 5 seconds
        //.SetAbsoluteExpiration(TimeSpan.FromMinutes(10)); // In this period entity will be expired

        public YaraEngine()
        {
            var ruleFiles = Directory.GetFiles(@"Yara", "*.yara", SearchOption.AllDirectories).ToArray();

            _ctx = new YaraContext();
            using (var compiler = new Compiler())
            {
                foreach (var yara in ruleFiles)
                {
                    compiler.AddRuleFile(yara);
                }

                _rules = compiler.Compile();

                Console.WriteLine($"* Compiled");
            }

            _scanner = new Scanner();
        }

        public void Dispose()
        {
            _ctx.Dispose();
            _rules.Dispose();
        }

        public IEnumerable<ScanResult> ScanProcess(int pid)
        {
            var processName = Process.GetProcessById(pid)?.ProcessName ?? "null";
            _logger.Debug($"Scanning process {processName}({pid})...");
            var timer = Stopwatch.StartNew();

            var scanResults = _scanner.ScanProcess(pid, _rules);

            timer.Stop();
            _logger.Debug($"Process {processName}({pid}) scan results: {scanResults.Count}. Scan duration: {timer.Elapsed}");

            return scanResults;
        }

        public IEnumerable<ScanResult> ScanFile(string filePath, out bool isCacheMiss)
        {
            _logger.Debug($"Scanning file {filePath}...");
            var timer = Stopwatch.StartNew();

            var fi = new FileInfo(filePath);
            var key = new ScanResultCacheKey(filePath, fi.Length, fi.LastWriteTime);
            List<ScanResult> scanResults = null;
            string detectionRule = string.Empty;
            if (!_fileScanCache.TryGetValue(key, out scanResults))
            {
                _logger.Debug($"Scan results for file {filePath} cache miss");
                scanResults = _scanner.ScanFile(filePath, _rules);
                _fileScanCache.Set(key, scanResults);
                if (scanResults.Any())
                {
                    detectionRule = scanResults.First().MatchingRule.Identifier;
                    _logger.Debug($"Detected malware file {filePath}, rule: {detectionRule}");
                }
                else
                {
                    _logger.Debug($"No malware detected in file {filePath}");
                }
                isCacheMiss = true;
            }
            else
            {
                _logger.Debug($"Scan results for file {filePath} cache hit");
                if (scanResults.Any())
                {
                    detectionRule = scanResults.First().MatchingRule.Identifier;
                    _logger.Debug($"Detected malware file {filePath}, found by cache, rule: {detectionRule}");
                }
                else
                {
                    _logger.Debug($"No malware detected in file {filePath}, found by cache");
                }
                isCacheMiss = false;
            }

            timer.Stop();
            _logger.Debug($"{filePath} scan results: {scanResults.Count}. Scan duration: {timer.Elapsed}");
            return scanResults;
        }

        
    }
}
