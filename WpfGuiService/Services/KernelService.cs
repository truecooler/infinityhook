using dnYara;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Win32.SafeHandles;
using NLog;
using Notification.Wpf;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using WpfGuiService.Extensions;
using WpfGuiService.Services.Notifications;

namespace WpfGuiService.Services
{
    internal class KernelService : IKernelService
    {
        private readonly ILogger _logger = LogManager.GetCurrentClassLogger();
        private readonly IYaraEngine _yaraEngine;
        private readonly INotificationService _notificationService;

        private const uint FILE_DEVICE_UNKNOWN = 0x00000022;

        private enum IOCTL_METHOD : uint
        {
            METHOD_BUFFERED = 0,
            METHOD_IN_DIRECT = 1,
            METHOD_OUT_DIRECT = 2,
            METHOD_NEITHER = 3
        }

        [Flags]
        private enum IOCTL_ACCESS : uint
        {
            FILE_ANY_DATA = 0,
            FILE_READ_DATA = 1,
            FILE_WRITE_DATA = 2
        }

        private const string DeviceName = "\\\\.\\kinfinity";

        private uint HelloIoctlCode => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, IOCTL_METHOD.METHOD_BUFFERED, IOCTL_ACCESS.FILE_READ_DATA |
                    IOCTL_ACCESS.FILE_WRITE_DATA);


        private uint WaitForHipsRequestIoctlCode => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, IOCTL_METHOD.METHOD_BUFFERED, IOCTL_ACCESS.FILE_READ_DATA |
                    IOCTL_ACCESS.FILE_WRITE_DATA);

        private uint WaitForOasRequestIoctlCode => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, IOCTL_METHOD.METHOD_BUFFERED, IOCTL_ACCESS.FILE_READ_DATA |
                    IOCTL_ACCESS.FILE_WRITE_DATA);

        private uint WaitForSelfDefenceRequestIoctlCode => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, IOCTL_METHOD.METHOD_BUFFERED, IOCTL_ACCESS.FILE_READ_DATA |
                    IOCTL_ACCESS.FILE_WRITE_DATA);


        private uint SendHipsResponseIoctlCode => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, IOCTL_METHOD.METHOD_BUFFERED, IOCTL_ACCESS.FILE_READ_DATA |
                    IOCTL_ACCESS.FILE_WRITE_DATA);

        private uint SendOasResponseIoctlCode => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, IOCTL_METHOD.METHOD_BUFFERED, IOCTL_ACCESS.FILE_READ_DATA |
                    IOCTL_ACCESS.FILE_WRITE_DATA);

        private uint SendSelfDefenceResponseIoctlCode => CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, IOCTL_METHOD.METHOD_BUFFERED, IOCTL_ACCESS.FILE_READ_DATA |
                    IOCTL_ACCESS.FILE_WRITE_DATA);

        public bool OasStatus { get; set ; }
        public bool HipsStatus { get; set; }
        public bool SelfDefenceStatus { get; set; }

        private bool _backgroundScanStatus = false;
        public bool BackgroundScanStatus 
        { get => _backgroundScanStatus; 
          set 
            {
                if (value)
                {
                    _backgroundScannerTaskCts = new();
                    _backgroundProcessScannerTask = Task.Run(BackgroundProcessScanner)
                        .ContinueWith(x => _exceptionLogger, TaskContinuationOptions.OnlyOnFaulted);
                }
                else
                {
                    _backgroundScannerTaskCts.Cancel();
                }
                _backgroundScanStatus = value;
            } 
        }

        private Task _hipsNotifictaionDispatcherTask = Task.CompletedTask;
        private Task _oasNotifictaionDispatcherTask = Task.CompletedTask;
        private Task _SelfDefenceNotifictaionDispatcherTask = Task.CompletedTask;
        private Task _backgroundProcessScannerTask = Task.CompletedTask;

        private CancellationTokenSource _backgroundScannerTaskCts = new CancellationTokenSource();
        private CancellationTokenSource _kernelNotificationsTaskCts = new CancellationTokenSource();

        private Action<Task> _exceptionLogger => (x) => _logger.Error(x?.Exception?.ToString());


        private bool _notificationReceivingRunning = false;

        private readonly MemoryCache _fileScanCache = new MemoryCache(new MemoryCacheOptions());
        private readonly MemoryCacheEntryOptions _fileScanCacheEntryOptions = new MemoryCacheEntryOptions()
        .SetSlidingExpiration(TimeSpan.FromMinutes(5));

        public KernelService(IYaraEngine yaraEngine, INotificationService notificationService)
        {
            _notificationService = notificationService;
            _yaraEngine = yaraEngine;
        }

        public void ConnectToDriverAndSubscribeForEvents()
        {
            if (_notificationReceivingRunning == true) throw new InvalidOperationException("Already running");

            using var hDevice = OpenDriverHandle();
            
            if (!DeviceIoControl(hDevice, HelloIoctlCode, Array.Empty<byte>(), 0,
                Array.Empty<byte>(), 0, out var _, IntPtr.Zero))
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());

            _hipsNotifictaionDispatcherTask = Task.Run(HipsNotifictaionDispatcher)
                .ContinueWith(x => _exceptionLogger, TaskContinuationOptions.OnlyOnFaulted);
            _oasNotifictaionDispatcherTask = Task.Run(OasNotifictaionDispatcher)
                .ContinueWith(x => _exceptionLogger, TaskContinuationOptions.OnlyOnFaulted);
            _SelfDefenceNotifictaionDispatcherTask = Task.Run(SelfDefenceNotifictaionDispatcher)
                .ContinueWith(x => _exceptionLogger, TaskContinuationOptions.OnlyOnFaulted);
            //_backgroundProcessScannerTask = Task.Run(BackgroundProcessScanner)
            //    .ContinueWith(x => _exceptionLogger, TaskContinuationOptions.OnlyOnFaulted);
            _notificationReceivingRunning = true;
        }

        private async Task BackgroundProcessScanner()
        {
            var cts = _backgroundScannerTaskCts;
            while (!cts.IsCancellationRequested)
            {
                var allProcesses = Process.GetProcesses();
                var scannableProcesses = Process.GetProcesses()
                    .Where(x => x.Id != Process.GetCurrentProcess().Id)
                    .Where(x => IsProcessMemoryAccessible(x.Id));

                _logger.Debug($"Processes total count: {allProcesses.Count()}");
                _logger.Debug($"Processes scannable count: {scannableProcesses.Count()}");
                foreach(var process in scannableProcesses)
                {
                    if (cts.IsCancellationRequested)
                        break;
                    try
                    {
                        ScanProcess(process);
                    }
                    catch (Exception ex)
                    {
                        _logger.Error($"Unable to scan process {process.ProcessName}({process.Id}): {ex}");
                    }
                    await Task.Delay(TimeSpan.FromMilliseconds(200));
                }

                await Task.Delay(TimeSpan.FromSeconds(1));
            }
        }

        private void ScanProcessByPid(int pid)
        {
            try
            {
                ScanProcess(Process.GetProcessById(pid));
            }
            catch (Exception ex)
            {
                _logger.Warn($"Unable to scan process by id {pid}: {ex}");
            }
        }

        private void ScanProcess(Process process)
        {
            try
            {
                var results = _yaraEngine.ScanProcess(process.Id);
                if (results.Any())
                {
                    _logger.Debug($"Detected malware by background scanner in proccess {process.ProcessName}({process.Id})");
                    var filePath = process.MainModule.FileName;
                    process.Kill();
                    Task.Run(() => TryToDeleteFileAsync(filePath, true)
                        .ContinueWith(x => _exceptionLogger, TaskContinuationOptions.OnlyOnFaulted));
                    _notificationService.ShowMemoryScannerDetectNotification(process.Id, process.ProcessName, filePath,
                        results.First().MatchingRule.Identifier);
                }
            }
            catch (Exception ex)
            {
                _logger.Error($"Unable to scan process {process.ProcessName}({process.Id}): {ex}");
            }
        }

        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_WM_READ = 0x0010;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern SafeProcessHandle OpenProcess(int dwDesiredAccess,
               bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(SafeProcessHandle hProcess,
      int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);
        private bool IsProcessMemoryAccessible(int pid)
        {
            try
            {
                var processHandle = OpenProcess(PROCESS_WM_READ, false, pid);
                var baseAddr = Process.GetProcessById(pid).MainModule.BaseAddress;
                int bytesRead = 0;
                byte[] buffer = new byte[1];
                var isSuccess = ReadProcessMemory(processHandle, (int)baseAddr, buffer, buffer.Length, ref bytesRead);
                return true;
            }
            catch (Exception ex)
            {
                _logger.Warn("Unable to open and read process memory: " + ex);
                return false;
            }
        }

        public void EndReceiveNotifications()
        {
            _kernelNotificationsTaskCts.Cancel();
            _backgroundScannerTaskCts.Cancel();
            _notificationReceivingRunning = false;
        }

        private async Task CommonNotificationDispatcher<TRequestType>(uint ctlCode, Func<TRequestType, Task> hotifyHandler)
            where TRequestType : struct
        {
            _logger.Debug("Starting notification dispatcher for {0}", typeof(TRequestType).Name);
            using var hDevice = OpenDriverHandle();
            var cts = _kernelNotificationsTaskCts;

            uint bytesRead = 0;
            byte[] buffer = new byte[4096];

            while (!cts.IsCancellationRequested)
            {
                _logger.Debug("Waiting for notify of type {0}...", typeof(TRequestType).Name);
                if (!DeviceIoControl(hDevice, ctlCode, Array.Empty<byte>(), 0,
                buffer, buffer.Length, out bytesRead, IntPtr.Zero))
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());

                _logger.Debug($"Reveived raw notify of type {typeof(TRequestType).Name}: {BitConverter.ToString(buffer, 0, (int)bytesRead)}");

                var request = buffer.CastToStruct<TRequestType>();
                hotifyHandler(request).ContinueWith(x => _exceptionLogger, TaskContinuationOptions.OnlyOnFaulted);
            }
        }
        private Task HipsNotifictaionDispatcher()
        {
            return CommonNotificationDispatcher(WaitForHipsRequestIoctlCode, (HipsRequest req) => HandleHipsRequest(req));
        }

        private Task OasNotifictaionDispatcher()
        {

            return CommonNotificationDispatcher(WaitForOasRequestIoctlCode, (OasRequest req) => HandleOasRequest(req));
        }

        private Task SelfDefenceNotifictaionDispatcher()
        {

            return CommonNotificationDispatcher(WaitForSelfDefenceRequestIoctlCode, (SelfDefenceRequest req) => HandleSelfDefenceRequest(req));
        }

        private async Task HandleHipsRequest(HipsRequest hipsRequest)
        {
            _logger.Debug("Got hips nofify! " + hipsRequest.ToString());
            var response = new HipsResponse
            {
                SessionId = hipsRequest.SessionId,
                Verdict = Verdict.Allow
            };

            if (!HipsStatus)
            {
                _logger.Debug("hips is disabled. ignoring request");
                SendHipsResponse(response);
                return;
            }
            var normalizedFilePath = NormalizePath(hipsRequest.ObjectPath);

            if (normalizedFilePath.EndsWith("calc.exe"))
            {
                _logger.Debug("calc.exe is blocked");
                response.Verdict = Verdict.Block;
                SendHipsResponse(response);
                return;
            }

            if (!IsFileAccessible(normalizedFilePath))
            {
                _logger.Debug($"Hips: {normalizedFilePath} is not accessible!!!. ignoring request");
                SendHipsResponse(response);
                return;
            }
            await Task.Yield();
            var scanResults = _yaraEngine.ScanFile(normalizedFilePath, out var isCacheMiss);
            response.Verdict = scanResults.Any() ? Verdict.Block : Verdict.Allow;

            if (response.Verdict == Verdict.Block)
            {
                Task.Run(() => TryToDeleteFileAsync(normalizedFilePath, true)
                    .ContinueWith(x => _exceptionLogger, TaskContinuationOptions.OnlyOnFaulted));

                _logger.Debug($"Malware file {normalizedFilePath} post to delete, rule: {scanResults.First().MatchingRule.Identifier}");

                _notificationService.ShowHipsDetectNotification(
                        (int)hipsRequest.CallerPid,
                        Process.GetProcessById((int)hipsRequest.CallerPid).ProcessName,
                        normalizedFilePath,
                        scanResults.First().MatchingRule.Identifier);
            }
            else
            {
                Task.Run(async () =>
                {
                    await Task.Delay(TimeSpan.FromSeconds(2));
                    _logger.Debug($"Performing demand scan of process {hipsRequest.CalleePid} requested by hips...");
                    ScanProcessByPid((int)hipsRequest.CalleePid);
                    await Task.Delay(TimeSpan.FromSeconds(6));
                    _logger.Debug($"Performing demand scan 2 of process {hipsRequest.CalleePid} requested by hips...");
                    ScanProcessByPid((int)hipsRequest.CalleePid);
                });
            }
            SendHipsResponse(response);
        }

        private ConcurrentDictionary<int, bool> _scannedProcessesOnDllLoad = new();
        private async Task HandleOasRequest(OasRequest oasRequest)
        {
            _logger.Debug("Got oas nofify! " + oasRequest.ToString());

            var response = new OasResponse
            {
                SessionId = oasRequest.SessionId,
                Verdict = Verdict.Allow
            };

            if (!OasStatus)
            {
                _logger.Debug("oas is disabled. ignoring request");
                SendOasResponse(response);
                return;
            }
            
            if (!oasRequest.ObjectPath.Contains(":"))
            {
                _logger.Debug($"{oasRequest.ObjectPath} is not a regular file. ignoring request");
                SendOasResponse(response);
                return;
            }
            var normalizedFilePath = NormalizePath(oasRequest.ObjectPath);

            //Если какой-то процесс пытается что-то сделать с файлом в папке с антивирусом, то
            //выносим запрещающий вердикт
            if (normalizedFilePath.StartsWith(Path.GetDirectoryName(Environment.ProcessPath))
                && Path.GetExtension(normalizedFilePath) != ".txt")
            {
                _logger.Debug("Attempt to access gui service folder, access denied");
                response.Verdict = Verdict.Block;

                if(normalizedFilePath == Environment.ProcessPath)
                {
                    _notificationService.ShowSelfDefenceNotification(
                        (int)oasRequest.CallerPid, Process.GetProcessById((int)oasRequest.CallerPid).ProcessName,
                        "Доступ к папке или файлам антивируса");

                    //Task.Run(() => _notificationService.ShowSelfDefenceNotification(
                    //        (int)request.CallerPid, Process.GetProcessById((int)request.CallerPid).ProcessName,
                    //        request.SelfDefenceEvent.ToString() + " с привилегиями TerminateProcess"));
                }

                SendOasResponse(response);
                return;
            }

            //Если какой-то процесс пытается работать с неисполняемым файлом,
            //выносим одобрительный вердикт, т.к нас интересуют только
            //исполняемые файлы. К тому же, это позволяет разгрузить операционную систему,
            //избегая сканирования всего подряд

            if (Path.GetExtension(normalizedFilePath).ToLower() != ".exe" 
                && Path.GetExtension(normalizedFilePath).ToLower() != ".dll")
            {
                _logger.Debug($"Oas: {normalizedFilePath} is not an executable. ignoring request");
                response.Verdict = Verdict.Allow;
                SendOasResponse(response);
                return;
            }

            //Если какой-то процесс пытается обратиться к файлу, которого нет - одобряем запрос
            if (!File.Exists(normalizedFilePath))
            {
                _logger.Debug($"{normalizedFilePath} is not exists. ignoring request");
                response.Verdict = Verdict.Allow;
                SendOasResponse(response);
                return;
            }

            if (!IsFileAccessible(normalizedFilePath))
            {
                _logger.Debug($"{normalizedFilePath} is not accessible!!!. ignoring request");
                SendOasResponse(response);
                return;
            }

            // Передаем управление в пул потоков, что бы разгрузить поток обработки событий 
            await Task.Yield();

            //Если данный запрос является попыткой какого-то процесса загрузить библиотеку,
            //выполняем эвристическое сканирование процесса.
            ScanCallerProcessIfFirstDllLoad((int)oasRequest.CallerPid, normalizedFilePath);

            //Сканируем сам файл через движок yara
            var scanResults = _yaraEngine.ScanFile(normalizedFilePath, out var isCacheMiss);
            response.Verdict = scanResults.Any() ? Verdict.Block : Verdict.Allow;

            //Если при сканировании обнаружены совпадения с сигнатурами вредоносных объектов, 
            //Убиваем процессы файла, удаляем его, и показываем уведомление пользователю
            if (response.Verdict == Verdict.Block)
            {
                TryToKillProcessByFilePath(normalizedFilePath);
                TryToDeleteFile(normalizedFilePath);

                _logger.Debug($"Malware file {normalizedFilePath} deleted, rule: " +
                    $"{scanResults.First().MatchingRule.Identifier}");

                _notificationService.ShowOasDetectNotification(
                    (int)oasRequest.CallerPid,
                    Process.GetProcessById((int)oasRequest.CallerPid).ProcessName,
                    normalizedFilePath,
                    scanResults.First().MatchingRule.Identifier);
            }

            SendOasResponse(response);
        }

        private void ScanCallerProcessIfFirstDllLoad(int callerPid, string filePath)
        {
            if (_scannedProcessesOnDllLoad.ContainsKey(callerPid))
                return;

            if (Path.GetExtension(filePath).ToLower() != ".dll")
                return;

            _logger.Debug($"Scanning process {callerPid} on first dll {filePath} load...");
            ScanProcessByPid(callerPid);
            _scannedProcessesOnDllLoad.TryAdd(callerPid, true);
        }

        private bool IsFileAccessible(string filePath)
        {
            try
            {
                using var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                fs.ReadByte();
                return true;
            }
            catch (Exception ex)
            {
                _logger.Debug($"Unable to check file {filePath} accessability: {ex}");
                return false;
            }
        }
        
        private string NormalizePath(string path) => path.Replace("\\??\\", "");

        private void TryToKillProcessByFilePath(string filePath)
        {
            var processes = Process.GetProcesses();
            foreach (var process in processes)
            {
                try
                {
                    if (process?.MainModule?.FileName == filePath)
                    {
                        process?.Kill();
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Error while trying to kill process");
                }
            }
        }

        private bool TryToDeleteFile(string filePath)
        {
            try
            {
                File.Delete(filePath);
                return true;
            }
            catch (Exception e)
            {
                _logger.Error(e, $"Error while trying to delete file {filePath}");
                return false;
            }
        }

        private async Task TryToDeleteFileAsync(string filePath, bool retryDeleteIfFailed = false)
        {
            int tries = 0;
            bool isDeleted = false;
            do
            {
                isDeleted = TryToDeleteFile(filePath);
                tries++;
                if (retryDeleteIfFailed && !isDeleted)
                {
                    _logger.Warn($"Error while trying to delete file {filePath}, try {tries}");
                    await Task.Delay(500);
                }
            } while (retryDeleteIfFailed && !isDeleted && tries < 10);
        }
        

        private async Task HandleSelfDefenceRequest(SelfDefenceRequest request)
        {
            _logger.Debug("Got self defence nofify! " + request.ToString());
            
            var response = new SelfDefenceResponse
            {
                SessionId = request.SessionId,
                Verdict = Verdict.Allow
            };
            
            if (!SelfDefenceStatus)
            {
                _logger.Debug("self defence is disabled. ignoring request");
                SendSelfDefenceResponse(response);
                return;
            }

            if ((int)request.CalleePid == Process.GetCurrentProcess().Id)
            {
                if (Process.GetProcessById((int)request.CallerPid).ProcessName != "svchost")
                {
                    _logger.Debug("Attempt to open gui service process handle, access denied");
                    
                    response.Verdict = Verdict.Block;
                    if ((request.DesiredAccess & 0x0001) != 0)
                    {
                        _logger.Debug($"Prevented termination of gui process from process {(int)request.CallerPid}");
                        Task.Run(() => _notificationService.ShowSelfDefenceNotification(
                            (int)request.CallerPid, Process.GetProcessById((int)request.CallerPid).ProcessName,
                            request.SelfDefenceEvent.ToString() + " с привилегиями TerminateProcess"));
                    }
                }
                else
                {
                    _logger.Debug("Allowed to open gui service for svchost");
                }
            }

            SendSelfDefenceResponse(response);
        }

        private void SendHipsResponse(HipsResponse response)
        {
            _logger.Debug("Sending hips response: " + response.ToString());
            SendCommonResponse(response, SendHipsResponseIoctlCode);
            _logger.Debug("Sent hips response: " + response.ToString());

        }

        private void SendOasResponse(OasResponse response)
        {
            _logger.Debug("Sending oas response: " + response.ToString());
            SendCommonResponse(response, SendOasResponseIoctlCode);
            _logger.Debug("Sent oas response: " + response.ToString());
        }

        private void SendSelfDefenceResponse(SelfDefenceResponse response)
        {
            _logger.Debug("Sending self defence response: " + response.ToString());
            SendCommonResponse(response, SendSelfDefenceResponseIoctlCode);
            _logger.Debug("Sent self defence response: " + response.ToString());
        }

        private void SendCommonResponse<TResponse>(TResponse response, uint ioctlCode)
            where TResponse : struct
        {
            using var hDevice = OpenDriverHandle();

            uint bytesRead = 0;
            var responseBytes = response.CastToArray();

            if (!DeviceIoControl(hDevice, ioctlCode, responseBytes, responseBytes.Length,
                Array.Empty<byte>(), 0, out bytesRead, IntPtr.Zero))
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
        }

        private SafeFileHandle OpenDriverHandle()
        {
            var hDevice = CreateFile(DeviceName, FileAccess.ReadWrite,
                FileShare.None, IntPtr.Zero, FileMode.Open, FileAttributes.Normal, IntPtr.Zero);
            if (hDevice.IsInvalid)
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            return hDevice;
        }

        private static uint CTL_CODE(uint DeviceType, uint Function, IOCTL_METHOD Method, IOCTL_ACCESS Access)
        {
            return ((DeviceType << 16) | (((uint)Access) << 14) | (Function << 2) | ((uint)Method));
        }

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool DeviceIoControl(
            SafeHandle hDevice,
            uint ioControlCode,
            [MarshalAs(UnmanagedType.LPArray)]
            [In] byte[] inBuffer,
            int ninBufferSize,
            [MarshalAs(UnmanagedType.LPArray)]
            [Out] byte[] outBuffer,
            int noutBufferSize,
            out uint bytesReturned,
            [In] IntPtr overlapped
        );

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern SafeFileHandle CreateFile(
            string lpFileName,
            [MarshalAs(UnmanagedType.U4)] FileAccess dwDesiredAccess,
            [MarshalAs(UnmanagedType.U4)] FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            [MarshalAs(UnmanagedType.U4)] FileMode dwCreationDisposition,
            [MarshalAs(UnmanagedType.U4)] FileAttributes dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(SafeHandle hObject);

        [Flags]
        enum EFileAccess : uint
        {
            //
            // Standart Section
            //

            AccessSystemSecurity = 0x1000000,   // AccessSystemAcl access type
            MaximumAllowed = 0x2000000,     // MaximumAllowed access type

            Delete = 0x10000,
            ReadControl = 0x20000,
            WriteDAC = 0x40000,
            WriteOwner = 0x80000,
            Synchronize = 0x100000,

            StandardRightsRequired = 0xF0000,
            StandardRightsRead = ReadControl,
            StandardRightsWrite = ReadControl,
            StandardRightsExecute = ReadControl,
            StandardRightsAll = 0x1F0000,
            SpecificRightsAll = 0xFFFF,

            FILE_READ_DATA = 0x0001,        // file & pipe
            FILE_LIST_DIRECTORY = 0x0001,       // directory
            FILE_WRITE_DATA = 0x0002,       // file & pipe
            FILE_ADD_FILE = 0x0002,         // directory
            FILE_APPEND_DATA = 0x0004,      // file
            FILE_ADD_SUBDIRECTORY = 0x0004,     // directory
            FILE_CREATE_PIPE_INSTANCE = 0x0004, // named pipe
            FILE_READ_EA = 0x0008,          // file & directory
            FILE_WRITE_EA = 0x0010,         // file & directory
            FILE_EXECUTE = 0x0020,          // file
            FILE_TRAVERSE = 0x0020,         // directory
            FILE_DELETE_CHILD = 0x0040,     // directory
            FILE_READ_ATTRIBUTES = 0x0080,      // all
            FILE_WRITE_ATTRIBUTES = 0x0100,     // all

            //
            // Generic Section
            //

            GenericRead = 0x80000000,
            GenericWrite = 0x40000000,
            GenericExecute = 0x20000000,
            GenericAll = 0x10000000,

            SPECIFIC_RIGHTS_ALL = 0x00FFFF,
            FILE_ALL_ACCESS =
            StandardRightsRequired |
            Synchronize |
            0x1FF,

            FILE_GENERIC_READ =
            StandardRightsRead |
            FILE_READ_DATA |
            FILE_READ_ATTRIBUTES |
            FILE_READ_EA |
            Synchronize,

            FILE_GENERIC_WRITE =
            StandardRightsWrite |
            FILE_WRITE_DATA |
            FILE_WRITE_ATTRIBUTES |
            FILE_WRITE_EA |
            FILE_APPEND_DATA |
            Synchronize,

            FILE_GENERIC_EXECUTE =
            StandardRightsExecute |
              FILE_READ_ATTRIBUTES |
              FILE_EXECUTE |
              Synchronize
        }

        [Flags]
        public enum EFileShare : uint
        {
            /// <summary>
            ///
            /// </summary>
            None = 0x00000000,
            /// <summary>
            /// Enables subsequent open operations on an object to request read access.
            /// Otherwise, other processes cannot open the object if they request read access.
            /// If this flag is not specified, but the object has been opened for read access, the function fails.
            /// </summary>
            Read = 0x00000001,
            /// <summary>
            /// Enables subsequent open operations on an object to request write access.
            /// Otherwise, other processes cannot open the object if they request write access.
            /// If this flag is not specified, but the object has been opened for write access, the function fails.
            /// </summary>
            Write = 0x00000002,
            /// <summary>
            /// Enables subsequent open operations on an object to request delete access.
            /// Otherwise, other processes cannot open the object if they request delete access.
            /// If this flag is not specified, but the object has been opened for delete access, the function fails.
            /// </summary>
            Delete = 0x00000004
        }

        public enum ECreationDisposition : uint
        {
            /// <summary>
            /// Creates a new file. The function fails if a specified file exists.
            /// </summary>
            New = 1,
            /// <summary>
            /// Creates a new file, always.
            /// If a file exists, the function overwrites the file, clears the existing attributes, combines the specified file attributes,
            /// and flags with FILE_ATTRIBUTE_ARCHIVE, but does not set the security descriptor that the SECURITY_ATTRIBUTES structure specifies.
            /// </summary>
            CreateAlways = 2,
            /// <summary>
            /// Opens a file. The function fails if the file does not exist.
            /// </summary>
            OpenExisting = 3,
            /// <summary>
            /// Opens a file, always.
            /// If a file does not exist, the function creates a file as if dwCreationDisposition is CREATE_NEW.
            /// </summary>
            OpenAlways = 4,
            /// <summary>
            /// Opens a file and truncates it so that its size is 0 (zero) bytes. The function fails if the file does not exist.
            /// The calling process must open the file with the GENERIC_WRITE access right.
            /// </summary>
            TruncateExisting = 5
        }

        [Flags]
        public enum EFileAttributes : uint
        {
            Readonly = 0x00000001,
            Hidden = 0x00000002,
            System = 0x00000004,
            Directory = 0x00000010,
            Archive = 0x00000020,
            Device = 0x00000040,
            Normal = 0x00000080,
            Temporary = 0x00000100,
            SparseFile = 0x00000200,
            ReparsePoint = 0x00000400,
            Compressed = 0x00000800,
            Offline = 0x00001000,
            NotContentIndexed = 0x00002000,
            Encrypted = 0x00004000,
            Write_Through = 0x80000000,
            Overlapped = 0x40000000,
            NoBuffering = 0x20000000,
            RandomAccess = 0x10000000,
            SequentialScan = 0x08000000,
            DeleteOnClose = 0x04000000,
            BackupSemantics = 0x02000000,
            PosixSemantics = 0x01000000,
            OpenReparsePoint = 0x00200000,
            OpenNoRecall = 0x00100000,
            FirstPipeInstance = 0x00080000
        }

    }
}
