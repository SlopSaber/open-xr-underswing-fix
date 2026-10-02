using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OpenXRUnderswingFix {
    internal static class UnityOpenXRPosePredictionPatch {
        private const uint PageExecuteReadWrite = 0x40;
        private const uint ThreadSuspendResume = 0x0002;
        private const long NanosecondsPerSecond = 1_000_000_000;

        private static readonly object Sync = new object();

        private static readonly byte[] PoseTimesSignature = {
            0x49, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0x7F, 0x48, 0x89, 0x51, 0x20, 0x4D, 0x3B,
            0xC1, 0x4A, 0x8D, 0x04, 0x02, 0x48, 0x0F, 0x44,
            0xC2, 0x48, 0x89, 0x41, 0x28, 0xC3
        };

        private static Timer retryTimer;
        private static Timer refreshTimer;
        private static IntPtr patchAddress;
        private static long displayPeriod;
        private static bool isSteamVr;
        private static DisplayRefreshRateTracker refreshRateTracker;
        private static Task<ScanResult> scanTask;
        private static int scanRevision;
        private static int revision;
        private static int queuedRetryRevision = -1;
        private static int queuedRefreshRevision = -1;
        private static bool enabled;

        private sealed class ScanRequest {
            internal readonly int ProcessId;
            internal readonly IntPtr ModuleBase;
            internal readonly string RuntimeName;
            internal readonly byte[] Signature;

            internal ScanRequest(int processId, IntPtr moduleBase, string runtimeName) {
                ProcessId = processId;
                ModuleBase = moduleBase;
                RuntimeName = runtimeName;
                Signature = (byte[])PoseTimesSignature.Clone();
            }
        }

        private sealed class ScanResult {
            internal readonly ScanRequest Request;
            internal readonly string ModulePath;
            internal readonly int ModuleSize;
            internal readonly int Offset;
            internal readonly int Matches;
            internal readonly Exception Error;

            internal ScanResult(ScanRequest request, string modulePath = null,
                int moduleSize = 0, int offset = -1, int matches = 0, Exception error = null) {
                Request = request;
                ModulePath = modulePath;
                ModuleSize = moduleSize;
                Offset = offset;
                Matches = matches;
                Error = error;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ModuleInfo {
            internal IntPtr BaseOfDll;
            internal uint SizeOfImage;
            internal IntPtr EntryPoint;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetModuleHandleEx(uint flags, string moduleName, out IntPtr module);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetModuleFileName(IntPtr module, StringBuilder path, uint size);

        [DllImport("kernel32.dll")]
        private static extern bool FreeLibrary(IntPtr module);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentProcessId();

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool GetModuleInformation(
            IntPtr process, IntPtr module, out ModuleInfo information, uint size);

        [DllImport("UnityOpenXR", EntryPoint = "NativeConfig_GetRuntimeName")]
        private static extern bool GetRuntimeName(out IntPtr runtimeName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(
            IntPtr process,
            IntPtr baseAddress,
            byte[] buffer,
            int size,
            IntPtr bytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(
            IntPtr address,
            UIntPtr size,
            uint newProtection,
            out uint oldProtection);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FlushInstructionCache(
            IntPtr process,
            IntPtr address,
            UIntPtr size);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(
            uint desiredAccess,
            bool inheritHandle,
            uint threadId);

        [DllImport("kernel32.dll")]
        private static extern uint SuspendThread(IntPtr thread);

        [DllImport("kernel32.dll")]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        internal static void Enable() {
            lock (Sync) {
                if (enabled) {
                    return;
                }

                enabled = true;
                revision++;
                if (!TryApply()) {
                    retryTimer = new Timer(Retry, null, 250, 250);
                }
            }
        }

        internal static void Disable() {
            lock (Sync) {
                enabled = false;
                revision++;
                refreshTimer?.Dispose();
                refreshTimer = null;
                refreshRateTracker = null;
                retryTimer?.Dispose();
                retryTimer = null;

                if (patchAddress == IntPtr.Zero) {
                    displayPeriod = 0;
                    isSteamVr = false;
                    return;
                }

                try {
                    using Process process = Process.GetCurrentProcess();
                    WriteBytes(process, patchAddress, PoseTimesSignature);
                    patchAddress = IntPtr.Zero;
                    displayPeriod = 0;
                    isSteamVr = false;
                } catch (Exception ex) {
                    Plugin.Log.Warn($"restore failed: {ex.Message}");
                }
            }
        }

        private static void Retry(object _) {
            int currentRevision;
            lock (Sync) {
                currentRevision = revision;
                if (!enabled || retryTimer == null || queuedRetryRevision == currentRevision) {
                    return;
                }

                queuedRetryRevision = currentRevision;
            }

            IPA.Utilities.Async.UnityMainThreadTaskScheduler.Factory.StartNew(
                () => RetryOnOwner(currentRevision));
        }

        private static void RetryOnOwner(int currentRevision) {
            lock (Sync) {
                if (queuedRetryRevision == currentRevision) {
                    queuedRetryRevision = -1;
                }

                if (!enabled || currentRevision != revision || retryTimer == null || !TryApply()) {
                    return;
                }

                retryTimer.Dispose();
                retryTimer = null;
            }
        }

        private static void QueueRefreshRateCheck(object _) {
            int currentRevision;
            lock (Sync) {
                currentRevision = revision;
                if (!enabled || refreshTimer == null || queuedRefreshRevision == currentRevision) {
                    return;
                }

                queuedRefreshRevision = currentRevision;
            }

            IPA.Utilities.Async.UnityMainThreadTaskScheduler.Factory.StartNew(
                () => UpdateDisplayPeriod(currentRevision));
        }

        private static void UpdateDisplayPeriod(int currentRevision) {
            lock (Sync) {
                if (queuedRefreshRevision == currentRevision) {
                    queuedRefreshRevision = -1;
                }

                if (!enabled || currentRevision != revision || !isSteamVr ||
                    refreshTimer == null ||
                    refreshRateTracker == null) {
                    return;
                }

                float refreshRate = GetDisplayRefreshRate();
                int trustedRefreshRate = refreshRateTracker.Observe(refreshRate);
                if (trustedRefreshRate == 0) {
                    return;
                }

                long updatedDisplayPeriod = (long)Math.Round(
                    NanosecondsPerSecond / (double)trustedRefreshRate);
                if (updatedDisplayPeriod == displayPeriod) {
                    return;
                }

                if (patchAddress == IntPtr.Zero) {
                    displayPeriod = updatedDisplayPeriod;
                    if (TryApply()) {
                        retryTimer?.Dispose();
                        retryTimer = null;
                    } else if (retryTimer == null) {
                        retryTimer = new Timer(Retry, null, 250, 250);
                    }

                    return;
                }

                try {
                    using Process process = Process.GetCurrentProcess();
                    WriteBytes(process, patchAddress, CreatePatch(updatedDisplayPeriod));
                    displayPeriod = updatedDisplayPeriod;
                    Plugin.Log.Info($"updated to {NanosecondsPerSecond / (double)displayPeriod:0.##}hz");
                } catch (Exception ex) {
                    Plugin.Log.Warn($"refresh update failed: {ex.Message}");
                }
            }
        }

        private static float GetDisplayRefreshRate() {
            return Convert.ToSingle(Type
                .GetType("UnityEngine.XR.XRDevice, UnityEngine.VRModule")
                ?.GetProperty("refreshRate")
                ?.GetValue(null));
        }

        private static bool TryApply() {
            if (patchAddress != IntPtr.Zero) {
                return true;
            }

            if (scanTask != null) {
                if (!scanTask.IsCompleted) {
                    return false;
                }

                ScanResult result = scanTask.GetAwaiter().GetResult();
                scanTask = null;
                if (scanRevision == revision) {
                    return PublishScan(result);
                }
            }

            if (!TryGetRuntimeName(out string runtimeName)) {
                return false;
            }

            isSteamVr = runtimeName.IndexOf(
                "SteamVR",
                StringComparison.OrdinalIgnoreCase) >= 0;
            if (isSteamVr && refreshTimer == null) {
                refreshRateTracker = new DisplayRefreshRateTracker();
                refreshTimer = new Timer(QueueRefreshRateCheck, null, 1000, 1000);
            }

            IntPtr moduleBase = GetModuleHandle("UnityOpenXR.dll");
            if (moduleBase == IntPtr.Zero) {
                return false;
            }

            ScanRequest request = new ScanRequest(
                unchecked((int)GetCurrentProcessId()), moduleBase, runtimeName);
            scanRevision = revision;
            scanTask = Task.Factory.StartNew(ScanModule, request, CancellationToken.None,
                TaskCreationOptions.DenyChildAttach, TaskScheduler.Default);
            return false;
        }

        private static bool TryGetRuntimeName(out string runtimeName) {
            runtimeName = null;
            try {
                if (!GetRuntimeName(out IntPtr name) || name == IntPtr.Zero) {
                    return false;
                }

                runtimeName = Marshal.PtrToStringAnsi(name);
                return !string.IsNullOrEmpty(runtimeName);
            } catch (DllNotFoundException) {
                return false;
            } catch (EntryPointNotFoundException) {
                return false;
            }
        }

        private static ScanResult ScanModule(object state) {
            ScanRequest request = (ScanRequest)state;
            try {
                using Process process = Process.GetProcessById(request.ProcessId);
                ProcessModule runtimeModule = process.Modules.Cast<ProcessModule>()
                    .FirstOrDefault(module => module.BaseAddress == request.ModuleBase && string.Equals(
                        module.ModuleName,
                        "UnityOpenXR.dll",
                        StringComparison.OrdinalIgnoreCase));

                if (runtimeModule == null) {
                    return new ScanResult(request);
                }

                byte[] moduleBytes = new byte[runtimeModule.ModuleMemorySize];
                if (!ReadProcessMemory(
                    process.Handle,
                    runtimeModule.BaseAddress,
                    moduleBytes,
                    moduleBytes.Length,
                    IntPtr.Zero)) {
                    throw new InvalidOperationException(
                        $"ReadProcessMemory failed: {Marshal.GetLastWin32Error()}");
                }

                int match = -1;
                int matches = 0;
                for (int offset = 0; offset <= moduleBytes.Length - request.Signature.Length; offset++) {
                    int index = 0;
                    while (index < request.Signature.Length &&
                        moduleBytes[offset + index] == request.Signature[index]) {
                        index++;
                    }

                    if (index == request.Signature.Length) {
                        match = offset;
                        matches++;
                    }
                }

                return new ScanResult(request, runtimeModule.FileName,
                    runtimeModule.ModuleMemorySize, match, matches);
            } catch (Exception ex) {
                return new ScanResult(request, error: ex);
            }
        }

        private static bool PublishScan(ScanResult result) {
            if (result.Error != null) {
                Plugin.Log.Warn($"patch failed: {result.Error.Message}");
                return true;
            }

            if (result.ModulePath == null || !TryGetRuntimeName(out string runtimeName)) {
                return false;
            }

            if (!string.Equals(runtimeName, result.Request.RuntimeName, StringComparison.Ordinal)) {
                return false;
            }

            if (result.Matches != 1) {
                Plugin.Log.Warn($"pattern sig matched {result.Matches} times");
                return true;
            }

            if (!GetModuleHandleEx(0, "UnityOpenXR.dll", out IntPtr module)) {
                return false;
            }

            try {
                if (module != result.Request.ModuleBase) {
                    return false;
                }

                using Process process = Process.GetCurrentProcess();
                if (!GetModuleInformation(process.Handle, module, out ModuleInfo information,
                    (uint)Marshal.SizeOf<ModuleInfo>()) ||
                    information.BaseOfDll != module || information.SizeOfImage != result.ModuleSize) {
                    return false;
                }

                StringBuilder modulePath = new StringBuilder(1024);
                uint pathLength = GetModuleFileName(module, modulePath, (uint)modulePath.Capacity);
                if (pathLength == 0 || pathLength >= modulePath.Capacity ||
                    !string.Equals(modulePath.ToString(), result.ModulePath, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }

                IntPtr address = IntPtr.Add(module, result.Offset);
                WriteBytes(
                    process,
                    address,
                    CreatePatch(isSteamVr ? displayPeriod : 0),
                    result.Request.Signature);
                patchAddress = address;

                long patchOffset = address.ToInt64() - module.ToInt64();
                string prediction = displayPeriod != 0
                    ? $"{NanosecondsPerSecond / (double)displayPeriod:0.##}hz"
                    : "render time";
                Plugin.Log.Info($"patched {runtimeName} at +0x{patchOffset:X} ({prediction})");
            } catch (Exception ex) {
                Plugin.Log.Warn($"patch failed: {ex.Message}");
            } finally {
                FreeLibrary(module);
            }

            return true;
        }

        private static byte[] CreatePatch(long fixedDisplayPeriod) {
            byte[] patch = {
                0x48, 0x89, 0x51, 0x20,
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x48, 0x01, 0xD0, 0x49, 0xFF, 0xC0,
                0x48, 0x0F, 0x48, 0xC2, 0x48, 0x89, 0x41, 0x28,
                0xC3, 0xCC
            };

            Array.Copy(BitConverter.GetBytes(fixedDisplayPeriod), 0, patch, 6, sizeof(long));
            return patch;
        }

        private static void WriteBytes(Process process, IntPtr address, byte[] bytes, byte[] expectedBytes = null) {
            UIntPtr size = new UIntPtr((uint)bytes.Length);
            byte[] currentBytes = expectedBytes != null ? new byte[expectedBytes.Length] : null;
            InvalidOperationException changedSignature = expectedBytes != null
                ? new InvalidOperationException("Native pose signature changed before publication.")
                : null;
            List<IntPtr> suspendedThreads = SuspendOtherThreads(process);
            try {
                if (expectedBytes != null) {
                    if (!ReadProcessMemory(process.Handle, address, currentBytes, currentBytes.Length, IntPtr.Zero)) {
                        throw changedSignature;
                    }

                    for (int index = 0; index < expectedBytes.Length; index++) {
                        if (currentBytes[index] != expectedBytes[index]) {
                            throw changedSignature;
                        }
                    }
                }

                if (!VirtualProtect(address, size, PageExecuteReadWrite, out uint oldProtection)) {
                    throw new InvalidOperationException(
                        $"VirtualProtect failed: {Marshal.GetLastWin32Error()}");
                }

                try {
                    Marshal.Copy(bytes, 0, address, bytes.Length);
                    if (!FlushInstructionCache(process.Handle, address, size)) {
                        throw new InvalidOperationException(
                            $"FlushInstructionCache failed: {Marshal.GetLastWin32Error()}");
                    }
                } finally {
                    if (!VirtualProtect(address, size, oldProtection, out _)) {
                        Plugin.Log.Warn($"VirtualProtect restore failed: {Marshal.GetLastWin32Error()}");
                    }
                }
            } finally {
                ResumeThreads(suspendedThreads);
            }
        }

        private static List<IntPtr> SuspendOtherThreads(Process process) {
            uint currentThread = GetCurrentThreadId();
            var suspendedThreads = new List<IntPtr>();

            foreach (ProcessThread thread in process.Threads) {
                if (thread.Id == currentThread) {
                    continue;
                }

                IntPtr handle = OpenThread(ThreadSuspendResume, false, (uint)thread.Id);
                if (handle == IntPtr.Zero) {
                    continue;
                }

                if (SuspendThread(handle) == uint.MaxValue) {
                    CloseHandle(handle);
                    continue;
                }

                suspendedThreads.Add(handle);
            }

            return suspendedThreads;
        }

        private static void ResumeThreads(IEnumerable<IntPtr> threads) {
            foreach (IntPtr thread in threads) {
                ResumeThread(thread);
                CloseHandle(thread);
            }
        }
    }
}
