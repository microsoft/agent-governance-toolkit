# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Owned process trees: POSIX sessions and Windows kill-on-close Job Objects."""

from __future__ import annotations

import asyncio
import os
import signal


class ProcessTree:
    """Contain a worker before its stdin handshake allows any runtime work."""

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.handle = None
        if os.name != "nt":
            return
        import ctypes
        import ctypes.wintypes as wintypes

        class BasicLimit(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )]

        class ExtendedLimit(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimit),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateJobObject.restype = wintypes.BOOL
        kernel.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
        ]
        kernel.QueryInformationJobObject.restype = wintypes.BOOL
        handle = kernel.CreateJobObjectW(None, None)
        if not handle:
            raise OSError("Could not create worker containment.")
        limits = ExtendedLimit()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        process = kernel.OpenProcess(0x0100 | 0x0001, False, pid)
        try:
            if not process or not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise OSError("Could not configure worker containment.")
            if not kernel.AssignProcessToJobObject(handle, process):
                raise OSError("Could not contain worker; startup denied.")
        except OSError:
            kernel.CloseHandle(handle)
            raise
        finally:
            if process:
                kernel.CloseHandle(process)
        self.handle = handle
        self.kernel = kernel

    def kill(self) -> None:
        if self.handle is not None:
            if not self.kernel.TerminateJobObject(self.handle, 1):
                raise OSError("Could not terminate owned worker tree.")
        elif os.name != "nt":
            try:
                os.killpg(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                return

    async def wait_stopped(self) -> None:
        if self.handle is None:
            return
        import ctypes
        import ctypes.wintypes as wintypes

        class Accounting(ctypes.Structure):
            _fields_ = [("times", ctypes.c_int64 * 4), ("counts", wintypes.DWORD * 4)]

        async def wait_empty():
            while True:
                accounting = Accounting()
                if not self.kernel.QueryInformationJobObject(
                    self.handle, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None,
                ):
                    raise OSError("Could not verify worker-tree termination.")
                if accounting.counts[2] == 0:
                    return
                await asyncio.sleep(0.01)

        try:
            await asyncio.wait_for(wait_empty(), 2)
        finally:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


async def reap(process: asyncio.subprocess.Process, tree: ProcessTree | None) -> None:
    if tree is not None:
        tree.kill()
    if process.returncode is None:
        try:
            process.kill()
        except ProcessLookupError:
            # Exit can race with termination; still reap the complete owned tree below.
            pass
    async def wait_all():
        await process.wait()
        if tree is not None:
            await tree.wait_stopped()

    await asyncio.wait_for(wait_all(), timeout=2)
