
#pragma once
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize engine - maps clean ntdll, resolves all SSNs + gadget
BOOL InitSyscallEngine(void);

// --- Custom API replacements ---

LPVOID CustomVirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

LPVOID CustomVirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

BOOL CustomWriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten
);

HANDLE CustomCreateRemoteThread(
    HANDLE  hProcess,
    LPVOID  lpStartAddress,
    LPVOID  lpParameter
);

// --- ASM indirect syscall stubs ---

extern NTSTATUS IndirectSyscall_NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

extern NTSTATUS IndirectSyscall_NtWriteVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

extern NTSTATUS IndirectSyscall_NtCreateThreadEx(
    PHANDLE        ThreadHandle,
    ACCESS_MASK    DesiredAccess,
    PVOID          ObjectAttributes,
    HANDLE         ProcessHandle,
    PVOID          StartRoutine,
    PVOID          Argument,
    ULONG          CreateFlags,
    SIZE_T         ZeroBits,
    SIZE_T         StackSize,
    SIZE_T         MaximumStackSize,
    PVOID          AttributeList
);

#ifdef __cplusplus
}
#endif
