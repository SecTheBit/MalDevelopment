### DLL Injection

Dll Injection is a type of process Injection Technique which Inject the malicious DLL into a legit process.


### Windows API Used

- CreateToolhelp32Snapshot
- Process32First
- Process32Next
- OpenProcess
- VirtualAllocEx
- GetModuleHandle
- GetProcAddress
- WriteProcessMemory
- CreateRemoteThread
- WaitForSingleObject

### Compatibility
```
gcc (x86_64-posix-seh-rev1, Built by MinGW-Builds project) 13.1.0             
Copyright (C) 2023 Free Software Foundation, Inc. 
This is free software; see the source for copying conditions. 
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
```

### Blog

Coming Soon !!

### Working POC




https://github.com/SecTheBit/MalDevelopment/assets/46895441/acd7e8f2-3dd4-4b5c-bc3d-d0890923a108

### Challenges

- On Executing the Exe for Second Time, you have to kill the process through process Hacker.
- Process is running even after closing it.

