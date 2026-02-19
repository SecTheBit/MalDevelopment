; indirect_syscall.asm (MASM x64)

EXTERN gSSN:DWORD
EXTERN gSyscallAddr:QWORD

.code

PUBLIC IndirectSyscall_NtAllocateVirtualMemory
IndirectSyscall_NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, gSSN
    jmp QWORD PTR [gSyscallAddr]
IndirectSyscall_NtAllocateVirtualMemory ENDP


PUBLIC IndirectSyscall_NtWriteVirtualMemory
IndirectSyscall_NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, gSSN
    jmp QWORD PTR [gSyscallAddr]
IndirectSyscall_NtWriteVirtualMemory ENDP

PUBLIC IndirectSyscall_NtCreateThreadEx
IndirectSyscall_NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, gSSN
    jmp QWORD PTR [gSyscallAddr]
IndirectSyscall_NtCreateThreadEx ENDP

END
