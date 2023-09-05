# include <windows.h>
# include <stdio.h>
# include "C:\Program Files (x86)\Windows Kits\NETFXSDK\4.8\Include\um\mscoree.h"
# include "C:\Program Files (x86)\Windows Kits\NETFXSDK\4.8\Include\um\metahost.h"


void main(){
    ICLRMetaHost  *ppInterface;
    IEnumUnknown *runtimes;
    ICLRRuntimeInfo  *runtimesArray;
    DWORD pcchBuffer;
    ICLRRuntimeHost *Runtimehost;
    LPWSTR versionString;
    ULONG fetchedItems;
    DWORD Returnvalue;
    // provides a interface to interface ICLRMetaHost which will help to enumerate the installed Runtimes
    if(CLRCreateInstance(&CLSID_CLRMetaHost,&IID_ICLRMetaHost,(LPVOID *)&ppInterface) != S_OK){
        printf("[+] Error\n");
        exit(0);
    }
    
    // enumerate the installed runtimes and return a pointer to ICRLRuntimeinfo Enumertion Interface
    if(ppInterface->lpVtbl->EnumerateInstalledRuntimes(ppInterface,&runtimes) != S_OK){
        printf("[+] Error\n");
        exit(0);
    }
    // Enumeraating through the interface // runtimes is IEnumUnknow interface which contains information about many objectss ,a.k.a enumeration interface
    while(runtimes->lpVtbl->Next(runtimes,1,(IUnknown **)&runtimesArray,(ULONG *)&fetchedItems) == S_OK){
        if(runtimesArray->lpVtbl->GetVersionString(runtimesArray,NULL,&pcchBuffer) == S_OK){
            printf("==============================================================================\n");
            versionString = (LPWSTR)malloc(sizeof(WCHAR) * pcchBuffer);
            if(runtimesArray->lpVtbl->GetVersionString(runtimesArray,versionString,&pcchBuffer) == S_OK){
            wprintf(L"[+] CLR Version is %ls\n",versionString);
            }
            break;
        }
        
    }

   //selecting the CLR Verion , the first one, thats whyhe break has been used
    BOOL Value;
    runtimesArray->lpVtbl->IsLoadable(runtimesArray,&Value);
    if(Value){
    printf("[+] CLR Version is Loadable\n");
    }
   if(runtimesArray->lpVtbl->GetInterface(runtimesArray,&CLSID_CLRRuntimeHost,&IID_ICLRRuntimeHost,(LPVOID *)&Runtimehost) == S_OK){
    printf("[+] Pointer to CLR Obtained\n");
   }
   
    if(Runtimehost->lpVtbl->Start(Runtimehost) == S_OK){   
        printf("[+] CLR Started\n");
    }
    
    HRESULT hr2=Runtimehost->lpVtbl->ExecuteInDefaultAppDomain(Runtimehost,L"C:\\Users\\h3x\\source\\repos\\ConsoleApp4\\bin\\Release\\ConsoleApp4.exe",L"ConsoleApp4.Program",L"helloworld",L"hello",&Returnvalue);
    if(hr2!=S_OK){
        printf("[+] Error\n");
        exit(0);
    }
    

}
