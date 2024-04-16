# include <stdio.h>
# include <windows.h>
# include <string.h>

void ErrorMessagess(DWORD status){
    char buffer[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,NULL,status,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),buffer,sizeof(buffer)/sizeof(char),NULL);
    printf("[+] Error is %s \n", buffer);
}
DWORD   ParseExportTable(HMODULE hmod,LPCSTR proc_name){
    char * baseAdress= (char *)hmod;
    DWORD * proc_named= (DWORD *)proc_name;
    //printf("%p",baseAdress);
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *) baseAdress;
    char *nt_header_addr=baseAdress+dosHeader->e_lfanew;
    IMAGE_NT_HEADERS64 * nt_headers=(IMAGE_NT_HEADERS64 *)nt_header_addr;
    IMAGE_OPTIONAL_HEADER64 *optional_header=&nt_headers->OptionalHeader;
    IMAGE_DATA_DIRECTORY *data_directoryBase_Address =(IMAGE_DATA_DIRECTORY *) &optional_header->DataDirectory[0];
    IMAGE_EXPORT_DIRECTORY *export_directory = (IMAGE_EXPORT_DIRECTORY *)(data_directoryBase_Address->VirtualAddress+baseAdress);
    DWORD numberofNames=export_directory->NumberOfNames;
    //printf("no of names is %d",numberofNames);// contain number of function present in dll or module
    DWORD *exportNamePointerTable = (DWORD * )(export_directory->AddressOfNames+baseAdress) ; //contains name of all function present in module or dll
    //printf("exportnamepointertable is %d",exportNamePointerTable[0]);
    WORD * AddressOfnameOrdinals = (WORD * )(export_directory->AddressOfNameOrdinals+baseAdress);
    DWORD * AddressofFunctions = (DWORD *)(export_directory->AddressOfFunctions+baseAdress);
    //printf("hellojjiii");
    DWORD index=0;
    for (index=0;index<numberofNames;index++){
        char *TempFuncAddr = (char *)(baseAdress+ exportNamePointerTable[index]);
        if(strcmp(TempFuncAddr,proc_name)==0){
              DWORD addr_name_ordinal=AddressofFunctions[AddressOfnameOrdinals[index]];
              return addr_name_ordinal;
        }
        else{
            if((strchr(TempFuncAddr, '.')) != NULL){
                char * forwardedLibs = strdup((char *)TempFuncAddr);
                char * FunctionName= strchr(forwardedLibs,'.');
                FunctionName++;
                //printf(FunctionName);
                HMODULE hmod_frwrd_dll=LoadLibraryA(forwardedLibs);
                DWORD Frwrd_Function_addr=ParseExportTable(hmod_frwrd_dll,FunctionName);
            }

        }

    }
}

void main(){

    HMODULE hKernel32 = LoadLibrary("user32.dll");
    LPVOID addr=NULL;
    DWORD threadid;
    DWORD lpNumberOfBytesWritten;
    HANDLE th;
    HMODULE hmod= GetModuleHandleA("user32.dll");
    DWORD  messagebox_addr= ParseExportTable(hmod,"MessageBoxA");
    DWORD *hmodule_new=(DWORD *)hmod;
    uintptr_t  final_addr=(messagebox_addr+(uintptr_t )hmodule_new);
    int(*messagebBoxFunc)(HWND, LPCTSTR, LPCTSTR, UINT);
    //;
    messagebBoxFunc =(int (*)(HWND, LPCTSTR, LPCTSTR, UINT))final_addr;
    //messagebBoxFunc newptr=(messagebBoxFunc)&final_addr;
    int value=messagebBoxFunc(NULL,"helloeveryone",NULL,MB_OK) ;


}
