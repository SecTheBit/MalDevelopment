# include <stdio.h>
# include <windows.h>

void ParseExportTable(HMODULE hmod,LPCSTR proc_name){
    LONG elfanew;
    char * baseAdress= (char *)hmod;
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *) baseAdress;
    IMAGE_NT_HEADERS64 * nt_headers=(IMAGE_NT_HEADERS64 *)(dosHeader->e_lfanew + baseAdress);
    IMAGE_OPTIONAL_HEADER64 optional_header=nt_headers->OptionalHeader;
    IMAGE_DATA_DIRECTORY data_directoryBase_Address = optional_header.DataDirectory[0];
    IMAGE_EXPORT_DIRECTORY *export_directory = (IMAGE_EXPORT_DIRECTORY *)(data_directoryBase_Address.VirtualAddress+baseAdress);
    DWORD name = export_directory->Name;
    printf("name is %lu",name);



    }


int main(){
    int a=0;
    ParseExportTable(GetModuleHandle("Kernel32.dll"),"VirtualAllocEx");


}