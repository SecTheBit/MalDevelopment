# include <stdio.h>
# include <windows.h>
# include <intrin.h>
# include <winternl.h>
PEB * getPIB(){ // for getting pointer to PEB, we first have to get hold of TEB(thread environment block), now 30 offset from there we can access pointer to pEB in TEB structure
 #ifdef _WIN64
    PEB * pebs = (PEB *) __readgsqword(0x60); // if compiling for x64, then PEB will be at 60 offset from beginning
 #else  // https://learn.microsoft.com/en-us/cpp/intrinsics/readfsbyte-readfsdword-readfsqword-readfsword?view=msvc-170
    PEB * pebs = (PEB *)__INTRINSIC_SPECIAL___readfsdword(0x30);
 #endif
    return pebs;

}
void ParsePEB(){
    PEB * rva_peb= getPIB();
    PEB * environment_block=(PEB *)rva_peb;
    PEB_LDR_DATA *ldr_data = environment_block->Ldr; // getting access to Ldr 
    LIST_ENTRY *Modulelist = &ldr_data->InMemoryOrderModuleList; // head of the doubly linked list
    LIST_ENTRY *tmp=Modulelist->Flink; //assigning addrreess of first structure in linked list to tmp variable
    for(tmp;tmp!=Modulelist;tmp=tmp->Flink){ //looping thorugh doubly linked list to get the address and names
        LDR_DATA_TABLE_ENTRY *iData=(LDR_DATA_TABLE_ENTRY *)tmp;
        wprintf(L"%ls,%p\n", iData->FullDllName.Buffer,iData->DllBase);    

    }
    

    
}



int main(){
   // OpenProcess(PROCESS_ALL_ACCESS,FALSE,GetCurrentProcess());
    ParsePEB();


}