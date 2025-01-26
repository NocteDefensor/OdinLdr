#include "Ntdll.h"
#include "Macros.h"
#include "Instance.h"

D_SEC(B)
DWORD djb2A(
    _In_    PBYTE   str
    )
{
	DWORD dwHash = 0x1337;
	BYTE c;

	while (c = *str++)
	{
		if (c >= 'a' && c <= 'z')
			c -= 'a' - 'A';

		dwHash = ((dwHash << 0x5) + dwHash) + c;
	}
	return dwHash;
}

D_SEC(B)
DWORD djb2W(
    _In_    LPWSTR  str
    )
{
	DWORD dwHash = 0x1337;
	WCHAR c;
	while (c = *str++)
	{
		if (c >= L'a' && c <= L'z')
			c -= L'a' - L'A';
		dwHash = ((dwHash << 0x5) + dwHash) + c;
	}
	return dwHash;
}

D_SEC(B)
PVOID xGetModuleHandle(
    _In_    DWORD   dwModuleHash
    )
{
	PTEB pTeb = (PTEB)__readgsqword(0x30);
	PPEB pPeb = pTeb->ProcessEnvironmentBlock;

	void* firstEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
	PLIST_ENTRY parser = (PLIST_ENTRY)firstEntry;

	do
	{
		PLDR_DATA_TABLE_ENTRY content = (PLDR_DATA_TABLE_ENTRY)parser;

		if (dwModuleHash == NULL)
		{
			return content->DllBase;
		}

		if (djb2W(content->BaseDllName.Buffer) == dwModuleHash)
		{
			return content->DllBase;
		}

		parser = parser->Flink;
	} while (parser->Flink != firstEntry);

	return NULL;
}

D_SEC(B)
PVOID xGetProcAddress(
    _In_    PVOID   pModuleAddr, 
    _In_    DWORD   dwProcHash
    )
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleAddr;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(U_PTR(pModuleAddr) + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY pImgExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(U_PTR(pModuleAddr) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleAddr + pImgExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleAddr + pImgExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleAddr + pImgExportDirectory->AddressOfNameOrdinals);

	for (int i = 0; i < pImgExportDirectory->NumberOfFunctions; i++)
	{
		PBYTE pczFunctionName = (PBYTE)((PBYTE)pModuleAddr + pdwAddressOfNames[i]);
		if (djb2A(pczFunctionName) == dwProcHash)
		{
			return (PVOID)((PBYTE)pModuleAddr + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]]);
		}
	}

	return NULL;
}

D_SEC(B)
VOID xMemcpy(
    _In_    PBYTE   dst, 
    _In_    PBYTE   src, 
    _In_    DWORD   size
    )
{
	while (size--)
		dst[size] = src[size];
}

D_SEC(B)
VOID xMemset(
    _In_    PBYTE   dst, 
    _In_    BYTE    c, 
    _In_    DWORD   size
    )
{
	while (size--)
		dst[size] = c;
}