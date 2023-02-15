// Credits : sektor7
#include "PE_header_structs.h"
#include "myAPI.h"
#include <stdio.h>

typedef HMODULE(WINAPI* LoadLibrary_ptr)(LPCSTR lpFileName);
LoadLibrary_ptr pLoadLibraryA = NULL;



HMODULE WINAPI myGetModuleHandle(LPCWSTR sModuleName) {

	// get the offset of Process Environment Block
#ifdef _M_IX86 
	PEB* ProcEnvBlk = (PEB*)__readfsdword(0x30);
#else
	PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);
#endif

	// return base address of a calling module
	if (sModuleName == NULL)
		return (HMODULE)(ProcEnvBlk->ImageBaseAddress);

	PEB_LDR_DATA* Ldr = ProcEnvBlk->Ldr;
	LIST_ENTRY* ModuleList = NULL;

	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* pStartListEntry = ModuleList->Flink;

	for (LIST_ENTRY* pListEntry = pStartListEntry;  		// start from beginning of InMemoryOrderModuleList
		pListEntry != ModuleList;	    	// walk all list entries
		pListEntry = pListEntry->Flink) {

		// get current Data Table Entry
		LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

		// check if module is found and return its base address
		if (lstrcmpiW(pEntry->BaseDllName.Buffer, sModuleName) == 0)
			return (HMODULE)pEntry->DllBase;
	}

	// otherwise:
	return NULL;

}

FARPROC WINAPI myGetProcAddress(HMODULE hMod, char* sProcName) {

	char* pBaseAddress = (char*)hMod;

	// get pointers to main headers/structures
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddress;
	IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddress + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY* pDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddress + pDataDir->VirtualAddress);

	// resolve addresses to Export Address Table, table of function names and "table of ordinals"
	DWORD* pEAT = (DWORD*)(pBaseAddress + pExportDirAddr->AddressOfFunctions);
	DWORD* pFuncNameTbl = (DWORD*)(pBaseAddress + pExportDirAddr->AddressOfNames);
	WORD* pHintsTbl = (WORD*)(pBaseAddress + pExportDirAddr->AddressOfNameOrdinals);

	// function address we're looking for
	void* pProcAddr = NULL;

	// resolve function by ordinal
	if (((DWORD_PTR)sProcName >> 16) == 0) {
		WORD ordinal = (WORD)sProcName & 0xFFFF;	// convert to WORD
		DWORD Base = pExportDirAddr->Base;			// first ordinal number

		// check if ordinal is not out of scope
		if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
			return NULL;

		// get the function virtual address = RVA + BaseAddr
		pProcAddr = (FARPROC)(pBaseAddress + (DWORD_PTR)pEAT[ordinal - Base]);
	}
	// resolve function by name
	else {
		// parse through table of function names
		for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
			char* sTmpFuncName = (char*)pBaseAddress + (DWORD_PTR)pFuncNameTbl[i];

			if (strcmp(sProcName, sTmpFuncName) == 0) {
				// found, get the function virtual address = RVA + BaseAddr
				pProcAddr = (FARPROC)(pBaseAddress + (DWORD_PTR)pEAT[pHintsTbl[i]]);
				break;
			}
		}
	}

	// check if found VA is forwarded to external dll_name.function
	if ((char*)pProcAddr >= (char*)pExportDirAddr &&
		(char*)pProcAddr < (char*)(pExportDirAddr + pDataDir->Size)) {

		char* strForwardedDLL = _strdup((char*)pProcAddr); 	// get a copy of dll_name.function string
		if (!strForwardedDLL) return NULL;

		// get external function name
		char* strForwardedFunction = strchr(strForwardedDLL, '.');
		*strForwardedFunction = 0;					// set trailing null byte for external library name -> dll_name\x0function
		strForwardedFunction++;						// shift a pointer to the beginning of function name

		// resolve LoadLibrary function pointer, keep it as global variable
		if (pLoadLibraryA == NULL) {
			pLoadLibraryA = (LoadLibrary_ptr)myGetProcAddress(myGetModuleHandle(L"KERNEL32.DLL"), (char*)"LoadLibraryA");
			if (pLoadLibraryA == NULL) return NULL;
		}

		// load the external library
		HMODULE hFwd = pLoadLibraryA(strForwardedDLL);
		free(strForwardedDLL);							// release the allocated memory for lib.func string copy
		if (!hFwd) return NULL;

		// get the address of function the original call is forwarded to
		pProcAddr = myGetProcAddress(hFwd, strForwardedFunction);
	}

	return (FARPROC)pProcAddr;
}
