#include <windows.h>

typedef HMODULE(WINAPI* pGetModuleHandle)(
	_In_ LPCSTR lpLibFileName
	);
pGetModuleHandle ReGetModuleHandle;

typedef HMODULE(WINAPI* pReLoadLibrary)(
	_In_ LPCSTR lpLibFileName
	);
pReLoadLibrary ReLoadLibrary;

typedef FARPROC(WINAPI *pGetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
	);
pGetProcAddress ReGetProcAddress;

DWORD GetKernel32Address() {
	DWORD dwKernel32Addr = 0;
	_asm {
		mov eax, fs: [0x30]
		mov eax, [eax + 0x0c]
		mov eax, [eax + 0x14]
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]
		mov dwKernel32Addr, eax
	}
	return  dwKernel32Addr;
}

DWORD RGetProcAddress() {
	DWORD dwAddrBase = GetKernel32Address();

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dwAddrBase;

	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + dwAddrBase);

	PIMAGE_DATA_DIRECTORY pDataDir = pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;

	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(dwAddrBase + pDataDir->VirtualAddress);

	DWORD dwFunCount = pExport->NumberOfFunctions;

	DWORD dwFunNameCount = pExport->NumberOfNames;

	PDWORD pAddrOfFun = (PDWORD)(pExport->AddressOfFunctions + dwAddrBase);

	PDWORD pAddrOfNames = (PDWORD)(pExport->AddressOfNames + dwAddrBase);

	PWORD pAddrOfOrdinals = (PWORD)(pExport->AddressOfNameOrdinals + dwAddrBase);
	for (size_t i = 0; i < dwFunCount; i++) {
		if (!pAddrOfFun[i]) {
			continue;
		}
		DWORD dwFunAddrOffset = pAddrOfFun[i];
		for (size_t j = 0; j < dwFunNameCount; j++) {
			if (pAddrOfOrdinals[j] == i) {
				DWORD dwNameOffset = pAddrOfNames[j];
				char * pFunName = (char *)(dwAddrBase + dwNameOffset);
				if (strcmp(pFunName, "GetProcAddress") == 0) {
					return dwFunAddrOffset + dwAddrBase;
				}
			}
		}
	}
}

void getAPIBaseAddr()
{
	HMODULE hKernel32 = (HMODULE)GetKernel32Address();

	ReGetProcAddress = (pGetProcAddress)RGetProcAddress();

	ReGetModuleHandle = (pGetModuleHandle)ReGetProcAddress(hKernel32, "GetModuleHandleA");

	ReLoadLibrary = (pGetModuleHandle)ReGetProcAddress(hKernel32, "LoadLibraryA");
}

__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }

void fixIatAndReloc(DWORD imageBase)
{
	DWORD relocBeginOffset = 0x99999999;
	DWORD relocEndOffset = 0x88888888;

	if (relocBeginOffset != 0x99999999)
	{
		for (DWORD i = relocBeginOffset; i <= relocEndOffset; i += 2)
		{
			(*(PDWORD)(imageBase + *(PWORD)(imageBase + i))) += imageBase;
		}
	}

	DWORD iatInfoOffset = 0x77777777;
	DWORD iatBeginOffset = 0x66666666;

	if (iatInfoOffset != 0x77777777)
	{
		getAPIBaseAddr();

		DWORD index = imageBase + iatInfoOffset;
		BYTE split;
		BOOL flag = TRUE;
		HMODULE dllBase = NULL;

		while (1)
		{
			if (flag)
			{
				char* dllName = index;
				dllBase = ReGetModuleHandle(dllName);
				if (!dllBase)
					dllBase = ReLoadLibrary(dllName);

				index += (strlen(dllName) + 1);
			}

			split = *(PBYTE)(index);


			if (split == '\x2C')
			{
				char* apiName = (char*)(index + 1);
				*(PDWORD)(imageBase + iatBeginOffset) = ReGetProcAddress(dllBase, apiName);
				iatBeginOffset += 4;
				index += (strlen(apiName) + 1) + 1;

				flag = FALSE;
			}
			else if (split == '\x3B')
			{
				index++;
				flag = TRUE;
			}
			else {
				break;
			}
		}
	}
}

void strat(LPVOID param)
{
	//这里放需要生成的shellcode代码，可以放在多个函数中，只要被引用即可。
	begin(param);//参数可带不可带，带了参数是接收远程线程创建的时给的参数
}

int main(LPVOID param)
{
	ULONG_PTR loadAddress = caller();
	DWORD imageBase = (loadAddress & 0xfffff000);

	fixIatAndReloc(imageBase);

	strat(param);
}