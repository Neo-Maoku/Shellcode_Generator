#include <windows.h>
#include <stdio.h>

int main()
{
	system("cl.exe /c /GS- BOF.c /FoBOF.obj");

	HANDLE hFile = CreateFile("BOF.obj", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile error.\n");
		return 0;
	}
	int file_size = 0;
	file_size = GetFileSize(hFile, NULL);
	char *buff;
	buff = (char*)malloc(file_size);
	DWORD dwRead;
	if (!ReadFile(hFile, buff, file_size, &dwRead, NULL))
	{
		CloseHandle(hFile);
		printf("ReadFile error.\n");
		return 0;
	}
	CloseHandle(hFile);

	//COFF文件头
	PIMAGE_FILE_HEADER PECOFF_FileHeader = (PIMAGE_FILE_HEADER)buff;

	//符号表
	PIMAGE_SYMBOL PECOFF_SYMBOL = (PIMAGE_SYMBOL)(buff + PECOFF_FileHeader->PointerToSymbolTable);
	PIMAGE_SYMBOL* PECOFF_SYMBOL_arr = (PIMAGE_SYMBOL*)malloc(PECOFF_FileHeader->NumberOfSymbols * sizeof(PIMAGE_SYMBOL));
	memset(PECOFF_SYMBOL_arr, 0, PECOFF_FileHeader->NumberOfSymbols * sizeof(PIMAGE_SYMBOL));

	WORD SectionNumber;
	DWORD chkstkRVA;
	DWORD memcpyRVA;
	DWORD memsetRVA;

	for (int i = 0; i <= PECOFF_FileHeader->NumberOfSymbols - 1; i++)
	{
		PECOFF_SYMBOL_arr[i] = PECOFF_SYMBOL;
		if (PECOFF_SYMBOL->SectionNumber != 0)
		{
			if (strcmp((const char*)(PECOFF_SYMBOL->N.ShortName), "_memcpy") == 0)
			{
				SectionNumber = PECOFF_SYMBOL->SectionNumber;
				memcpyRVA = PECOFF_SYMBOL->Value;
			}
			else if (strcmp((const char*)(PECOFF_SYMBOL->N.ShortName), "_chkstk") == 0)
			{
				SectionNumber = PECOFF_SYMBOL->SectionNumber;
				chkstkRVA = PECOFF_SYMBOL->Value;
			}
			else if (strcmp((const char*)(PECOFF_SYMBOL->N.ShortName), "_memset") == 0)
			{
				SectionNumber = PECOFF_SYMBOL->SectionNumber;
				memsetRVA = PECOFF_SYMBOL->Value;
			}
		}
		else if (PECOFF_SYMBOL->SectionNumber == 0)
		{
			if (strcmp((const char*)(PECOFF_SYMBOL->N.ShortName), "_memcpy") == 0)
			{
				PECOFF_SYMBOL->Value = memcpyRVA;
				PECOFF_SYMBOL->SectionNumber = SectionNumber;
			}
			else if (strcmp((const char*)(PECOFF_SYMBOL->N.ShortName), "__chkstk") == 0)
			{
				PECOFF_SYMBOL->Value = chkstkRVA;
				PECOFF_SYMBOL->SectionNumber = SectionNumber;
				PECOFF_SYMBOL->N.ShortName[7] = '\0';
			}
			else if (strcmp((const char*)(PECOFF_SYMBOL->N.ShortName), "_memset") == 0)
			{
				PECOFF_SYMBOL->Value = memsetRVA;
				PECOFF_SYMBOL->SectionNumber = SectionNumber;
			}
		}
		PECOFF_SYMBOL++;
	}

	hFile = CreateFile("BOF.obj", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile error.\n");
		return 0;
	}

	BOOL result = WriteFile(hFile, buff, dwRead, &dwRead, NULL);
	if (!result) {
		printf("WriteFile error\n");
	}
	CloseHandle(hFile);

	return 0;
}