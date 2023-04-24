#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#define BUFSIZE 4096

DWORD WINAPI InstanceThread(LPVOID);
VOID GetAnswerToRequest(LPTSTR, LPTSTR, LPDWORD);

#include <stdarg.h>
void myPrintf(const char *format, ...)
{
	return;
	/*va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);*/
}

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

DWORD is64 = KEY_WOW64_32KEY;
// 向注册表中写入一个字符串值
bool RegWriteString(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName, LPCSTR lpData) {
	HKEY hSubKey;
	DWORD dwDisposition;

	// 创建或打开子键
	LONG lRes = RegCreateKeyExA(hKey, lpSubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | is64, NULL, &hSubKey, &dwDisposition);
	if (lRes != ERROR_SUCCESS) {
		return false;
	}

	// 写入字符串值
	lRes = RegSetValueExA(hSubKey, lpValueName, 0, REG_SZ, (LPBYTE)lpData, strlen(lpData) + 1);
	RegCloseKey(hSubKey);

	return (lRes == ERROR_SUCCESS);
}

// 修改注册表中的字符串值
bool RegModifyString(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName, LPCSTR lpData) {
	HKEY hSubKey;

	// 打开子键
	LONG lRes = RegOpenKeyExA(hKey, lpSubKey, 0, KEY_WRITE | is64, &hSubKey);
	if (lRes != ERROR_SUCCESS) {
		return false;
	}

	// 修改字符串值
	lRes = RegSetValueExA(hSubKey, lpValueName, 0, REG_SZ, (LPBYTE)lpData, strlen(lpData) + 1);
	RegCloseKey(hSubKey);

	return (lRes == ERROR_SUCCESS);
}

// 从注册表中查询一个字符串值
bool RegQueryString(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName, BYTE** lpData, DWORD &dwSize) {
	HKEY hSubKey;
	DWORD dwType;

	// 打开子键
	LONG lRes = RegOpenKeyExA(hKey, lpSubKey, 0, KEY_READ | is64, &hSubKey);
	if (lRes != ERROR_SUCCESS) {
		return false;
	}

	// 查询字符串值
	lRes = RegQueryValueExA(hSubKey, lpValueName, 0, &dwType, NULL, &dwSize);
	if (lRes == ERROR_SUCCESS && dwType == REG_SZ && dwSize > 0) {
		*lpData = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dwSize);
		lRes = RegQueryValueExA(hSubKey, lpValueName, 0, &dwType, *lpData, &dwSize);
		if (lRes != ERROR_SUCCESS) {
			HeapFree(GetProcessHeap(), 0, *lpData);
			RegCloseKey(hSubKey);
			return false;
		}
	}
	else
	{
		RegCloseKey(hSubKey);
		return false;
	}

	RegCloseKey(hSubKey);
	return true;
}

// 向注册表中写入二进制数据
bool RegWriteBinary(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName, const BYTE* lpData, DWORD dwSize) {
	HKEY hSubKey;
	DWORD dwDisposition;
	// 创建或打开子键
	LONG lRes = RegCreateKeyExA(hKey, lpSubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | is64, NULL, &hSubKey, &dwDisposition);
	if (lRes != ERROR_SUCCESS) {
		return false;
	}
	// 设置二进制数据
	lRes = RegSetValueExA(hSubKey, lpValueName, 0, REG_BINARY, lpData, dwSize);
	RegCloseKey(hSubKey);
	return (lRes == ERROR_SUCCESS);
}

// 修改注册表中的二进制数据
bool RegModifyBinary(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName, const BYTE* lpData, DWORD dwSize) {
	HKEY hSubKey;
	// 打开子键
	LONG lRes = RegOpenKeyExA(hKey, lpSubKey, 0, KEY_SET_VALUE | is64, &hSubKey);
	if (lRes != ERROR_SUCCESS) {
		return false;
	}
	// 修改二进制数据
	lRes = RegSetValueExA(hSubKey, lpValueName, 0, REG_BINARY, lpData, dwSize);
	RegCloseKey(hSubKey);
	return (lRes == ERROR_SUCCESS);
}

// 从注册表中查询二进制数据
bool RegQueryBinary(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName, BYTE** lpData, DWORD &dwSize) {
	HKEY hSubKey;
	DWORD dwType;
	// 打开子键
	LONG lRes = RegOpenKeyExA(hKey, lpSubKey, 0, KEY_QUERY_VALUE | is64, &hSubKey);
	if (lRes != ERROR_SUCCESS) {
		return false;
	}
	// 查询二进制数据大小
	lRes = RegQueryValueExA(hSubKey, lpValueName, 0, &dwType, NULL, &dwSize);
	if (lRes != ERROR_SUCCESS || dwType != REG_BINARY) {
		RegCloseKey(hSubKey);
		return false;
	}
	// 查询二进制数据
	*lpData = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dwSize);
	lRes = RegQueryValueExA(hSubKey, lpValueName, 0, &dwType, *lpData, &dwSize);
	if (lRes != ERROR_SUCCESS)
		HeapFree(GetProcessHeap(), 0, *lpData);
	RegCloseKey(hSubKey);
	return (lRes == ERROR_SUCCESS);
}

// 向注册表中写入DWORD数据
bool RegWriteDword(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName, DWORD value)
{
	HKEY hSubKey;
	LONG lRes = RegCreateKeyExA(hKey, lpSubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | is64, NULL, &hSubKey, NULL);
	if (lRes != ERROR_SUCCESS) {
		return false;
	}

	lRes = RegSetValueExA(hSubKey, lpValueName, 0, REG_DWORD, (BYTE*)&value, 4);
	RegCloseKey(hSubKey);

	return lRes == ERROR_SUCCESS;
}

// 修改注册表中的DWORD数据
bool RegModifyDword(HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValueName, DWORD value)
{
	HKEY hSubKey;
	LONG lRes = RegOpenKeyExA(hKey, lpSubKey, 0, KEY_SET_VALUE | is64, &hSubKey);
	if (lRes != ERROR_SUCCESS) {
		return FALSE;
	}

	lRes = RegSetValueExA(hSubKey, lpValueName, 0, REG_DWORD, (BYTE *)&value, 4);
	RegCloseKey(hSubKey);

	return lRes == ERROR_SUCCESS;
}

// 从注册表中查询DWORD数据
bool RegQueryDword(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName, PDWORD value)
{
	HKEY hSubKey;
	LONG lRes = RegOpenKeyExA(hKey, lpSubKey, 0, KEY_READ | is64, &hSubKey);
	if (lRes != ERROR_SUCCESS) {
		return false;
	}

	DWORD dataType = 0;
	DWORD dataSize = 4;
	lRes = RegQueryValueExA(hSubKey, lpValueName, 0, &dataType, (BYTE*)(value), &dataSize);
	RegCloseKey(hSubKey);

	return lRes == ERROR_SUCCESS && dataType == REG_DWORD;
}

// 从注册表中删除指定键值
bool MyRegDeleteValue(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName) {
	HKEY hSubKey;
	// 打开子键
	LONG lRes = RegOpenKeyExA(hKey, lpSubKey, 0, KEY_SET_VALUE | is64, &hSubKey);
	if (lRes != ERROR_SUCCESS) {
		return false;
	}
	// 删除二进制数据
	lRes = RegDeleteValueA(hSubKey, lpValueName);
	RegCloseKey(hSubKey);
	return (lRes == ERROR_SUCCESS);
}

// 删除指定的注册表键
bool MyRegDeleteKey(HKEY hKey, LPCSTR lpSubKey, bool recursive)
{
	// 打开指定的注册表键
	HKEY hSubKey;
	LONG lRes = RegOpenKeyExA(hKey, lpSubKey, 0, KEY_ALL_ACCESS | is64, &hSubKey);
	if (lRes != ERROR_SUCCESS) {
		return false;
	}

	// 删除指定键
	if (recursive) {
		lRes = RegDeleteTreeA(hSubKey, "");
	}
	else {
		lRes = RegDeleteKeyExA(hSubKey, "", is64, 0);
	}
	RegCloseKey(hSubKey);

	return (lRes == ERROR_SUCCESS);
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

int myItoa(int num, char* str, int base)
{
	int i = 0;
	int isNegative = 0;

	if (num == 0) {
		str[i++] = '0';
		str[i] = '\0';
		return i;
	}

	if (num < 0 && base == 10) {
		isNegative = 1;
		num = -num;
	}

	/* Process individual digits */
	while (num != 0) {
		int rem = num % base;
		str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
		num = num / base;
	}

	/* If number is negative, append '-' */
	if (isNegative) {
		str[i++] = '-';
	}

	str[i] = '\0';

	int len = i;
	i = 0;
	int j = len - 1;
	while (i < j) {
		char temp = str[i];
		str[i] = str[j];
		str[j] = temp;
		i++;
		j--;
	}
	return len;
}

void* myMemset(void* ptr, int value, int num) {
	unsigned char* p = (unsigned char*)ptr;
	unsigned char v = value;
	int i;
	for (i = 0; i < num; i++) {
		*p++ = v;
	}
	return ptr;
}

BYTE* convertCharToByte(char* charStr, int len)
{
	int vauleMap[110] = {};
	vauleMap['0'] = 0;
	vauleMap['1'] = 1;
	vauleMap['2'] = 2;
	vauleMap['3'] = 3;
	vauleMap['4'] = 4;
	vauleMap['5'] = 5;
	vauleMap['6'] = 6;
	vauleMap['7'] = 7;
	vauleMap['8'] = 8;
	vauleMap['9'] = 9;
	vauleMap['a'] = 10;
	vauleMap['b'] = 11;
	vauleMap['c'] = 12;
	vauleMap['d'] = 13;
	vauleMap['e'] = 14;
	vauleMap['f'] = 15;
	vauleMap['A'] = 10;
	vauleMap['B'] = 11;
	vauleMap['C'] = 12;
	vauleMap['D'] = 13;
	vauleMap['E'] = 14;
	vauleMap['F'] = 15;

	if (len % 2 != 0) {
		return NULL;
	}
	int byteLen = len / 2;
	BYTE* byteStr = (BYTE*)HeapAlloc(GetProcessHeap(), 0, byteLen);

	for (int i = 0; i < len; i += 2) {
		byteStr[i / 2] = (BYTE)(vauleMap[charStr[i]] * 0x10 + vauleMap[charStr[i + 1]]);
	}

	return byteStr;
}

char* convertByteToChar(BYTE* byteStr, int len)
{
	int vauleMap[20] = {};
	vauleMap[0] = '0';
	vauleMap[1] = '1';
	vauleMap[2] = '2';
	vauleMap[3] = '3';
	vauleMap[4] = '4';
	vauleMap[5] = '5';
	vauleMap[6] = '6';
	vauleMap[7] = '7';
	vauleMap[8] = '8';
	vauleMap[9] = '9';
	vauleMap[10] = 'A';
	vauleMap[11] = 'B';
	vauleMap[12] = 'C';
	vauleMap[13] = 'D';
	vauleMap[14] = 'E';
	vauleMap[15] = 'F';

	int byteLen = len * 2;
	char* charStr = (char*)HeapAlloc(GetProcessHeap(), 0, byteLen + 1);

	for (int i = 0, j = 0; i < byteLen; i += 2, j++) {
		charStr[i] = vauleMap[(byteStr[j] / 0x10)];
		charStr[i + 1] = vauleMap[(byteStr[j] % 0x10)];
	}
	charStr[byteLen] = '\0';

	return charStr;
}

DWORD convertCharToDword(char* str) {
	DWORD result = 0;
	while (*str) {
		if (*str >= '0' && *str <= '9') {
			result = result * 16 + (*str - '0');
		}
		else if (*str >= 'A' && *str <= 'F') {
			result = result * 16 + (*str - 'A' + 10);
		}
		else if (*str >= 'a' && *str <= 'f') {
			result = result * 16 + (*str - 'a' + 10);
		}
		str++;
	}
	return result;
}

void convertDwordToByte(DWORD vaule, BYTE* str) {
	for (int i = 1; i <= 4; i++)
		str[i - 1] = *(PBYTE)(PBYTE(&vaule) + (4 - i));
}

char* myStrcpy(char* dest, const char* src) {
	char* result = dest; // 记录目标字符串的起始位置
	while (*src != '\0') { // 当源字符串未结束时
		*dest = *src; // 将源字符串中的字符复制到目标字符串
		dest++; // 移动指针
		src++;
	}
	*dest = '\0'; // 在目标字符串结尾添加'\0'
	return result; // 返回目标字符串的起始位置
}

//操作数(数据类型+位数) 注册主项 注册子项 [子健名lpValueName] [写入的数据lpData] [写入的长度dwSize]
void regOperate(char* param, char* result)
{
	char* params[10];
	splitParam((char*)param, params);

	HKEY hKeyArray[] = { HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, HKEY_CURRENT_CONFIG };

	int operand = myAtoi(params[0]);
	HKEY hKey = hKeyArray[params[1][0] - '0'];
	char* lpSubKey = params[2];
	BYTE* lpData = NULL;
	char* str;
	DWORD dwSize = 0;
	bool isSuccess = false;

	if (operand >= 20)
	{
		is64 = KEY_WOW64_64KEY;
		operand -= 20;
	}
	else
		is64 = KEY_WOW64_32KEY;

	int length = myItoa(operand, result, 10);
	result[length++] = ';';
	result[length++] = ';';

	switch (operand)
	{
	case 0:
		//向注册表中写入一个字符串值
		isSuccess = RegWriteString(hKey, lpSubKey, params[3], params[4]);
		break;
	case 1:
		//修改注册表中的字符串值
		isSuccess = RegModifyString(hKey, lpSubKey, params[3], params[4]);
		break;
	case 2:
		//从注册表中查询一个字符串值
		isSuccess = RegQueryString(hKey, lpSubKey, params[3], &lpData, dwSize);
		break;
	case 3:
		//向注册表中写入二进制数据
		lpData = convertCharToByte(params[4], myAtoi(params[5]));
		isSuccess = RegWriteBinary(hKey, lpSubKey, params[3], lpData, myAtoi(params[5]) / 2);

		HeapFree(GetProcessHeap(), 0, lpData);
		break;
	case 4:
		//修改注册表中的二进制数据
		lpData = convertCharToByte(params[4], myAtoi(params[5]));
		isSuccess = RegModifyBinary(hKey, lpSubKey, params[3], lpData, myAtoi(params[5]) / 2);
		HeapFree(GetProcessHeap(), 0, lpData);
		break;
	case 5:
		//从注册表中查询二进制数据
		isSuccess = RegQueryBinary(hKey, lpSubKey, params[3], &lpData, dwSize);
		break;
	case 6:
		isSuccess = RegWriteDword(hKey, lpSubKey, params[3], convertCharToDword(params[4]));
		break;
	case 7:
		isSuccess = RegModifyDword(hKey, lpSubKey, params[3], convertCharToDword(params[4]));
		break;
	case 8:
		isSuccess = RegQueryDword(hKey, lpSubKey, params[3], &dwSize);
		break;
	case 9:
		//从注册表中删除指定键值
		isSuccess = MyRegDeleteValue(hKey, lpSubKey, params[3]);
		break;
	case 10:
		//从注册表中删除指定的键(含有子项)
		isSuccess = MyRegDeleteKey(hKey, lpSubKey, true);
		isSuccess = MyRegDeleteKey(hKey, lpSubKey, false);
		break;
	default:
		break;
	}

	if (isSuccess) {
		result[length++] = '1';
		result[length++] = ';';
		result[length++] = ';';
		myPrintf("operate is success\n");
		if (operand == 2)
		{
			myPrintf("lpData: %s dwSize: %d\n", lpData, dwSize);
			myStrcpy(result + length, (char*)lpData);
			length += (dwSize - 1);
			result[length++] = ';';
			result[length++] = ';';
			HeapFree(GetProcessHeap(), 0, lpData);
		}
		else if (operand == 5)
		{
			str = convertByteToChar(lpData, dwSize);
			myPrintf("str: %s dwSize: %d\n", str, dwSize);
			myMemcpy(result + length, str, dwSize * 2);
			length += (dwSize * 2);
			result[length++] = ';';
			result[length++] = ';';
			HeapFree(GetProcessHeap(), 0, lpData);
			HeapFree(GetProcessHeap(), 0, str);
		}
		else if (operand == 8)
		{
			myPrintf("vaule :%x\n", dwSize);
			lpData = (BYTE*)HeapAlloc(GetProcessHeap(), 0, 4);
			convertDwordToByte(dwSize, lpData);
			str = convertByteToChar(lpData, 4);
			myMemcpy(result + length, str, 8);
			length += 8;
			result[length++] = ';';
			result[length++] = ';';
			HeapFree(GetProcessHeap(), 0, lpData);
			HeapFree(GetProcessHeap(), 0, str);
		}
	}
	else {
		result[length++] = '0';
		result[length++] = ';';
		result[length++] = ';';
		myPrintf("operate is fail\n");
	}

	result[length] = '\0';

	myPrintf("result: %s\n", result);
}

extern "C" int begin(LPVOID param)
{
	BOOL   fConnected = FALSE;
	DWORD  dwThreadId = 0;
	HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL;
	LPCTSTR lpszPipename = TEXT("\\\\.\\pipe\\");
	strcat((char*)lpszPipename, (char*)param);

	// The main loop creates an instance of the named pipe and 
	// then waits for a client to connect to it. When the client 
	// connects, a thread is created to handle communications 
	// with that client, and this loop is free to wait for the
	// next client connect request. It is an infinite loop.

	for (;;)
	{
		myPrintf(("\nPipe Server: Main thread awaiting client connection on %s\n"), lpszPipename);
		hPipe = CreateNamedPipe(
			lpszPipename,             // pipe name 
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_MESSAGE |       // message type pipe 
			PIPE_READMODE_MESSAGE |   // message-read mode 
			PIPE_WAIT,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			BUFSIZE,                  // output buffer size 
			BUFSIZE,                  // input buffer size 
			0,                        // client time-out 
			NULL);                    // default security attribute 

		if (hPipe == INVALID_HANDLE_VALUE)
		{
			myPrintf(("CreateNamedPipe failed, GLE=%d.\n"), GetLastError());
			return -1;
		}

		// Wait for the client to connect; if it succeeds, 
		// the function returns a nonzero value. If the function
		// returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 

		fConnected = ConnectNamedPipe(hPipe, NULL) ?
			TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		if (fConnected)
		{
			myPrintf("Client connected, creating a processing thread.\n");

			// Create a thread for this client. 
			hThread = CreateThread(
				NULL,              // no security attribute 
				0,                 // default stack size 
				InstanceThread,    // thread proc
				(LPVOID)hPipe,    // thread parameter 
				0,                 // not suspended 
				&dwThreadId);      // returns thread ID 

			if (hThread == NULL)
			{
				myPrintf(("CreateThread failed, GLE=%d.\n"), GetLastError());
				return -1;
			}
			else CloseHandle(hThread);
		}
		else
			// The client could not connect, so close the pipe. 
			CloseHandle(hPipe);
	}

	return 0;
}

DWORD WINAPI InstanceThread(LPVOID lpvParam)
{
	HANDLE hHeap = GetProcessHeap();
	TCHAR* pchRequest = (TCHAR*)HeapAlloc(hHeap, 0, BUFSIZE * sizeof(TCHAR));
	TCHAR* pchReply = (TCHAR*)HeapAlloc(hHeap, 0, BUFSIZE * sizeof(TCHAR));

	DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
	BOOL fSuccess = FALSE;
	HANDLE hPipe = NULL;

	if (lpvParam == NULL)
	{
		myPrintf("\nERROR - Pipe Server Failure:\n");
		myPrintf("   InstanceThread got an unexpected NULL value in lpvParam.\n");
		myPrintf("   InstanceThread exitting.\n");
		if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
		if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
		return (DWORD)-1;
	}

	if (pchRequest == NULL)
	{
		myPrintf("\nERROR - Pipe Server Failure:\n");
		myPrintf("   InstanceThread got an unexpected NULL heap allocation.\n");
		myPrintf("   InstanceThread exitting.\n");
		if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
		return (DWORD)-1;
	}

	if (pchReply == NULL)
	{
		myPrintf("\nERROR - Pipe Server Failure:\n");
		myPrintf("   InstanceThread got an unexpected NULL heap allocation.\n");
		myPrintf("   InstanceThread exitting.\n");
		if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
		return (DWORD)-1;
	}

	// Print verbose messages. In production code, this should be for debugging only.
	myPrintf("InstanceThread created, receiving and processing messages.\n");

	// The thread's parameter is a handle to a pipe object instance. 

	hPipe = (HANDLE)lpvParam;

	// Loop until done reading
	while (1)
	{
		// Read client requests from the pipe. This simplistic code only allows messages
		// up to BUFSIZE characters in length.
		fSuccess = ReadFile(
			hPipe,        // handle to pipe 
			pchRequest,    // buffer to receive data 
			BUFSIZE * sizeof(TCHAR), // size of buffer 
			&cbBytesRead, // number of bytes read 
			NULL);        // not overlapped I/O 

		if (!fSuccess || cbBytesRead == 0)
		{
			if (GetLastError() == ERROR_BROKEN_PIPE)
			{
				myPrintf(("InstanceThread: client disconnected.\n"));
			}
			else
			{
				myPrintf(("InstanceThread ReadFile failed, GLE=%d.\n"), GetLastError());
			}
			break;
		}

		// Process the incoming message,cbReplyBytes的长度是加了结束符.
		GetAnswerToRequest(pchRequest, pchReply, &cbReplyBytes);
		myPrintf("pchReply: %s, cbReplyBytes:%d\n", pchReply, cbReplyBytes);
		// Write the reply to the pipe. 
		fSuccess = WriteFile(
			hPipe,        // handle to pipe 
			pchReply,     // buffer to write from 
			cbReplyBytes, // number of bytes to write 
			&cbWritten,   // number of bytes written 
			NULL);        // not overlapped I/O 

		if (!fSuccess || cbReplyBytes != cbWritten)
		{
			myPrintf(("InstanceThread WriteFile failed, GLE=%d.\n"), GetLastError());
			break;
		}
	}

	// Flush the pipe to allow the client to read the pipe's contents 
	// before disconnecting. Then disconnect the pipe, and close the 
	// handle to this pipe instance. 

	FlushFileBuffers(hPipe);
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);

	HeapFree(hHeap, 0, pchRequest);
	HeapFree(hHeap, 0, pchReply);

	myPrintf("InstanceThread exiting.\n");
	return 1;
}

VOID GetAnswerToRequest(LPTSTR pchRequest, LPTSTR pchReply, LPDWORD pchBytes)
	// This routine is a simple function to print the client request to the console
	// and populate the reply buffer with a default data string. This is where you
	// would put the actual client request processing code that runs in the con
	// of an instance thread. Keep in mind the main thread will continue to wait for
	// and receive other client connections while the instance thread is working.
{
	myPrintf(("Client Request String:\"%s\"\n"), pchRequest);
	regOperate(pchRequest, pchReply);

	// Check the outgoing message to make sure it's not too long for the buffer.
	/*if (FAILED(StringCchCopy(pchReply, BUFSIZE, ("default answer from server"))))
	{
		*pchBytes = 0;
		pchReply[0] = 0;
		myPrintf("StringCchCopy failed, no outgoing message.\n");
		return;
	}*/
	*pchBytes = (lstrlen(pchReply) + 1) * sizeof(TCHAR);
}