#include "beacon.h"

__declspec(naked) void    BeaconDataParse(datap * parser, char * buffer, int size) {
	__asm {
		mov al, 0x0;
		ret;
	}
};
__declspec(naked) int     BeaconDataInt(datap * parser) {
	__asm {
		mov al, 0x1;
		ret;
	}
};
__declspec(naked) short   BeaconDataShort(datap * parser) {
	__asm {
		mov al, 0x2;
		ret;
	}
};
__declspec(naked) int     BeaconDataLength(datap * parser) {
	__asm {
		mov al, 0x3;
		ret;
	}
};
__declspec(naked) char *  BeaconDataExtract(datap * parser, int * size) {
	__asm {
		mov al, 0x4;
		ret;
	}
};
__declspec(naked) void    BeaconFormatAlloc(formatp * format, int maxsz) {
	__asm {
		mov al, 0x5;
		ret;
	}
};
__declspec(naked) void    BeaconFormatReset(formatp * format) {
	__asm {
		mov al, 0x6;
		ret;
	}
};
__declspec(naked) void    BeaconFormatFree(formatp * format) {
	__asm {
		mov al, 0x7;
		ret;
	}
};
__declspec(naked) void    BeaconFormatAppend(formatp * format, char * text, int len) {
	__asm {
		mov al, 0x8;
		ret;
	}
};
__declspec(naked) void    BeaconFormatPrintf(formatp * format, char * fmt, ...) {
	__asm {
		mov al, 0x9;
		ret;
	}
};
__declspec(naked) char *  BeaconFormatToString(formatp * format, int * size) {
	__asm {
		mov al, 0xA;
		ret;
	}
};
__declspec(naked) void    BeaconFormatInt(formatp * format, int value) {
	__asm {
		mov al, 0xB;
		ret;
	}
};
__declspec(naked) void   BeaconPrintf(int type, char * fmt, ...) {
	__asm {
		mov al, 0xC;
		ret;
	}
};
__declspec(naked) void   BeaconOutput(int type, char * data, int len) {
	__asm {
		mov al, 0xD;
		ret;
	}
};
__declspec(naked) BOOL   BeaconUseToken(HANDLE token) {
	__asm {
		mov al, 0xE;
		ret;
	}
};
__declspec(naked) void   BeaconRevertToken() {
	__asm {
		mov al, 0xF;
		ret;
	}
};
__declspec(naked) BOOL   BeaconIsAdmin() {
	__asm {
		mov al, 0x10;
		ret;
	}
};
__declspec(naked) void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length) {
	__asm {
		mov al, 0x11;
		ret;
	}
};
__declspec(naked) void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len) {
	__asm {
		mov al, 0x12;
		ret;
	}
};
__declspec(naked) void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len) {
	__asm {
		mov al, 0x13;
		ret;
	}
};
__declspec(naked) void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo) {
	__asm {
		mov al, 0x14;
		ret;
	}
};
__declspec(naked) BOOL   toWideChar(char * src, wchar_t * dst, int max) {
	__asm {
		mov al, 0x15;
		ret;
	}
};