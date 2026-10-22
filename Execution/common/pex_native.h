#pragma once

#include <windows.h>

#include "pex_hashes.h"

/*
 * Minimal native runtime for the host tools.
 *
 * Build target: /NODEFAULTLIB with /ENTRY:NativeEntry. Nothing here relies on
 * the CRT or on static imports: module and export lookup are hash-based over
 * the PEB, and every function pointer is resolved at startup.
 */

BOOL NativeInit(VOID);
VOID NativeExit(int nCode);

int   NativeArgc(VOID);
PCSTR NativeArgv(int nIndex);
DWORD NativeHash(PCSTR szText);
BOOL  NativeHasFlag(DWORD dwFlagHash);
PCSTR NativeOptionValue(DWORD dwOptionHash);

VOID NativeWriteStdout(PCSTR pData, DWORD cbData);
VOID NativeWriteStderr(PCSTR pData, DWORD cbData);
VOID NativePrint(PCSTR szText);
VOID NativePrintChar(char ch);
VOID NativePrintHex(ULONG_PTR ulValue);
VOID NativePrintDec(DWORD dwValue);

PVOID NativeGetModuleByHash(DWORD dwNameHash);
PVOID NativeGetProcFromModule(PVOID pModule, DWORD dwNameHash);
PVOID NativeResolve(DWORD dwModuleHash, DWORD dwNameHash);

BOOL NativeReadFile(PCSTR szPath, PVOID* ppData, PDWORD pcbData);
BOOL NativeWriteFile(PCSTR szPath, const VOID* pData, DWORD cbData);
BOOL NativeFileExists(PCSTR szPath);
BOOL NativeTempPath(PCHAR szPath, DWORD cchPath);

/* Resolved kernel32 entry points used by the tools. */
extern PVOID g_pfnVirtualAlloc;
extern PVOID g_pfnVirtualFree;
extern PVOID g_pfnVirtualProtect;
extern PVOID g_pfnVirtualQuery;
extern PVOID g_pfnGetModuleHandleExA;
extern PVOID g_pfnFreeLibrary;
extern PVOID g_pfnLoadLibraryA;
extern PVOID g_pfnGetProcAddress;
extern PVOID g_pfnGetModuleHandleA;
extern PVOID g_pfnCreateFileA;
extern PVOID g_pfnCloseHandle;
extern PVOID g_pfnReadFile;
extern PVOID g_pfnWriteFile;
extern PVOID g_pfnWideCharToMultiByte;
extern PVOID g_pfnMultiByteToWideChar;
extern PVOID g_pfnGetConsoleMode;
extern PVOID g_pfnWriteConsoleW;

VOID NativeWriteText(PCSTR pData, DWORD cbData);
PCSTR NativeJoinArgsUtf8(int nStart);
