#pragma once

#include <windows.h>

/*
 * Whole-file helpers shared by the tools and their test harnesses.
 * All sizes are capped at 64 MB: the inputs here are object files and test
 * markers, and an unbounded read would only hide a caller bug.
 */

#define PEX_FILE_MAX_BYTES (64u * 1024u * 1024u)

BOOL PexFileReadAll(PCSTR szPath, PVOID* ppData, DWORD* pcbData);
BOOL PexFileWriteAll(PCSTR szPath, const VOID* pData, DWORD cbData);
BOOL PexFileExists(PCSTR szPath);
BOOL PexFileEquals(PCSTR szPath, const VOID* pData, DWORD cbData);
BOOL PexPathJoin(PCHAR szOut, DWORD cchOut, PCSTR szDirectory, PCSTR szName);
