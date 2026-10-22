#pragma once

#include <windows.h>

/*
 * Shared reflective-loader core.
 *
 * The host copies the DLL verbatim into a staging buffer and calls the
 * ReflectiveLoad export; the payload performs mapping, relocation, imports,
 * TLS and exception registration itself.
 */

typedef struct _REFL_IMAGE
{
    PVOID pBase;
    DWORD cbImage;
    DWORD dwSizeOfImage;
    DWORD dwEntryRva;
    BOOL  bHasException;
    DWORD dwExceptionRva;
    DWORD cbException;
    BOOL  bPrivate;
    BOOL  bInLoaderList;
} REFL_IMAGE, *PREFL_IMAGE;

typedef PVOID (WINAPI* PFN_REFLECTIVE_LOAD)(VOID);
typedef BOOLEAN (NTAPI* PFN_RTL_DELETE_TABLE)(PRUNTIME_FUNCTION pTable);

BOOL ReflLoad(PCSTR szPath, BOOL bCorrupt, PREFL_IMAGE pImage,
              PCHAR szError, DWORD cchError);
BOOL ReflInvoke(PREFL_IMAGE pImage, PCSTR szExport, ULONG_PTR* pulValue);
VOID ReflUnload(PREFL_IMAGE pImage);
