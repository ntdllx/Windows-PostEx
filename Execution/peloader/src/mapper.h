#pragma once

#include <windows.h>

#include "pex_syscall.h"

/* ---------------------------------------------------------------- */
/* Placement modes                                                   */
/* ---------------------------------------------------------------- */

typedef enum _PEL_MODE
{
    PEL_MODE_IMAGE = 0,   /* image section from the payload file (MEM_IMAGE, file attribution) */
    PEL_MODE_STOMP = 1    /* map into a loaded module's executable section (MEM_IMAGE, host attribution) */
} PEL_MODE;

typedef struct _PEL_IMAGE
{
    PVOID   pBase;
    SIZE_T  cbImage;
    DWORD   dwEntryRva;

    BOOL    bHasException;
    DWORD   dwExceptionRva;
    DWORD   cbException;

    PEL_MODE mode;

    HANDLE  hSection;
    HANDLE  hFile;
    HMODULE hHost;
} PEL_IMAGE, *PPEL_IMAGE;

/* ---------------------------------------------------------------- */
/* Mapping                                                           */
/* ---------------------------------------------------------------- */

BOOL PelMapFile(PPEX_SYSCALL pSys, PCSTR szPath, PEL_MODE mode, PCSTR szHost,
                PPEL_IMAGE pImage, PCHAR szError, DWORD cchError);

BOOL PelInvoke(PPEL_IMAGE pImage, PCSTR szExport, ULONG_PTR* pulValue);

/* Detaches the payload and drops its function table. The image itself is left
 * mapped: shared-CRT per-module state keeps pointers into it after detach. */
VOID PelRelease(PPEL_IMAGE pImage);
