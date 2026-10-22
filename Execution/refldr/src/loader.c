#include "loader.h"

#include "pex_native.h"
#include "pex_pe.h"

#ifndef PEX_NATIVE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "pex_file.h"
#include "pex_log.h"
#endif

/* ------------------------------------------------------------------ */
/* Host wrappers                                                       */
/* ------------------------------------------------------------------ */

#ifdef PEX_NATIVE
static BOOL ReflReadFile(PCSTR szPath, PVOID* ppData, PDWORD pcbData)
{
    return NativeReadFile(szPath, ppData, pcbData);
}

static VOID ReflReleaseFile(PVOID pData)
{
    if (pData != NULL)
    {
        ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pData, 0, MEM_RELEASE);
    }
}

static BOOL ReflFailSilent(PCHAR szError, DWORD cchError)
{
    if (szError != NULL && cchError != 0) szError[0] = 0;
    return FALSE;
}
#define ReflFail(szError, cchError, ...) ReflFailSilent(szError, cchError)
#else
static BOOL ReflReadFile(PCSTR szPath, PVOID* ppData, PDWORD pcbData)
{
    return PexFileReadAll(szPath, ppData, pcbData);
}

static VOID ReflReleaseFile(PVOID pData)
{
    free(pData);
}

static BOOL ReflFail(PCHAR szError, DWORD cchError, PCSTR szFormat, ...)
{
    va_list pArgList;

    if (szError != NULL && cchError != 0)
    {
        va_start(pArgList, szFormat);
        _vsnprintf_s(szError, cchError, _TRUNCATE, szFormat, pArgList);
        va_end(pArgList);
    }
    return FALSE;
}
#endif

static BOOL ReflHasStaticTls(PVOID pFile, DWORD cbFile)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFile;
    PIMAGE_NT_HEADERS pNt;
    DWORD             dwTlsRva;
    DWORD             dwOffset = 0;
    PIMAGE_TLS_DIRECTORY pTls;

    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pFile + pDos->e_lfanew);
    dwTlsRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (dwTlsRva == 0) return FALSE;

    if (!PexPeRvaToOffset(pFile, cbFile, dwTlsRva, &dwOffset)) return TRUE;

    pTls = (PIMAGE_TLS_DIRECTORY)((PBYTE)pFile + dwOffset);
    return (pTls->AddressOfIndex != 0);
}

/* ------------------------------------------------------------------ */
/* Load / invoke / unload                                              */
/* ------------------------------------------------------------------ */

BOOL ReflLoad(PCSTR szPath, BOOL bCorrupt, PREFL_IMAGE pImage,
              PCHAR szError, DWORD cchError)
{
    PVOID  pFile = NULL;
    DWORD  cbFile = 0;
    PBYTE  pStaging = NULL;
    DWORD  dwOldProtect = 0;
    DWORD  dwExportOffset = 0;
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PFN_REFLECTIVE_LOAD pfnLoad;
    PVOID  pBase;
    MEMORY_BASIC_INFORMATION mbi;
    HMODULE hModule = NULL;

    if (pImage == NULL) return FALSE;
    ZeroMemory(pImage, sizeof(*pImage));
    if (szError != NULL && cchError != 0) szError[0] = 0;

    if (!ReflReadFile(szPath, &pFile, &cbFile))
    {
        return ReflFail(szError, cchError, "cannot read %s", szPath);
    }
    if (!PexPeValidate(pFile, cbFile, PEX_PE_FILE))
    {
        ReflReleaseFile(pFile);
        return ReflFail(szError, cchError, "%s is not a valid AMD64 PE", szPath);
    }

    if (ReflHasStaticTls(pFile, cbFile))
    {
        ReflReleaseFile(pFile);
        return ReflFail(szError, cchError,
                        "%s uses static TLS (__declspec(thread)); unsupported",
                        szPath);
    }

    pStaging = (PBYTE)((PVOID (WINAPI*)(PVOID, SIZE_T, DWORD, DWORD))g_pfnVirtualAlloc)(
        NULL, cbFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pStaging == NULL)
    {
        ReflReleaseFile(pFile);
        return ReflFail(szError, cchError, "cannot stage %s", szPath);
    }
    CopyMemory(pStaging, pFile, cbFile);
    ReflReleaseFile(pFile);

    if (!PexPeFindExportHash(pStaging, cbFile, PEX_PE_FILE,
                             HASH_REFLECTIVELOAD, NULL, &dwExportOffset))
    {
        ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pStaging, 0, MEM_RELEASE);
        return ReflFail(szError, cchError, "%s has no ReflectiveLoad export", szPath);
    }

    if (bCorrupt)
    {
        /* Corrupt after the export is located, so the failure comes from the
         * stub's validation rather than from the host's parser. */
        pDos = (PIMAGE_DOS_HEADER)pStaging;
        pNt = (PIMAGE_NT_HEADERS)(pStaging + pDos->e_lfanew);
        pNt->OptionalHeader.SizeOfImage = 0;
    }

    if (!((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD, PDWORD))g_pfnVirtualProtect)(
            pStaging, cbFile, PAGE_EXECUTE_READ, &dwOldProtect))
    {
        ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pStaging, 0, MEM_RELEASE);
        return ReflFail(szError, cchError, "cannot make the staging buffer executable");
    }

    pfnLoad = (PFN_REFLECTIVE_LOAD)(pStaging + dwExportOffset);
    pBase = pfnLoad();

    ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pStaging, 0, MEM_RELEASE);

    if (pBase == NULL)
    {
        return ReflFail(szError, cchError, "the payload stub refused to map");
    }

    pImage->pBase = pBase;

    pDos = (PIMAGE_DOS_HEADER)pBase;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pBase + pDos->e_lfanew);
    pImage->dwSizeOfImage = pNt->OptionalHeader.SizeOfImage;
    pImage->dwEntryRva = pNt->OptionalHeader.AddressOfEntryPoint;
    pImage->cbImage = pImage->dwSizeOfImage;

    if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size >= sizeof(RUNTIME_FUNCTION))
    {
        pImage->bHasException = TRUE;
        pImage->dwExceptionRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        pImage->cbException = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    }

    if (((SIZE_T (WINAPI*)(PVOID, PMEMORY_BASIC_INFORMATION, SIZE_T))g_pfnVirtualQuery)(
            pBase, &mbi, sizeof(mbi)) != 0)
    {
        pImage->bPrivate = (mbi.Type != MEM_IMAGE);
    }

    /* A reflective image must not be discoverable through the loader list. */
    if (((BOOL (WINAPI*)(DWORD, PCSTR, HMODULE*))g_pfnGetModuleHandleExA)(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (PCSTR)pBase, &hModule))
    {
        pImage->bInLoaderList = TRUE;
        ((BOOL (WINAPI*)(HMODULE))g_pfnFreeLibrary)(hModule);
    }

    return TRUE;
}

BOOL ReflInvoke(PREFL_IMAGE pImage, PCSTR szExport, ULONG_PTR* pulValue)
{
    PVOID pFunction = NULL;

    *pulValue = 0;

    if (!PexPeFindExport(pImage->pBase, pImage->dwSizeOfImage, PEX_PE_MAPPED,
                         szExport, &pFunction, NULL))
    {
#ifndef PEX_NATIVE
        PexLog(PEX_LOG_ERROR, "export %s not found", szExport);
#endif
        return FALSE;
    }

    *pulValue = ((ULONG_PTR (WINAPI*)(VOID))pFunction)();
    return TRUE;
}

VOID ReflUnload(PREFL_IMAGE pImage)
{
    PFN_RTL_DELETE_TABLE pfnDeleteTable;
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;

    if (pImage->pBase == NULL) return;

    pDos = (PIMAGE_DOS_HEADER)pImage->pBase;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pImage->pBase + pDos->e_lfanew);

    if (pImage->dwEntryRva != 0)
    {
        BOOL (WINAPI* pfnEntry)(HMODULE, DWORD, PVOID) =
            (BOOL (WINAPI*)(HMODULE, DWORD, PVOID))((PBYTE)pImage->pBase + pImage->dwEntryRva);
        pfnEntry((HMODULE)pImage->pBase, DLL_PROCESS_DETACH, NULL);
    }

    if (pImage->bHasException)
    {
        pfnDeleteTable = (PFN_RTL_DELETE_TABLE)NativeResolve(
            HASH_NTDLL_DLL, HASH_RTLDELETEFUNCTIONTABLE);
        if (pfnDeleteTable != NULL)
        {
            pfnDeleteTable((PRUNTIME_FUNCTION)((PBYTE)pImage->pBase + pImage->dwExceptionRva));
        }
    }

    /* The image is not released here: shared-CRT per-module state can outlive
     * DLL_PROCESS_DETACH, so the address space is reclaimed at exit. */
    ZeroMemory(pImage, sizeof(*pImage));
}
