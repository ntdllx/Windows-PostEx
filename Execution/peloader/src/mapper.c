#include "mapper.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "pex_file.h"
#include "pex_native.h"
#include "pex_pe.h"

#ifdef PEX_NATIVE
static BOOL PelReadFile(PCSTR szPath, PVOID* ppData, PDWORD pcbData)
{
    return NativeReadFile(szPath, ppData, pcbData);
}

static VOID PelFreeFile(PVOID pData)
{
    ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pData, 0, MEM_RELEASE);
}

static DWORD PelStrLen(PCSTR szText)
{
    DWORD cch = 0;
    while (szText[cch] != 0) cch++;
    return cch;
}
#else
static BOOL PelReadFile(PCSTR szPath, PVOID* ppData, PDWORD pcbData)
{
    return PexFileReadAll(szPath, ppData, pcbData);
}

static VOID PelFreeFile(PVOID pData)
{
    free(pData);
}

static DWORD PelStrLen(PCSTR szText)
{
    return (DWORD)lstrlenA(szText);
}
#endif

/* ---------------------------------------------------------------- */
/* ntdll loader helpers                                              */
/* ---------------------------------------------------------------- */

typedef struct _PEL_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} PEL_UNICODE_STRING, *PPEL_UNICODE_STRING;

typedef struct _PEL_ANSI_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} PEL_ANSI_STRING, *PPEL_ANSI_STRING;

typedef NTSTATUS (NTAPI* PFN_LDR_LOAD_DLL)(PWSTR pSearchPath, PULONG pFlags,
                                           PPEL_UNICODE_STRING pName, PHANDLE phModule);
typedef NTSTATUS (NTAPI* PFN_LDR_GET_PROC)(HMODULE hModule, PPEL_ANSI_STRING pName,
                                           ULONG ulOrdinal, PVOID* ppAddress);

static PFN_LDR_LOAD_DLL  g_pfnLdrLoadDll;
static PFN_LDR_GET_PROC  g_pfnLdrGetProc;

static BOOL PelInitLoader(VOID)
{
    if (g_pfnLdrLoadDll != NULL && g_pfnLdrGetProc != NULL) return TRUE;

    g_pfnLdrLoadDll = (PFN_LDR_LOAD_DLL)NativeResolve(HASH_NTDLL_DLL, HASH_LDRLOADDLL);
    g_pfnLdrGetProc = (PFN_LDR_GET_PROC)NativeResolve(HASH_NTDLL_DLL, HASH_LDRGETPROCEDUREADDRESS);

    return g_pfnLdrLoadDll != NULL && g_pfnLdrGetProc != NULL;
}

static HMODULE PelLoadDll(PCSTR szName)
{
    PEL_UNICODE_STRING usName;
    WCHAR              awchName[256];
    HANDLE             hModule = NULL;
    DWORD              i = 0;

    if (!PelInitLoader()) return NULL;

    while (szName[i] != 0 && i < 255)
    {
        awchName[i] = (WCHAR)(BYTE)szName[i];
        i++;
    }
    awchName[i] = 0;

    usName.Length = (USHORT)(i * sizeof(WCHAR));
    usName.MaximumLength = (USHORT)((i + 1) * sizeof(WCHAR));
    usName.Buffer = awchName;

    if (g_pfnLdrLoadDll(NULL, NULL, &usName, &hModule) < 0) return NULL;
    return (HMODULE)hModule;
}

static PVOID PelGetProc(HMODULE hModule, PCSTR szName)
{
    PEL_ANSI_STRING asName;
    PVOID           pAddress = NULL;

    if (!PelInitLoader()) return NULL;

    asName.Length = (USHORT)PelStrLen(szName);
    asName.MaximumLength = (USHORT)(asName.Length + 1);
    asName.Buffer = (PCHAR)szName;

    if (g_pfnLdrGetProc(hModule, &asName, 0, &pAddress) < 0) return NULL;
    return pAddress;
}

/* ---------------------------------------------------------------- */
/* Helpers                                                           */
/* ---------------------------------------------------------------- */

#ifdef PEX_NATIVE
static BOOL PexFailSilent(PCHAR szError, DWORD cchError)
{
    if (szError != NULL && cchError != 0) szError[0] = 0;
    return FALSE;
}
#define PelFail(szError, cchError, ...) PexFailSilent(szError, cchError)
#else
static BOOL PelFail(PCHAR szError, DWORD cchError, PCSTR szFormat, ...)
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

static BOOL PelHasStaticTls(PVOID pFile, DWORD cbFile)
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

static BOOL PelHasTlsCallbacks(PVOID pFile, DWORD cbFile)
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
    if (!PexPeRvaToOffset(pFile, cbFile, dwTlsRva, &dwOffset)) return FALSE;

    pTls = (PIMAGE_TLS_DIRECTORY)((PBYTE)pFile + dwOffset);
    return (pTls->AddressOfCallBacks != 0);
}

static BOOL PelMakeWritable(PPEX_SYSCALL pSys, PBYTE pBase, PIMAGE_NT_HEADERS pNt)
{
    DWORD                 dwOld = 0;
    PIMAGE_SECTION_HEADER pSection;
    WORD                  i;

    if (PexSysProtect(pSys, pBase, pNt->OptionalHeader.SizeOfImage,
                       PAGE_READWRITE, &dwOld) >= 0)
    {
        return TRUE;
    }

    pSection = IMAGE_FIRST_SECTION(pNt);
    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {
        SIZE_T cbSection = pSection[i].Misc.VirtualSize;
        if (pSection[i].SizeOfRawData > cbSection) cbSection = pSection[i].SizeOfRawData;
        if (cbSection == 0) continue;
        cbSection = (cbSection + 0xFFF) & ~(SIZE_T)0xFFF;

        if (PexSysProtect(pSys, pBase + pSection[i].VirtualAddress, cbSection,
                           PAGE_READWRITE, &dwOld) < 0)
        {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL PelCopyImage(PBYTE pBase, const BYTE* pFile, PIMAGE_NT_HEADERS pNt)
{
    PIMAGE_SECTION_HEADER pSection;
    WORD                  i;

    CopyMemory(pBase, pFile, pNt->OptionalHeader.SizeOfHeaders);

    pSection = IMAGE_FIRST_SECTION(pNt);
    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {
        if (pSection[i].SizeOfRawData == 0) continue;
        CopyMemory(pBase + pSection[i].VirtualAddress,
                   pFile + pSection[i].PointerToRawData,
                   pSection[i].SizeOfRawData);
    }
    return TRUE;
}

static BOOL PelRelocate(PBYTE pBase, PIMAGE_NT_HEADERS pNt, PCHAR szError, DWORD cchError)
{
    ULONG_PTR ulDelta = (ULONG_PTR)pBase - (ULONG_PTR)pNt->OptionalHeader.ImageBase;
    DWORD     dwRelocRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD     dwRelocSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    PIMAGE_BASE_RELOCATION pBlock;

    if (ulDelta == 0) return TRUE;
    if (dwRelocRva == 0) return TRUE;
    if (dwRelocRva >= pNt->OptionalHeader.SizeOfImage) return FALSE;

    pBlock = (PIMAGE_BASE_RELOCATION)(pBase + dwRelocRva);

    while (pBlock->VirtualAddress != 0)
    {
        DWORD cbBlock = pBlock->SizeOfBlock;
        DWORD cEntries;
        PWORD pwEntry;
        DWORD i;

        if (cbBlock < sizeof(IMAGE_BASE_RELOCATION)) return FALSE;
        if ((BYTE*)pBlock + cbBlock > pBase + dwRelocRva + dwRelocSize) return FALSE;
        if (pBlock->VirtualAddress >= pNt->OptionalHeader.SizeOfImage) return FALSE;

        cEntries = (cbBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        pwEntry = (PWORD)(pBlock + 1);

        for (i = 0; i < cEntries; i++)
        {
            WORD  wType = (WORD)((pwEntry[i] >> 12) & 0xF);
            WORD  wOffset = (WORD)(pwEntry[i] & 0xFFF);
            PBYTE pbTarget = pBase + pBlock->VirtualAddress + wOffset;

            if ((SIZE_T)(pbTarget - pBase) + sizeof(ULONGLONG) > pNt->OptionalHeader.SizeOfImage)
            {
                return PelFail(szError, cchError, "relocation target out of image");
            }

            if (wType == IMAGE_REL_BASED_DIR64)
            {
                *(PULONGLONG)pbTarget += (ULONGLONG)ulDelta;
            }
            else if (wType == IMAGE_REL_BASED_ABSOLUTE)
            {
                /* padding */
            }
            else
            {
                return PelFail(szError, cchError, "unsupported relocation type %u", wType);
            }
        }

        pBlock = (PIMAGE_BASE_RELOCATION)((PBYTE)pBlock + cbBlock);
    }

    return TRUE;
}

static BOOL PelImports(PBYTE pBase, PIMAGE_NT_HEADERS pNt, PCHAR szError, DWORD cchError)
{
    DWORD dwImportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    PIMAGE_IMPORT_DESCRIPTOR pDescriptor;

    if (dwImportRva == 0) return TRUE;
    if (dwImportRva >= pNt->OptionalHeader.SizeOfImage) return FALSE;
    if (!PelInitLoader()) return FALSE;

    pDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + dwImportRva);

    while (pDescriptor->Name != 0)
    {
        PCSTR szModule = (PCSTR)(pBase + pDescriptor->Name);
        HMODULE hModule;
        PIMAGE_THUNK_DATA pThunk;
        PIMAGE_THUNK_DATA pOriginal;
        DWORD cThunks = 0;

        if (pDescriptor->Name >= pNt->OptionalHeader.SizeOfImage) return FALSE;

        hModule = ((HMODULE (WINAPI*)(PCSTR))g_pfnGetModuleHandleA)(szModule);
        if (hModule == NULL) hModule = PelLoadDll(szModule);
        if (hModule == NULL)
        {
            return PelFail(szError, cchError, "cannot load dependency %s", szModule);
        }

        pThunk = (PIMAGE_THUNK_DATA)(pBase + pDescriptor->FirstThunk);
        pOriginal = pDescriptor->OriginalFirstThunk != 0
                        ? (PIMAGE_THUNK_DATA)(pBase + pDescriptor->OriginalFirstThunk)
                        : pThunk;

        while (pOriginal->u1.AddressOfData != 0)
        {
            PVOID pFunction = NULL;

            if (++cThunks > 65536) return FALSE;
            if ((SIZE_T)((BYTE*)pOriginal - pBase) + sizeof(IMAGE_THUNK_DATA) >
                pNt->OptionalHeader.SizeOfImage)
            {
                return FALSE;
            }

            if ((pOriginal->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
            {
                ULONG ulOrdinal = (ULONG)(pOriginal->u1.Ordinal & 0xFFFF);
                PEL_ANSI_STRING asName = { 0, 0, NULL };

                if (g_pfnLdrGetProc(hModule, &asName, ulOrdinal, &pFunction) < 0)
                {
                    return PelFail(szError, cchError, "ordinal %u not found in %s", ulOrdinal, szModule);
                }
            }
            else
            {
                PIMAGE_IMPORT_BY_NAME pName =
                    (PIMAGE_IMPORT_BY_NAME)(pBase + pOriginal->u1.AddressOfData);

                pFunction = PelGetProc(hModule, (PCSTR)pName->Name);
                if (pFunction == NULL)
                {
                    return PelFail(szError, cchError, "import %s!%s not found",
                                   szModule, (PCSTR)pName->Name);
                }
            }

            pThunk->u1.Function = (ULONG_PTR)pFunction;
            pOriginal++;
            pThunk++;
        }

        pDescriptor++;
    }

    return TRUE;
}

static BOOL PelRegisterException(PBYTE pBase, PIMAGE_NT_HEADERS pNt)
{
    typedef BOOLEAN (NTAPI* PFN_RTL_ADD_TABLE)(PRUNTIME_FUNCTION pTable, DWORD cEntries,
                                               ULONG_PTR ulBaseAddress);

    DWORD dwRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    DWORD cbSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    PFN_RTL_ADD_TABLE pfnAddTable;

    if (dwRva == 0 || cbSize < sizeof(RUNTIME_FUNCTION)) return TRUE;
    if ((SIZE_T)dwRva + cbSize > pNt->OptionalHeader.SizeOfImage) return FALSE;

    pfnAddTable = (PFN_RTL_ADD_TABLE)NativeResolve(HASH_NTDLL_DLL, HASH_RTLADDFUNCTIONTABLE);
    if (pfnAddTable == NULL) return FALSE;

    return pfnAddTable((PRUNTIME_FUNCTION)(pBase + dwRva),
                       cbSize / sizeof(RUNTIME_FUNCTION), (ULONG_PTR)pBase) != FALSE;
}

static BOOL PelProtectSections(PPEX_SYSCALL pSys, PBYTE pBase, PIMAGE_NT_HEADERS pNt,
                               PCHAR szError, DWORD cchError)
{
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    DWORD                 dwOld = 0;
    WORD                  i;

    if (PexSysProtect(pSys, pBase,
                       (pNt->OptionalHeader.SizeOfHeaders + 0xFFF) & ~(SIZE_T)0xFFF,
                       PAGE_READONLY, &dwOld) < 0)
    {
        return PelFail(szError, cchError, "cannot protect headers");
    }

    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {
        SIZE_T cbSection = pSection[i].Misc.VirtualSize;
        DWORD  flProtect;

        if (pSection[i].SizeOfRawData > cbSection) cbSection = pSection[i].SizeOfRawData;
        cbSection = (cbSection + 0xFFF) & ~(SIZE_T)0xFFF;
        if (cbSection == 0) continue;

        if ((pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
            (pSection[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0)
        {
            return PelFail(szError, cchError, "section %s is writable+executable",
                           pSection[i].Name);
        }

        if ((pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
            flProtect = PAGE_EXECUTE_READ;
        else if ((pSection[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0)
            flProtect = PAGE_READWRITE;
        else
            flProtect = PAGE_READONLY;

        if (PexSysProtect(pSys, pBase + pSection[i].VirtualAddress, cbSection,
                           flProtect, &dwOld) < 0)
        {
            return PelFail(szError, cchError, "cannot protect section %s", pSection[i].Name);
        }
    }

    return TRUE;
}

static BOOL PelFinish(PPEX_SYSCALL pSys, PPEL_IMAGE pImage, const BYTE* pFile,
                      DWORD cbFile, BOOL bLaidOut, PCHAR szError, DWORD cchError)
{
    PBYTE             pBase = (PBYTE)pImage->pBase;
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;

    (void)cbFile;

    if (bLaidOut)
    {
        pDos = (PIMAGE_DOS_HEADER)pBase;
        pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    }
    else
    {
        /* The target still holds the host's bytes; read the headers from the
         * file until the image has been copied in. */
        pDos = (PIMAGE_DOS_HEADER)pFile;
        pNt = (PIMAGE_NT_HEADERS)(pFile + pDos->e_lfanew);
    }

    if (!PelMakeWritable(pSys, pBase, pNt))
    {
        return PelFail(szError, cchError, "cannot make the image writable");
    }

    if (!bLaidOut)
    {
        ZeroMemory(pBase, pNt->OptionalHeader.SizeOfImage);
        if (!PelCopyImage(pBase, pFile, pNt))
        {
            return PelFail(szError, cchError, "cannot copy image sections");
        }

        pDos = (PIMAGE_DOS_HEADER)pBase;
        pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    }

    if (!PelRelocate(pBase, pNt, szError, cchError)) return FALSE;
    if (!PelImports(pBase, pNt, szError, cchError)) return FALSE;

    pImage->dwEntryRva = pNt->OptionalHeader.AddressOfEntryPoint;
    pImage->cbImage = pNt->OptionalHeader.SizeOfImage;

    if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size >= sizeof(RUNTIME_FUNCTION))
    {
        pImage->bHasException = TRUE;
        pImage->dwExceptionRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
        pImage->cbException = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

        if (!PelRegisterException(pBase, pNt))
        {
            return PelFail(szError, cchError, "cannot register the exception table");
        }
    }

    if (!PelProtectSections(pSys, pBase, pNt, szError, cchError)) return FALSE;

    if (pImage->dwEntryRva != 0)
    {
        BOOL (WINAPI* pfnEntry)(HMODULE, DWORD, PVOID) =
            (BOOL (WINAPI*)(HMODULE, DWORD, PVOID))(pBase + pImage->dwEntryRva);

        if (!pfnEntry((HMODULE)pBase, DLL_PROCESS_ATTACH, NULL))
        {
            return PelFail(szError, cchError, "DllMain returned FALSE");
        }
    }

    return TRUE;
}

/* ---------------------------------------------------------------- */
/* Placement                                                         */
/* ---------------------------------------------------------------- */

static BOOL PelMapImage(PPEX_SYSCALL pSys, PCSTR szPath, PPEL_IMAGE pImage,
                        PCHAR szError, DWORD cchError)
{
    HANDLE          hFile;
    SIZE_T          cbView = 0;
    PVOID           pBase = NULL;
    NTSTATUS        status;

    hFile = ((HANDLE (WINAPI*)(PCSTR, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE))g_pfnCreateFileA)(
        szPath, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return PelFail(szError, cchError, "cannot open %s", szPath);
    }

    status = PexSysCreateSection(pSys, &pImage->hSection, SECTION_ALL_ACCESS, NULL,
                                  NULL, PAGE_READONLY, SEC_IMAGE, hFile);
    if (status < 0)
    {
        ((BOOL (WINAPI*)(HANDLE))g_pfnCloseHandle)(hFile);
        return PelFail(szError, cchError, "SEC_IMAGE section creation failed (0x%08x)", status);
    }

    status = PexSysMapView(pSys, pImage->hSection, PEX_CURRENT_PROCESS,
                            &pBase, 0, 0, NULL, &cbView, 2 /* ViewUnmap */, 0, PAGE_READONLY);
    if (status < 0 || pBase == NULL)
    {
        ((BOOL (WINAPI*)(HANDLE))g_pfnCloseHandle)(pImage->hSection);
        ((BOOL (WINAPI*)(HANDLE))g_pfnCloseHandle)(hFile);
        return PelFail(szError, cchError, "image section mapping failed (0x%08x)", status);
    }

    pImage->hFile = hFile;
    pImage->pBase = pBase;
    pImage->mode = PEL_MODE_IMAGE;

    return PelFinish(pSys, pImage, NULL, 0, TRUE, szError, cchError);
}

static BOOL PelFindStompSection(PBYTE pHost, SIZE_T cbPayload, PDWORD pdwRva,
                                PCHAR szError, DWORD cchError)
{
    PIMAGE_DOS_HEADER     pDos = (PIMAGE_DOS_HEADER)pHost;
    PIMAGE_NT_HEADERS     pNt = (PIMAGE_NT_HEADERS)(pHost + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    DWORD                 dwBest = 0;
    SIZE_T                cbBest = 0;
    WORD                  i;

    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {
        SIZE_T cbSection;

        if ((pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;

        cbSection = pSection[i].Misc.VirtualSize;
        if (cbSection > cbBest)
        {
            cbBest = cbSection;
            dwBest = pSection[i].VirtualAddress;
        }
    }

    if (cbBest < cbPayload)
    {
        return PelFail(szError, cchError,
                       "host has no executable section large enough (%llu < %llu bytes)",
                       (unsigned long long)cbBest, (unsigned long long)cbPayload);
    }

    *pdwRva = dwBest;
    return TRUE;
}

static BOOL PelMapStomp(PPEX_SYSCALL pSys, PCSTR szPath, PCSTR szHost,
                        PPEL_IMAGE pImage, PCHAR szError, DWORD cchError)
{
    PVOID  pFile = NULL;
    DWORD  cbFile = 0;
    DWORD  dwSizeOfImage = 0;
    HMODULE hHost;
    DWORD  dwSectionRva = 0;
    PBYTE  pTarget;
    DWORD  dwOld = 0;

    if (!PelReadFile(szPath, &pFile, &cbFile))
    {
        return PelFail(szError, cchError, "cannot read %s", szPath);
    }

    if (!PexPeValidate(pFile, cbFile, PEX_PE_FILE) ||
        !PexPeGetSizeOfImage(pFile, cbFile, &dwSizeOfImage))
    {
        PelFreeFile(pFile);
        return PelFail(szError, cchError, "%s is not a valid AMD64 PE", szPath);
    }

    hHost = ((HMODULE (WINAPI*)(PCSTR))g_pfnLoadLibraryA)(szHost);
    if (hHost == NULL)
    {
        PelFreeFile(pFile);
        return PelFail(szError, cchError, "cannot load host module %s", szHost);
    }

    if (!PelFindStompSection((PBYTE)hHost, dwSizeOfImage, &dwSectionRva, szError, cchError))
    {
        PelFreeFile(pFile);
        return FALSE;
    }

    pTarget = (PBYTE)hHost + dwSectionRva;

    if (PexSysProtect(pSys, pTarget, dwSizeOfImage, PAGE_READWRITE, &dwOld) < 0)
    {
        PelFreeFile(pFile);
        return PelFail(szError, cchError, "cannot make the host section writable");
    }

    pImage->pBase = pTarget;
    pImage->mode = PEL_MODE_STOMP;
    pImage->hHost = hHost;

    if (!PelFinish(pSys, pImage, (const BYTE*)pFile, cbFile, FALSE, szError, cchError))
    {
        PelFreeFile(pFile);
        return FALSE;
    }

    PelFreeFile(pFile);
    return TRUE;
}

/* ---------------------------------------------------------------- */
/* Public API                                                        */
/* ---------------------------------------------------------------- */

BOOL PelMapFile(PPEX_SYSCALL pSys, PCSTR szPath, PEL_MODE mode, PCSTR szHost,
                PPEL_IMAGE pImage, PCHAR szError, DWORD cchError)
{
    PVOID pCheck = NULL;
    DWORD cbCheck = 0;

    ZeroMemory(pImage, sizeof(*pImage));
    if (szError != NULL && cchError != 0) szError[0] = 0;

    if (!PelReadFile(szPath, &pCheck, &cbCheck))
    {
        return PelFail(szError, cchError, "cannot read %s", szPath);
    }

    if (!PexPeValidate(pCheck, cbCheck, PEX_PE_FILE))
    {
        PelFreeFile(pCheck);
        return PelFail(szError, cchError, "%s is not a valid AMD64 PE", szPath);
    }

    if (PelHasStaticTls(pCheck, cbCheck))
    {
        PelFreeFile(pCheck);
        return PelFail(szError, cchError,
                       "%s uses static TLS (__declspec(thread)); unsupported", szPath);
    }

    if (PelHasTlsCallbacks(pCheck, cbCheck))
    {
        PelFreeFile(pCheck);
        return PelFail(szError, cchError,
                       "%s uses TLS callbacks; unsupported", szPath);
    }

    PelFreeFile(pCheck);

    if (mode == PEL_MODE_IMAGE)
    {
        return PelMapImage(pSys, szPath, pImage, szError, cchError);
    }

    if (szHost == NULL || szHost[0] == 0)
    {
        return PelFail(szError, cchError, "stomp mode requires a host module name");
    }

    return PelMapStomp(pSys, szPath, szHost, pImage, szError, cchError);
}

BOOL PelInvoke(PPEL_IMAGE pImage, PCSTR szExport, ULONG_PTR* pulValue)
{
    PVOID pFunction = NULL;

    *pulValue = 0;

    if (!PexPeFindExport(pImage->pBase, (DWORD)pImage->cbImage, PEX_PE_MAPPED,
                          szExport, &pFunction, NULL))
    {
        return FALSE;
    }

    *pulValue = ((ULONG_PTR (WINAPI*)(VOID))pFunction)();
    return TRUE;
}

VOID PelRelease(PPEL_IMAGE pImage)
{
    PBYTE   pBase = (PBYTE)pImage->pBase;
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;

    if (pImage->pBase == NULL) return;

    pDos = (PIMAGE_DOS_HEADER)pBase;
    pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);

    if (pImage->dwEntryRva != 0)
    {
        BOOL (WINAPI* pfnEntry)(HMODULE, DWORD, PVOID) =
            (BOOL (WINAPI*)(HMODULE, DWORD, PVOID))(pBase + pImage->dwEntryRva);
        pfnEntry((HMODULE)pBase, DLL_PROCESS_DETACH, NULL);
    }

    if (pImage->bHasException)
    {
        typedef BOOLEAN (NTAPI* PFN_RTL_DELETE_TABLE)(PRUNTIME_FUNCTION pTable);

        PFN_RTL_DELETE_TABLE pfnDeleteTable =
            (PFN_RTL_DELETE_TABLE)NativeResolve(HASH_NTDLL_DLL, HASH_RTLDELETEFUNCTIONTABLE);
        if (pfnDeleteTable != NULL)
        {
            pfnDeleteTable((PRUNTIME_FUNCTION)(pBase + pImage->dwExceptionRva));
        }
    }

    /* The view stays mapped: shared-CRT per-module state can keep pointers
     * into the image after detach, so it is reclaimed at process exit. */

    if (pImage->mode == PEL_MODE_IMAGE)
    {
        if (pImage->hSection != NULL) ((BOOL (WINAPI*)(HANDLE))g_pfnCloseHandle)(pImage->hSection);
        if (pImage->hFile != NULL) ((BOOL (WINAPI*)(HANDLE))g_pfnCloseHandle)(pImage->hFile);
    }

    (void)pNt;
    ZeroMemory(pImage, sizeof(*pImage));
}
