#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pex_args.h"
#include "pex_file.h"
#include "pex_log.h"
#include "pex_marker.h"
#include "pex_native.h"

#include "bof_api.h"
#include "coff_core.h"

/*
 * coffldr -- maps an AMD64 COFF object and calls its entry point.
 *
 * The tool supplies the three host services the core refuses to know about:
 * executable memory near the loader (so REL32 to host functions stays in
 * range), a name resolver (BOF primitives first, then common system DLLs), and
 * page protection.
 */

#define TOOL_OUTPUT_MAX 65536

typedef struct _TOOL_CTX
{
    BOF_API_CTX BofApi;
    BYTE        abOutput[TOOL_OUTPUT_MAX];
    DWORD       cbOutput;
} TOOL_CTX, *PTOOL_CTX;

/* ------------------------------------------------------------------ */
/* Host services                                                       */
/* ------------------------------------------------------------------ */

static PVOID WINAPI ToolAlloc(PVOID pUser, SIZE_T cbSize)
{
    PBYTE pAnchor = (PBYTE)(ULONG_PTR)&ToolAlloc;
    DWORD i;

    (void)pUser;

    /* A REL32 fixup against a host function only fits when the image lands
     * within 2 GB of the loader. VirtualAlloc honours a hint when the range is
     * free, so walk downwards in 64 MB steps before giving up. */
    for (i = 1; i <= 24; i++)
    {
        SIZE_T cbDistance = (SIZE_T)i * 0x4000000;
        PVOID  pMemory;

        if ((SIZE_T)pAnchor <= cbDistance) break;

        pMemory = ((PVOID (WINAPI*)(PVOID, SIZE_T, DWORD, DWORD))g_pfnVirtualAlloc)(
            pAnchor - cbDistance, cbSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pMemory != NULL) return pMemory;
    }

    return ((PVOID (WINAPI*)(PVOID, SIZE_T, DWORD, DWORD))g_pfnVirtualAlloc)(
        NULL, cbSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static void WINAPI ToolFree(PVOID pUser, PVOID pMemory, SIZE_T cbSize)
{
    (void)pUser;
    (void)cbSize;
    if (pMemory != NULL)
    {
        ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pMemory, 0, MEM_RELEASE);
    }
}

static BOOL WINAPI ToolProtect(PVOID pUser, PVOID pAddress, SIZE_T cbSize, DWORD flProtect)
{
    DWORD flOldProtect = 0;

    (void)pUser;
    return ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD, PDWORD))g_pfnVirtualProtect)(
        pAddress, cbSize, flProtect, &flOldProtect);
}

#pragma warning(push)
#pragma warning(disable: 4152)
static PVOID ToolGetProcAddress(HMODULE hModule, PCSTR szName)
{
    if (g_pfnGetProcAddress == NULL) return NULL;
    return ((FARPROC (WINAPI*)(HMODULE, PCSTR))g_pfnGetProcAddress)(hModule, szName);
}
#pragma warning(pop)

static PVOID WINAPI ToolResolve(PVOID pUser, PCSTR szName)
{
    static PCSTR s_apszModules[] =
    {
        "kernel32.dll", "advapi32.dll", "user32.dll", "ws2_32.dll", "ntdll.dll", NULL
    };
    TOOL_CTX* pCtx = (TOOL_CTX*)pUser;
    PVOID     pAddress;
    DWORD     i;

    pAddress = BofApiResolve(&pCtx->BofApi, szName);
    if (pAddress != NULL) return pAddress;

    for (i = 0; s_apszModules[i] != NULL; i++)
    {
        HMODULE hModule = (HMODULE)NativeGetModuleByHash(NativeHash(s_apszModules[i]));

        if (hModule == NULL && g_pfnLoadLibraryA != NULL)
        {
            hModule = ((HMODULE (WINAPI*)(PCSTR))g_pfnLoadLibraryA)(s_apszModules[i]);
        }
        if (hModule == NULL) continue;

        pAddress = NativeGetProcFromModule(hModule, NativeHash(szName));
        if (pAddress == NULL)
        {
            /* The manual export walker cannot follow API-set forwarders
             * (kernel32 -> api-ms-win-*), so let the loader resolve them. */
            pAddress = ToolGetProcAddress(hModule, szName);
        }
        if (pAddress != NULL) return pAddress;
    }

    return NULL;
}

static void WINAPI ToolLog(PVOID pUser, int nLevel, PCSTR szMessage)
{
    (void)pUser;
    PexLog(nLevel, "%s", szMessage);
}

static void WINAPI ToolOutput(PVOID pUser, int nType, const VOID* pData, int cbData)
{
    TOOL_CTX* pCtx = (TOOL_CTX*)pUser;
    DWORD     cbCopy;

    (void)nType;
    if (pCtx == NULL || pData == NULL || cbData <= 0) return;

    cbCopy = (DWORD)cbData;
    if (pCtx->cbOutput + cbCopy > TOOL_OUTPUT_MAX)
    {
        cbCopy = TOOL_OUTPUT_MAX - pCtx->cbOutput;
    }
    if (cbCopy == 0) return;

    CopyMemory(pCtx->abOutput + pCtx->cbOutput, pData, cbCopy);
    pCtx->cbOutput += cbCopy;
}

static void ToolInit(TOOL_CTX* pCtx, PCSTR pArgs, DWORD cbArgs)
{
    ZeroMemory(pCtx, sizeof(*pCtx));
    BofApiInit(&pCtx->BofApi, pArgs, (int)cbArgs, ToolOutput, pCtx);
}

static COFF_OPS ToolMakeOps(TOOL_CTX* pCtx)
{
    COFF_OPS ops;

    ops.pfnAlloc = ToolAlloc;
    ops.pfnFree = ToolFree;
    ops.pfnProtect = ToolProtect;
    ops.pfnResolve = ToolResolve;
    ops.pfnLog = ToolLog;
    ops.pUser = pCtx;
    return ops;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static BOOL ToolCheckWx(PCOFF_IMAGE pImage, DWORD* pdwRwxSections)
{
    COFF_STATS stats;
    DWORD      i;
    BOOL       bClean = TRUE;

    *pdwRwxSections = 0;
    if (CoffGetStats(pImage, &stats) != COFF_OK) return FALSE;

    for (i = 0; i < stats.cSections; i++)
    {
        COFF_SECTION_VIEW view;
        MEMORY_BASIC_INFORMATION mbi;
        DWORD dwProtect;
        PCSTR szProtect;

        if (CoffGetSection(pImage, i, &view) != COFF_OK) continue;
        if (view.cbSize == 0) continue;

        if (((SIZE_T (WINAPI*)(PVOID, PMEMORY_BASIC_INFORMATION, SIZE_T))g_pfnVirtualQuery)(
                view.pBase, &mbi, sizeof(mbi)) == 0) continue;

        dwProtect = mbi.Protect & 0xFF;
        switch (dwProtect)
        {
        case PAGE_READONLY:          szProtect = "R";  break;
        case PAGE_READWRITE:         szProtect = "RW"; break;
        case PAGE_EXECUTE_READ:      szProtect = "RX"; break;
        case PAGE_EXECUTE_READWRITE: szProtect = "RWX"; break;
        case PAGE_EXECUTE_WRITECOPY: szProtect = "RWX"; break;
        default:                     szProtect = "?";  break;
        }

        PexLog(PEX_LOG_DEBUG, "  section %-8s base=%p size=0x%05x protect=%s",
                view.szName, view.pBase, view.cbSize, szProtect);

        if (dwProtect == PAGE_EXECUTE_READWRITE || dwProtect == PAGE_EXECUTE_WRITECOPY)
        {
            (*pdwRwxSections)++;
            bClean = FALSE;
        }
    }

    return bClean;
}

static PCSTR ToolSectionFlags(DWORD flCharacteristics, PCHAR szBuffer, DWORD cchBuffer)
{
    DWORD dwUsed = 0;

    szBuffer[0] = 0;
    if ((flCharacteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
        dwUsed += (DWORD)_snprintf_s(szBuffer + dwUsed, cchBuffer - dwUsed, _TRUNCATE, "x");
    if ((flCharacteristics & IMAGE_SCN_MEM_READ) != 0)
        dwUsed += (DWORD)_snprintf_s(szBuffer + dwUsed, cchBuffer - dwUsed, _TRUNCATE, "r");
    if ((flCharacteristics & IMAGE_SCN_MEM_WRITE) != 0)
        dwUsed += (DWORD)_snprintf_s(szBuffer + dwUsed, cchBuffer - dwUsed, _TRUNCATE, "w");
    if (dwUsed == 0)
    {
        _snprintf_s(szBuffer, cchBuffer, _TRUNCATE, "-");
    }
    return szBuffer;
}

/* ------------------------------------------------------------------ */
/* inspect                                                             */
/* ------------------------------------------------------------------ */

static int ToolInspect(PCSTR szPath, BOOL bJson)
{
    PVOID              pObject = NULL;
    DWORD              cbObject = 0;
    PIMAGE_FILE_HEADER pHeader;
    PIMAGE_SECTION_HEADER pSectionHeaders;
    DWORD              i;

    if (!PexFileReadAll(szPath, &pObject, &cbObject))
    {
        PexLog(PEX_LOG_ERROR, "cannot read %s", szPath);
        return 1;
    }
    if (cbObject < sizeof(IMAGE_FILE_HEADER))
    {
        PexLog(PEX_LOG_ERROR, "file is shorter than a COFF header");
        free(pObject);
        return 2;
    }

    pHeader = (PIMAGE_FILE_HEADER)pObject;
    pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pObject + sizeof(IMAGE_FILE_HEADER));

    if (bJson)
    {
        printf("{\"file\":\"%s\",\"machine\":%u,\"sections\":%u,\"symbols\":%u}\n",
               szPath, (unsigned)pHeader->Machine,
               (unsigned)pHeader->NumberOfSections,
               (unsigned)pHeader->NumberOfSymbols);
    }
    else
    {
        printf("file      %s\n", szPath);
        printf("machine   0x%04x %s\n", (unsigned)pHeader->Machine,
               (pHeader->Machine == IMAGE_FILE_MACHINE_AMD64) ? "AMD64" :
               (pHeader->Machine == IMAGE_FILE_MACHINE_I386) ? "I386 (unsupported)" : "other");
        printf("sections  %u\n", (unsigned)pHeader->NumberOfSections);
        printf("symbols   %u\n", (unsigned)pHeader->NumberOfSymbols);
        printf("\n");
        printf("%-3s %-9s %-10s %-7s %s\n", "idx", "name", "raw", "relocs", "flags");
        for (i = 0; i < pHeader->NumberOfSections; i++)
        {
            CHAR szFlags[8];
            printf("%-3u %-9.8s 0x%-8x %-7u %s\n",
                   i,
                   pSectionHeaders[i].Name,
                   pSectionHeaders[i].SizeOfRawData,
                   pSectionHeaders[i].NumberOfRelocations,
                   ToolSectionFlags(pSectionHeaders[i].Characteristics, szFlags, sizeof(szFlags)));
        }
    }

    free(pObject);
    return 0;
}

/* ------------------------------------------------------------------ */
/* run                                                                 */
/* ------------------------------------------------------------------ */

static int ToolRun(PCSTR szPath, PCSTR szEntry, PCSTR szArguments, BOOL bJson)
{
    PVOID      pObject = NULL;
    DWORD      cbObject = 0;
    BYTE*      pbArgs = NULL;
    DWORD      cbArgs = 0;
    TOOL_CTX   ctx;
    COFF_OPS   ops;
    PCOFF_IMAGE pImage = NULL;
    COFF_STATUS status;
    COFF_STATS  stats;
    DWORD      dwRwx = 0;

    if (!PexFileReadAll(szPath, &pObject, &cbObject))
    {
        PexLog(PEX_LOG_ERROR, "cannot read %s", szPath);
        return 1;
    }
    if (!BofApiPackArgs(szArguments, &pbArgs, &cbArgs))
    {
        PexLog(PEX_LOG_ERROR, "cannot pack arguments");
        free(pObject);
        return 1;
    }
    PexLogHex(PEX_LOG_DEBUG, "args", pbArgs, cbArgs);

    ToolInit(&ctx, (PCSTR)pbArgs, cbArgs);
    ops = ToolMakeOps(&ctx);

    status = CoffLoadImage(pObject, cbObject, &ops, &pImage);
    if (status != COFF_OK)
    {
        PexLog(PEX_LOG_ERROR, "load failed: %s", CoffStatusName(status));
        BofApiRelease(&ctx.BofApi);
        BofApiFreeArgs(pbArgs);
        free(pObject);
        return 2;
    }

    if (!ToolCheckWx(pImage, &dwRwx))
    {
        PexLog(PEX_LOG_ERROR, "%u section(s) ended up writable+executable", dwRwx);
    }

    status = CoffRunEntry(pImage, szEntry, (PCSTR)pbArgs, cbArgs, NULL);
    if (status != COFF_OK)
    {
        PexLog(PEX_LOG_ERROR, "entry failed: %s", CoffStatusName(status));
        CoffFreeImage(pImage);
        BofApiRelease(&ctx.BofApi);
        BofApiFreeArgs(pbArgs);
        free(pObject);
        return 3;
    }

    CoffGetStats(pImage, &stats);

    if (bJson)
    {
        printf("{\"tool\":\"coffldr\",\"status\":\"ok\",\"sections\":%u,\"symbols\":%u,"
               "\"relocations\":%u,\"externals\":%u,\"import_slots\":%u,\"output_bytes\":%u}\n",
               stats.cSections, stats.cSymbols, stats.cRelocations,
               stats.cExternals, stats.cImportSlots, ctx.cbOutput);
    }
    else if (ctx.cbOutput != 0)
    {
        fwrite(ctx.abOutput, 1, ctx.cbOutput, stdout);
    }

    CoffFreeImage(pImage);
    BofApiRelease(&ctx.BofApi);
    BofApiFreeArgs(pbArgs);
    free(pObject);
    return 0;
}

/* ------------------------------------------------------------------ */
/* selftest                                                            */
/* ------------------------------------------------------------------ */

typedef enum _CHECK_KIND
{
    CHECK_NONE = 0,
    CHECK_TEXT,
    CHECK_BYTES,
    CHECK_PREFIX_HEX,
    CHECK_LOAD_ERROR
} CHECK_KIND;

typedef struct _SELFTEST_CASE
{
    PCSTR szName;
    PCSTR szArguments;
    CHECK_KIND  kind;
    PCSTR pExpect;
    DWORD       cbExpect;
    DWORD       dwMinRelocations;
    PCSTR szMarkerName;
    PCSTR szMarkerText;
    COFF_STATUS statusExpect;
} SELFTEST_CASE;

static const SELFTEST_CASE g_aCases[] =
{
    { "t01_entry",     NULL,      CHECK_NONE,       NULL, 0, 0, NULL, NULL, COFF_OK },
    { "t02_args",      "alpha,42",CHECK_TEXT,       "ARG0=alpha ARG1=42\n", 0, 0, NULL, NULL, COFF_OK },
    { "t03_output",    NULL,      CHECK_BYTES,      "A\0B", 3, 0, NULL, NULL, COFF_OK },
    { "t04_addr64",    NULL,      CHECK_TEXT,       "T=ADDR64_OK\n", 0, 1, NULL, NULL, COFF_OK },
    { "t05_rel32",     NULL,      CHECK_TEXT,       "R=3,44\n", 0, 1, NULL, NULL, COFF_OK },
    { "t06_imagebase", NULL,      CHECK_PREFIX_HEX, "IB=0x", 0, 1, NULL, NULL, COFF_OK },
    { "t07_import",    NULL,      CHECK_NONE,       NULL, 0, 1, "t07.marker", "T07_OK", COFF_OK },
    { "t08_badsym",    NULL,      CHECK_LOAD_ERROR, NULL, 0, 0, NULL, NULL, COFF_ERR_SYMBOL },
};

static BOOL SelftestVerifyPrefixHex(const TOOL_CTX* pCtx, PCSTR szPrefix)
{
    size_t cchPrefix = lstrlenA(szPrefix);
    size_t i;
    unsigned __int64 qwValue = 0;
    BOOL bAnyDigit = FALSE;

    if (pCtx->cbOutput < cchPrefix) return FALSE;
    if (memcmp(pCtx->abOutput, szPrefix, cchPrefix) != 0) return FALSE;

    for (i = cchPrefix; i < pCtx->cbOutput; i++)
    {
        CHAR ch = (CHAR)pCtx->abOutput[i];
        int  nDigit;

        if (ch >= '0' && ch <= '9')      nDigit = ch - '0';
        else if (ch >= 'a' && ch <= 'f') nDigit = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') nDigit = ch - 'A' + 10;
        else break;

        qwValue = (qwValue << 4) | (unsigned __int64)nDigit;
        bAnyDigit = TRUE;
    }

    return bAnyDigit && qwValue != 0;
}

static BOOL SelftestRunCase(const SELFTEST_CASE* pCase, PCSTR szDirectory,
                            CHAR* szDetail, DWORD cchDetail)
{
    CHAR       szPath[MAX_PATH];
    PVOID      pObject = NULL;
    DWORD      cbObject = 0;
    BYTE*      pbArgs = NULL;
    DWORD      cbArgs = 0;
    TOOL_CTX   ctx;
    COFF_OPS   ops;
    PCOFF_IMAGE pImage = NULL;
    COFF_STATUS status;
    COFF_STATS  stats;
    DWORD      dwRwx = 0;
    BOOL       bPassed = TRUE;

    szDetail[0] = 0;

    if (!PexPathJoin(szPath, sizeof(szPath), szDirectory, pCase->szName) ||
        strcat_s(szPath, sizeof(szPath), ".obj") != 0)
    {
        _snprintf_s(szDetail, cchDetail, _TRUNCATE, "path too long");
        return FALSE;
    }

    if (!PexFileReadAll(szPath, &pObject, &cbObject))
    {
        _snprintf_s(szDetail, cchDetail, _TRUNCATE, "missing %s", szPath);
        return FALSE;
    }

    if (!BofApiPackArgs(pCase->szArguments, &pbArgs, &cbArgs))
    {
        _snprintf_s(szDetail, cchDetail, _TRUNCATE, "argument packing failed");
        free(pObject);
        return FALSE;
    }

    ToolInit(&ctx, (PCSTR)pbArgs, cbArgs);
    ops = ToolMakeOps(&ctx);

    status = CoffLoadImage(pObject, cbObject, &ops, &pImage);
    if (status != pCase->statusExpect)
    {
        _snprintf_s(szDetail, cchDetail, _TRUNCATE,
                    "load status %s, expected %s",
                    CoffStatusName(status), CoffStatusName(pCase->statusExpect));
        BofApiRelease(&ctx.BofApi);
        BofApiFreeArgs(pbArgs);
        free(pObject);
        return FALSE;
    }

    if (status != COFF_OK)
    {
        bPassed = TRUE;   /* negative case matched */
        BofApiRelease(&ctx.BofApi);
        BofApiFreeArgs(pbArgs);
        free(pObject);
        return bPassed;
    }

    if (!ToolCheckWx(pImage, &dwRwx))
    {
        _snprintf_s(szDetail, cchDetail, _TRUNCATE, "%u page(s) writable+executable", dwRwx);
        bPassed = FALSE;
    }

    if (bPassed)
    {
        status = CoffRunEntry(pImage, NULL, (PCSTR)pbArgs, cbArgs, NULL);
        if (status != COFF_OK)
        {
            _snprintf_s(szDetail, cchDetail, _TRUNCATE, "entry failed: %s", CoffStatusName(status));
            bPassed = FALSE;
        }
    }

    if (bPassed && pCase->kind == CHECK_TEXT)
    {
        DWORD cbExpect = pCase->cbExpect ? pCase->cbExpect : (DWORD)lstrlenA(pCase->pExpect);

        if (ctx.cbOutput != cbExpect ||
            memcmp(ctx.abOutput, pCase->pExpect, cbExpect) != 0)
        {
            _snprintf_s(szDetail, cchDetail, _TRUNCATE,
                        "output mismatch (got %u bytes)", ctx.cbOutput);
            bPassed = FALSE;
        }
    }
    else if (bPassed && pCase->kind == CHECK_BYTES)
    {
        if (ctx.cbOutput != pCase->cbExpect ||
            memcmp(ctx.abOutput, pCase->pExpect, pCase->cbExpect) != 0)
        {
            _snprintf_s(szDetail, cchDetail, _TRUNCATE,
                        "byte output mismatch (got %u bytes)", ctx.cbOutput);
            bPassed = FALSE;
        }
    }
    else if (bPassed && pCase->kind == CHECK_PREFIX_HEX)
    {
        if (!SelftestVerifyPrefixHex(&ctx, pCase->pExpect))
        {
            _snprintf_s(szDetail, cchDetail, _TRUNCATE, "prefix/nonzero check failed");
            bPassed = FALSE;
        }
    }

    if (bPassed && pCase->dwMinRelocations != 0)
    {
        CoffGetStats(pImage, &stats);
        if (stats.cRelocations < pCase->dwMinRelocations)
        {
            _snprintf_s(szDetail, cchDetail, _TRUNCATE,
                        "relocations=%u, expected at least %u",
                        stats.cRelocations, pCase->dwMinRelocations);
            bPassed = FALSE;
        }
    }

    if (bPassed && pCase->szMarkerName != NULL)
    {
        if (!PexMarkerVerify(szDirectory, pCase->szMarkerName, pCase->szMarkerText))
        {
            _snprintf_s(szDetail, cchDetail, _TRUNCATE,
                        "marker %s missing or wrong", pCase->szMarkerName);
            bPassed = FALSE;
        }
    }

    CoffFreeImage(pImage);
    BofApiRelease(&ctx.BofApi);
    BofApiFreeArgs(pbArgs);
    free(pObject);
    return bPassed;
}

static int ToolSelftest(PCSTR szDirectory, BOOL bJson, BOOL bVerbose)
{
    CHAR  szOriginalDirectory[MAX_PATH];
    CHAR  szAbsolute[MAX_PATH];
    DWORD cCases = (DWORD)(sizeof(g_aCases) / sizeof(g_aCases[0]));
    DWORD dwPassed = 0;
    DWORD i;

    if (GetCurrentDirectoryA(sizeof(szOriginalDirectory), szOriginalDirectory) == 0)
    {
        szOriginalDirectory[0] = 0;
    }
    if (GetFullPathNameA(szDirectory, sizeof(szAbsolute), szAbsolute, NULL) == 0)
    {
        PexLog(PEX_LOG_ERROR, "cannot resolve test directory %s", szDirectory);
        return 1;
    }
    if (!SetCurrentDirectoryA(szAbsolute))
    {
        PexLog(PEX_LOG_ERROR, "cannot enter test directory %s", szAbsolute);
        return 1;
    }

    for (i = 0; i < cCases; i++)
    {
        CHAR szDetail[512];
        BOOL bPassed = SelftestRunCase(&g_aCases[i], szAbsolute, szDetail, sizeof(szDetail));

        if (bPassed) dwPassed++;

        if (!bJson)
        {
            printf("%s %-16s %s\n", bPassed ? "PASS" : "FAIL", g_aCases[i].szName, szDetail);
        }
        else if (bVerbose || !bPassed)
        {
            printf("{\"case\":\"%s\",\"passed\":%s,\"detail\":\"%s\"}\n",
                   g_aCases[i].szName, bPassed ? "true" : "false", szDetail);
        }
    }

    if (szOriginalDirectory[0] != 0)
    {
        SetCurrentDirectoryA(szOriginalDirectory);
    }

    if (bJson)
    {
        printf("{\"tool\":\"coffldr\",\"total\":%u,\"passed\":%u,\"failed\":%u}\n",
               cCases, dwPassed, cCases - dwPassed);
    }
    else
    {
        printf("\n%u/%u passed\n", dwPassed, cCases);
    }

    return (dwPassed == cCases) ? 0 : 4;
}

/* ------------------------------------------------------------------ */
/* Entry                                                               */
/* ------------------------------------------------------------------ */

static void ToolUsage(void)
{
    printf("coffldr -- AMD64 COFF object mapper\n\n");
    printf("  coffldr run <file.obj> [--args a,b] [--entry go] [--json]\n");
    printf("  coffldr inspect <file.obj> [--json]\n");
    printf("  coffldr selftest [--dir <path>] [--json]\n\n");
    printf("Exit codes: 0 ok, 1 input, 2 load, 3 execute, 4 verification\n");
}

int main(int argc, PCHAR* argv)
{
    static PCSTR s_ppszValueOptions[] = { "--args", "--entry", "--dir", NULL };
    PEX_ARGS args;
    PCSTR szCommand;
    BOOL bJson;

    if (!NativeInit()) return 1;

    PexArgsInit(&args, argc, argv, s_ppszValueOptions);

    szCommand = PexArgsPositional(&args, 0);
    if (szCommand == NULL)
    {
        ToolUsage();
        return 1;
    }

    bJson = PexArgsFlag(&args, "--json");
    if (bJson) PexLogSetQuiet(TRUE);
    if (PexArgsFlag(&args, "--verbose")) PexLogSetLevel(PEX_LOG_DEBUG);

    if (lstrcmpA(szCommand, "run") == 0)
    {
        PCSTR szPath = PexArgsPositional(&args, 1);
        if (szPath == NULL) { ToolUsage(); return 1; }
        return ToolRun(szPath, PexArgsValue(&args, "--entry"),
                       PexArgsValue(&args, "--args"), bJson);
    }
    if (lstrcmpA(szCommand, "inspect") == 0)
    {
        PCSTR szPath = PexArgsPositional(&args, 1);
        if (szPath == NULL) { ToolUsage(); return 1; }
        return ToolInspect(szPath, bJson);
    }
    if (lstrcmpA(szCommand, "selftest") == 0)
    {
        PCSTR szDirectory = PexArgsValue(&args, "--dir");
        if (szDirectory == NULL) szDirectory = ".";
        return ToolSelftest(szDirectory, bJson, PexArgsFlag(&args, "--verbose"));
    }

    ToolUsage();
    return 1;
}
