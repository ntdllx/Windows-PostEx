#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "pex_args.h"
#include "pex_file.h"
#include "pex_log.h"
#include "pex_native.h"
#include "pex_syscall.h"

#include "mapper.h"

/*
 * peloader -- maps a DLL into the current process with the loader on this
 * side. Two placements are available:
 *
 *   image  an image section built from the payload file (SEC_IMAGE)
 *   stomp  the executable section of a module that is already loaded
 */

typedef struct _PEL_CASE
{
    PCSTR    szDll;
    PEL_MODE mode;
    PCSTR    szHost;
    PCSTR    szExport;
    ULONG_PTR ulExpect;
    PCSTR    szFlagName;
    PCSTR    szFlagText;
    BOOL     bExportIsString;
} PEL_CASE;

static const PEL_CASE g_aCases[] =
{
    { "p01_hello.dll",  PEL_MODE_IMAGE, NULL,          NULL,      0,      "wm_pel_p01.flag", "ATTACH",   FALSE },
    { "p02_export.dll", PEL_MODE_IMAGE, NULL,          "Run",     0x2222, "wm_pel_p02.flag", "P02",      FALSE },
    { "p03_reloc.dll",  PEL_MODE_IMAGE, NULL,          "GetText", 0,      "wm_pel_p03.flag", "RELOC_OK", TRUE  },
    { "p01_hello.dll",  PEL_MODE_STOMP, "winhttp.dll", NULL,      0,      "wm_pel_p01.flag", "ATTACH",   FALSE },
    { "p02_export.dll", PEL_MODE_STOMP, "winhttp.dll", "Run",     0x2222, "wm_pel_p02.flag", "P02",      FALSE },
    { "p03_reloc.dll",  PEL_MODE_STOMP, "winhttp.dll", "GetText", 0,      "wm_pel_p03.flag", "RELOC_OK", TRUE  },
};

static BOOL PelFlagPath(PCSTR szName, PCHAR szPath, DWORD cchPath)
{
    CHAR  szTemp[MAX_PATH];
    DWORD cchTemp = GetTempPathA(MAX_PATH, szTemp);

    if (cchTemp == 0 || cchTemp >= MAX_PATH) return FALSE;
    return PexPathJoin(szPath, cchPath, szTemp, szName);
}

static VOID PelFlagDelete(PCSTR szName)
{
    CHAR szPath[MAX_PATH];

    if (PelFlagPath(szName, szPath, sizeof(szPath))) DeleteFileA(szPath);
}

static BOOL PelFlagVerify(PCSTR szName, PCSTR szText)
{
    CHAR szPath[MAX_PATH];

    if (!PelFlagPath(szName, szPath, sizeof(szPath))) return FALSE;
    return PexFileEquals(szPath, szText, (DWORD)lstrlenA(szText));
}

static VOID PelQuery(PPEL_IMAGE pImage, PBOOL pbImageType, PBOOL pbInLoaderList)
{
    MEMORY_BASIC_INFORMATION mbi;
    HMODULE hOwner = NULL;

    *pbImageType = FALSE;
    *pbInLoaderList = FALSE;

    if (((SIZE_T (WINAPI*)(PVOID, PMEMORY_BASIC_INFORMATION, SIZE_T))g_pfnVirtualQuery)(
            pImage->pBase, &mbi, sizeof(mbi)) != 0)
    {
        *pbImageType = (mbi.Type == MEM_IMAGE);
    }

    if (((BOOL (WINAPI*)(DWORD, PCSTR, HMODULE*))g_pfnGetModuleHandleExA)(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (PCSTR)pImage->pBase, &hOwner))
    {
        *pbInLoaderList = TRUE;
        ((BOOL (WINAPI*)(HMODULE))g_pfnFreeLibrary)(hOwner);
    }
}

static int PelRun(PCSTR szPath, PEL_MODE mode, PCSTR szHost, PCSTR szExport, BOOL bJson)
{
    PEX_SYSCALL sys;
    PEL_IMAGE    image;
    CHAR         szError[512];
    ULONG_PTR    ulValue = 0;
    BOOL         bImageType = FALSE;
    BOOL         bInLoaderList = FALSE;

    if (!PexSysInit(&sys))
    {
        PexLog(PEX_LOG_ERROR, "cannot initialise the syscall layer");
        return 1;
    }

    if (!PelMapFile(&sys, szPath, mode, szHost, &image, szError, sizeof(szError)))
    {
        PexLog(PEX_LOG_ERROR, "%s", szError);
        return 2;
    }

    if (szExport != NULL && !PelInvoke(&image, szExport, &ulValue))
    {
        PelRelease(&image);
        return 3;
    }

    PelQuery(&image, &bImageType, &bInLoaderList);

    if (bJson)
    {
        printf("{\"tool\":\"peloader\",\"status\":\"ok\",\"mode\":\"%s\","
               "\"base\":\"0x%llx\",\"image_size\":%u,\"type\":\"%s\","
               "\"in_loader_list\":%s,\"value\":\"0x%llx\"}\n",
               mode == PEL_MODE_IMAGE ? "image" : "stomp",
               (unsigned long long)(ULONG_PTR)image.pBase,
               (unsigned)image.cbImage,
               bImageType ? "MEM_IMAGE" : "other",
               bInLoaderList ? "true" : "false",
               (unsigned long long)ulValue);
    }
    else
    {
        PexLog(PEX_LOG_INFO, "base=0x%llx size=0x%x type=%s loader_list=%s",
                (unsigned long long)(ULONG_PTR)image.pBase,
                (unsigned)image.cbImage,
                bImageType ? "MEM_IMAGE" : "other",
                bInLoaderList ? "yes" : "no");
        if (szExport != NULL) printf("0x%llx\n", (unsigned long long)ulValue);
    }

    PelRelease(&image);
    return 0;
}

static BOOL PelCaseRun(const PEL_CASE* pCase, PCSTR szDirectory,
                       PCHAR szDetail, DWORD cchDetail)
{
    PEX_SYSCALL sys;
    PEL_IMAGE    image;
    CHAR         szPath[MAX_PATH];
    CHAR         szError[512];
    ULONG_PTR    ulValue = 0;
    BOOL         bImageType = FALSE;
    BOOL         bInLoaderList = FALSE;

    szDetail[0] = 0;

    if (pCase->szFlagName != NULL) PelFlagDelete(pCase->szFlagName);

    if (!PexPathJoin(szPath, sizeof(szPath), szDirectory, pCase->szDll))
    {
        lstrcpynA(szDetail, "path too long", cchDetail);
        return FALSE;
    }
    if (!PexFileExists(szPath))
    {
        lstrcpynA(szDetail, "test binary missing", cchDetail);
        return FALSE;
    }

    if (!PexSysInit(&sys))
    {
        lstrcpynA(szDetail, "syscall init failed", cchDetail);
        return FALSE;
    }

    if (!PelMapFile(&sys, szPath, pCase->mode, pCase->szHost, &image, szError, sizeof(szError)))
    {
        lstrcpynA(szDetail, szError, cchDetail);
        return FALSE;
    }

    PelQuery(&image, &bImageType, &bInLoaderList);

    if (!bImageType)
    {
        lstrcpynA(szDetail, "image is not MEM_IMAGE", cchDetail);
        PelRelease(&image);
        return FALSE;
    }

    if (pCase->mode == PEL_MODE_STOMP && !bInLoaderList)
    {
        lstrcpynA(szDetail, "stomped image is not attributed to a loaded module", cchDetail);
        PelRelease(&image);
        return FALSE;
    }

    if (pCase->szExport != NULL)
    {
        if (!PelInvoke(&image, pCase->szExport, &ulValue))
        {
            lstrcpynA(szDetail, "export invocation failed", cchDetail);
            PelRelease(&image);
            return FALSE;
        }

        if (pCase->bExportIsString)
        {
            if (ulValue == 0 || lstrcmpA((PCSTR)ulValue, "RELOC_OK") != 0)
            {
                lstrcpynA(szDetail, "relocated string mismatch", cchDetail);
                PelRelease(&image);
                return FALSE;
            }
        }
        else if (ulValue != pCase->ulExpect)
        {
            _snprintf_s(szDetail, cchDetail, _TRUNCATE,
                        "export returned 0x%llx", (unsigned long long)ulValue);
            PelRelease(&image);
            return FALSE;
        }
    }

    PelRelease(&image);

    if (pCase->szFlagName != NULL && !PelFlagVerify(pCase->szFlagName, pCase->szFlagText))
    {
        _snprintf_s(szDetail, cchDetail, _TRUNCATE, "flag %s missing", pCase->szFlagName);
        return FALSE;
    }

    return TRUE;
}

static int PelSelftest(PCSTR szDirectory, BOOL bJson)
{
    DWORD cCases = (DWORD)(sizeof(g_aCases) / sizeof(g_aCases[0]));
    DWORD dwPassed = 0;
    DWORD i;

    for (i = 0; i < cCases; i++)
    {
        CHAR szDetail[512];
        BOOL bPassed = PelCaseRun(&g_aCases[i], szDirectory, szDetail, sizeof(szDetail));

        if (bPassed) dwPassed++;

        if (bJson)
        {
            printf("{\"case\":\"%s\",\"mode\":\"%s\",\"passed\":%s,\"detail\":\"%s\"}\n",
                   g_aCases[i].szDll,
                   g_aCases[i].mode == PEL_MODE_IMAGE ? "image" : "stomp",
                   bPassed ? "true" : "false", szDetail);
        }
        else
        {
            printf("%s %-8s %-16s %s\n", bPassed ? "PASS" : "FAIL",
                   g_aCases[i].mode == PEL_MODE_IMAGE ? "image" : "stomp",
                   g_aCases[i].szDll, szDetail);
        }
    }

    if (bJson)
    {
        printf("{\"tool\":\"peloader\",\"total\":%u,\"passed\":%u,\"failed\":%u}\n",
               cCases, dwPassed, cCases - dwPassed);
    }
    else
    {
        printf("\n%u/%u passed\n", dwPassed, cCases);
    }

    return (dwPassed == cCases) ? 0 : 4;
}

static void PelUsage(void)
{
    printf("peloader -- loader-side DLL mapper\n\n");
    printf("  peloader map <payload.dll> --mode image|stomp [--host winhttp.dll]\n");
    printf("              [--export Name] [--json]\n");
    printf("  peloader selftest [--dir <path>] [--json]\n\n");
    printf("Exit codes: 0 ok, 1 input, 2 map, 3 execute, 4 verification\n");
}

int main(int argc, char** argv)
{
    static const PCSTR s_apValueOptions[] = { "--mode", "--host", "--export", "--dir", NULL };
    PEX_ARGS args;
    PCSTR     szCommand;
    BOOL      bJson;

    if (!NativeInit())
    {
        return 1;
    }

    PexArgsInit(&args, argc, argv, s_apValueOptions);

    szCommand = PexArgsPositional(&args, 0);
    if (szCommand == NULL)
    {
        PelUsage();
        return 1;
    }

    bJson = PexArgsFlag(&args, "--json");
    if (bJson) PexLogSetQuiet(TRUE);
    if (PexArgsFlag(&args, "--verbose")) PexLogSetLevel(PEX_LOG_DEBUG);

    if (lstrcmpA(szCommand, "map") == 0)
    {
        PCSTR szPath = PexArgsPositional(&args, 1);
        PCSTR szMode = PexArgsValue(&args, "--mode");
        PEL_MODE mode;

        if (szPath == NULL) { PelUsage(); return 1; }

        if (szMode == NULL || lstrcmpiA(szMode, "image") == 0)
            mode = PEL_MODE_IMAGE;
        else if (lstrcmpiA(szMode, "stomp") == 0)
            mode = PEL_MODE_STOMP;
        else
        {
            PexLog(PEX_LOG_ERROR, "unknown mode %s", szMode);
            return 1;
        }

        return PelRun(szPath, mode, PexArgsValue(&args, "--host"),
                      PexArgsValue(&args, "--export"), bJson);
    }

    if (lstrcmpA(szCommand, "selftest") == 0)
    {
        PCSTR szDirectory = PexArgsValue(&args, "--dir");
        if (szDirectory == NULL) szDirectory = ".";
        return PelSelftest(szDirectory, bJson);
    }

    PelUsage();
    return 1;
}
