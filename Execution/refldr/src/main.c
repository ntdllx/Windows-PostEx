#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "pex_args.h"
#include "pex_file.h"
#include "pex_log.h"
#include "pex_native.h"

#include "loader.h"

/*
 * refldr -- loads a DLL through its own in-image loader.
 *
 * The payload is a DLL that exports ReflectiveLoad. The host copies the file
 * verbatim into a staging buffer (file layout), makes it executable, and calls
 * that export. Everything after that -- section mapping, relocation, imports,
 * TLS, exception tables -- happens inside the payload.
 */


/* ------------------------------------------------------------------ */
/* Temp flags                                                          */
/* ------------------------------------------------------------------ */

static BOOL ReflFlagPath(PCSTR szName, PCHAR szPath, DWORD cchPath)
{
    CHAR szTemp[MAX_PATH];
    DWORD cchTemp = GetTempPathA(MAX_PATH, szTemp);

    if (cchTemp == 0 || cchTemp >= MAX_PATH) return FALSE;
    return PexPathJoin(szPath, cchPath, szTemp, szName);
}

static VOID ReflFlagDelete(PCSTR szName)
{
    CHAR szPath[MAX_PATH];

    if (ReflFlagPath(szName, szPath, sizeof(szPath))) DeleteFileA(szPath);
}

static BOOL ReflFlagVerify(PCSTR szName, PCSTR szText)
{
    CHAR szPath[MAX_PATH];

    if (!ReflFlagPath(szName, szPath, sizeof(szPath))) return FALSE;
    return PexFileEquals(szPath, szText, (DWORD)lstrlenA(szText));
}

/* Commands                                                            */
/* ------------------------------------------------------------------ */

static int ReflRun(PCSTR szPath, PCSTR szExport, BOOL bKeep, BOOL bJson, BOOL bCorrupt)
{
    REFL_IMAGE image;
    ULONG_PTR  ulValue = 0;
    CHAR       szError[256];

    if (!ReflLoad(szPath, bCorrupt, &image, szError, sizeof(szError)))
    {
        PexLog(PEX_LOG_ERROR, "%s", szError);
        if (bJson)
        {
            printf("{\"tool\":\"refldr\",\"status\":\"load_failed\"}\n");
        }
        return 2;
    }

    if (szExport != NULL && !ReflInvoke(&image, szExport, &ulValue))
    {
        ReflUnload(&image);
        return 3;
    }

    if (bJson)
    {
        printf("{\"tool\":\"refldr\",\"status\":\"ok\",\"base\":\"0x%llx\","
               "\"image_size\":%u,\"relocated\":true,\"private\":%s,"
               "\"in_loader_list\":%s,\"export\":\"%s\",\"value\":\"0x%llx\"}\n",
               (unsigned long long)(ULONG_PTR)image.pBase,
               image.dwSizeOfImage,
               image.bPrivate ? "true" : "false",
               image.bInLoaderList ? "true" : "false",
               szExport != NULL ? szExport : "",
               (unsigned long long)ulValue);
    }
    else
    {
        PexLog(PEX_LOG_INFO, "base=0x%llx size=0x%x private=%s loader_list=%s",
                (unsigned long long)(ULONG_PTR)image.pBase,
                image.dwSizeOfImage,
                image.bPrivate ? "yes" : "no",
                image.bInLoaderList ? "yes" : "no");
        if (szExport != NULL)
        {
            printf("0x%llx\n", (unsigned long long)ulValue);
        }
    }

    if (!bKeep) ReflUnload(&image);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Self-test                                                           */
/* ------------------------------------------------------------------ */

typedef struct _REFL_CASE
{
    PCSTR szDll;
    PCSTR szExport;
    ULONG_PTR ulExpect;
    PCSTR szFlag1Name;
    PCSTR szFlag1Text;
    PCSTR szFlag2Name;
    PCSTR szFlag2Text;
    BOOL  bKeep;
    BOOL  bCorrupt;
    BOOL  bExpectFail;
    BOOL  bExportIsString;
} REFL_CASE;

static const REFL_CASE g_aCases[] =
{
    { "r01_minimal.dll",   NULL,       0,      "wm_r01_attach.flag",  "ATTACH", NULL, NULL, FALSE, FALSE, FALSE, FALSE },
    { "r02_imports.dll",   "Run",      0x2222, "wm_r02.flag",         "IMPORTS_OK", NULL, NULL, FALSE, FALSE, FALSE, FALSE },
    { "r03_reloc.dll",     "GetText",  0,      "wm_r03.flag",         "RELOC_OK", NULL, NULL, FALSE, FALSE, FALSE, TRUE },
    { "r04_tls.dll",       NULL,       0,      NULL,                  NULL, NULL, NULL, FALSE, FALSE, TRUE,  FALSE },
    { "r06_seh.dll",       "Run",      0x6601, "wm_r06.flag",         "SEH_OK", NULL, NULL, FALSE, FALSE, FALSE, FALSE },
    { "r01_minimal.dll",   NULL,       0,      NULL,                  NULL, NULL, NULL, TRUE,  TRUE,  TRUE,  FALSE },
    { "r01_minimal.dll",   NULL,       0,      "wm_r01_attach.flag",  "ATTACH", "wm_r01_detach.flag", "DETACH", FALSE, FALSE, FALSE, FALSE },
};

static BOOL ReflCaseRun(const REFL_CASE* pCase, PCSTR szDirectory, PCHAR szDetail, DWORD cchDetail)
{
    CHAR       szPath[MAX_PATH];
    REFL_IMAGE image;
    ULONG_PTR  ulValue = 0;
    BOOL       bLoaded;

    szDetail[0] = 0;

    if (pCase->szFlag1Name) ReflFlagDelete(pCase->szFlag1Name);
    if (pCase->szFlag2Name) ReflFlagDelete(pCase->szFlag2Name);

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

    bLoaded = ReflLoad(szPath, pCase->bCorrupt, &image, szDetail, cchDetail);
    if (pCase->bExpectFail)
    {
        if (bLoaded)
        {
            ReflUnload(&image);
            lstrcpynA(szDetail, "load succeeded, expected failure", cchDetail);
            return FALSE;
        }
        return TRUE;
    }
    if (!bLoaded)
    {
        lstrcpynA(szDetail, "load failed", cchDetail);
        return FALSE;
    }

    if (!image.bPrivate)
    {
        lstrcpynA(szDetail, "image is file-backed (MEM_IMAGE)", cchDetail);
        ReflUnload(&image);
        return FALSE;
    }
    if (image.bInLoaderList)
    {
        lstrcpynA(szDetail, "image is visible in the loader list", cchDetail);
        ReflUnload(&image);
        return FALSE;
    }

    if (pCase->szExport != NULL)
    {
        if (!ReflInvoke(&image, pCase->szExport, &ulValue))
        {
            lstrcpynA(szDetail, "export invocation failed", cchDetail);
            ReflUnload(&image);
            return FALSE;
        }

        if (pCase->bExportIsString)
        {
            if (ulValue == 0 || lstrcmpA((PCSTR)ulValue, "RELOC_OK") != 0)
            {
                lstrcpynA(szDetail, "export did not return the relocated string", cchDetail);
                ReflUnload(&image);
                return FALSE;
            }
        }
        else if (ulValue != pCase->ulExpect)
        {
            _snprintf_s(szDetail, cchDetail, _TRUNCATE,
                        "export returned 0x%llx, expected 0x%llx",
                        (unsigned long long)ulValue, (unsigned long long)pCase->ulExpect);
            ReflUnload(&image);
            return FALSE;
        }
    }

    if (!pCase->bKeep) ReflUnload(&image);

    if (pCase->szFlag1Name && !ReflFlagVerify(pCase->szFlag1Name, pCase->szFlag1Text))
    {
        _snprintf_s(szDetail, cchDetail, _TRUNCATE, "flag %s missing or wrong", pCase->szFlag1Name);
        return FALSE;
    }
    if (pCase->szFlag2Name && !ReflFlagVerify(pCase->szFlag2Name, pCase->szFlag2Text))
    {
        _snprintf_s(szDetail, cchDetail, _TRUNCATE, "flag %s missing or wrong", pCase->szFlag2Name);
        return FALSE;
    }

    return TRUE;
}

static int ReflSelftest(PCSTR szDirectory, BOOL bJson)
{
    DWORD cCases = (DWORD)(sizeof(g_aCases) / sizeof(g_aCases[0]));
    DWORD dwPassed = 0;
    DWORD i;

    for (i = 0; i < cCases; i++)
    {
        CHAR szDetail[256];
        BOOL bPassed = ReflCaseRun(&g_aCases[i], szDirectory, szDetail, sizeof(szDetail));

        if (bPassed) dwPassed++;

        if (bJson)
        {
            printf("{\"case\":\"%s\",\"passed\":%s,\"detail\":\"%s\"}\n",
                   g_aCases[i].szDll, bPassed ? "true" : "false", szDetail);
        }
        else
        {
            printf("%s %-18s %s\n", bPassed ? "PASS" : "FAIL", g_aCases[i].szDll, szDetail);
        }
    }

    if (bJson)
    {
        printf("{\"tool\":\"refldr\",\"total\":%u,\"passed\":%u,\"failed\":%u}\n",
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

static void ReflUsage(void)
{
    printf("refldr -- reflective DLL loader\n\n");
    printf("  refldr run <payload.dll> [--export Name] [--keep] [--json]\n");
    printf("  refldr selftest [--dir <path>] [--json]\n\n");
    printf("Exit codes: 0 ok, 1 input, 2 load, 3 execute, 4 verification\n");
}

int main(int argc, char** argv)
{
    static const char* s_ppszValueOptions[] = { "--export", "--dir", NULL };
    PEX_ARGS args;
    PCSTR     szCommand;
    BOOL      bJson;

    if (!NativeInit()) return 1;

    PexArgsInit(&args, argc, argv, s_ppszValueOptions);

    szCommand = PexArgsPositional(&args, 0);
    if (szCommand == NULL)
    {
        ReflUsage();
        return 1;
    }

    bJson = PexArgsFlag(&args, "--json");
    if (bJson) PexLogSetQuiet(TRUE);
    if (PexArgsFlag(&args, "--verbose")) PexLogSetLevel(PEX_LOG_DEBUG);

    if (lstrcmpA(szCommand, "run") == 0)
    {
        PCSTR szPath = PexArgsPositional(&args, 1);
        if (szPath == NULL) { ReflUsage(); return 1; }
        return ReflRun(szPath, PexArgsValue(&args, "--export"),
                       PexArgsFlag(&args, "--keep"), bJson, FALSE);
    }
    if (lstrcmpA(szCommand, "selftest") == 0)
    {
        PCSTR szDirectory = PexArgsValue(&args, "--dir");
        if (szDirectory == NULL) szDirectory = ".";
        return ReflSelftest(szDirectory, bJson);
    }

    ReflUsage();
    return 1;
}
