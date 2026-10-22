#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clr_host.h"

#include "pex_args.h"
#include "pex_file.h"
#include "pex_log.h"
#include "pex_native.h"

/*
 * clrldr -- load a .NET Framework assembly into a private AppDomain and run
 * its entry point, or run a Windows PowerShell 5.1 script through the same
 * managed runner. The development build also drives the self-test.
 */

/* ------------------------------------------------------------------ */
/* run                                                                 */
/* ------------------------------------------------------------------ */

static int ClrRun(PCSTR szPath, PCSTR szArguments)
{
    PVOID  pFile = NULL;
    DWORD  cbFile = 0;
    PCHAR  szOutput = NULL;
    DWORD  cbOutput = 0;
    CHAR   szError[256];

    if (!PexFileReadAll(szPath, &pFile, &cbFile))
    {
        PexLog(PEX_LOG_ERROR, "cannot read %s", szPath);
        return 1;
    }

    if (!ClrRunAssembly((const BYTE*)pFile, cbFile, szArguments,
                        szError, sizeof(szError), &szOutput, &cbOutput))
    {
        PexLog(PEX_LOG_ERROR, "%s", szError);
        free(pFile);
        return 2;
    }

    if (cbOutput != 0) NativeWriteText(szOutput, cbOutput);

    ClrFreeOutput(szOutput);
    free(pFile);
    return 0;
}

static int ClrRunPs(PCSTR szScript)
{
    PCHAR szOutput = NULL;
    DWORD cbOutput = 0;
    CHAR  szError[256];

    if (szScript == NULL || szScript[0] == 0)
    {
        PexLog(PEX_LOG_ERROR, "empty script");
        return 1;
    }

    if (!ClrRunPowerShell(szScript, szError, sizeof(szError), &szOutput, &cbOutput))
    {
        PexLog(PEX_LOG_ERROR, "%s", szError);
        return 2;
    }

    if (cbOutput != 0) NativeWriteText(szOutput, cbOutput);

    ClrFreeOutput(szOutput);
    return 0;
}

/* ------------------------------------------------------------------ */
/* selftest                                                            */
/* ------------------------------------------------------------------ */

typedef struct _CLR_CASE
{
    PCSTR szName;
    PCSTR szArguments;
    PCSTR szExpect;
    BOOL  bContains;
} CLR_CASE;

static const CLR_CASE g_aCases[] =
{
    { "c01_basic.dll", "",           "CLR_OK\r\n[+] exit: 0\r\n",            FALSE },
    { "c02_args.dll",  "alpha beta", "ARGS=alpha|beta\r\n[+] exit: 0\r\n",  FALSE },
    { "c03_void.dll",  "",           "VOID_OK\r\n[+] exit: 0\r\n",          FALSE },
    { "c04_exit.dll",  "",           "EXIT7\r\n[+] exit: 7\r\n",            FALSE },
    { "c05_throw.dll", "",           "[!] exception:",                      TRUE  },
    { "c06_bad.bin",   "",           "[!] exception:",                      TRUE  },
};

typedef struct _CLR_PS_CASE
{
    PCSTR szName;
    PCSTR szScript;
    PCSTR szExpect;
} CLR_PS_CASE;

static const CLR_PS_CASE g_aPsCases[] =
{
    { "ps01_output",  "Write-Output 'PS_OK'",   "PS_OK"      },
    { "ps02_unicode", "Write-Output 'PS_UNICODE_\xC3\xA9'", "PS_UNICODE_\xC3\xA9"   },
    { "ps03_error",   "Write-Error 'boom'",      "[ps-error]" },
};

static BOOL ClrCaseRun(const CLR_CASE* pCase, PCSTR szDirectory,
                       PCHAR szDetail, DWORD cchDetail)
{
    CHAR   szPath[MAX_PATH];
    PVOID  pFile = NULL;
    DWORD  cbFile = 0;
    PCHAR  szOutput = NULL;
    DWORD  cbOutput = 0;
    CHAR   szError[256];
    BOOL   bPassed = FALSE;

    szDetail[0] = 0;

    if (!PexPathJoin(szPath, sizeof(szPath), szDirectory, pCase->szName))
    {
        lstrcpynA(szDetail, "path too long", cchDetail);
        return FALSE;
    }
    if (!PexFileExists(szPath))
    {
        lstrcpynA(szDetail, "test assembly missing", cchDetail);
        return FALSE;
    }
    if (!PexFileReadAll(szPath, &pFile, &cbFile))
    {
        lstrcpynA(szDetail, "cannot read the test assembly", cchDetail);
        return FALSE;
    }

    if (!ClrRunAssembly((const BYTE*)pFile, cbFile, pCase->szArguments,
                        szError, sizeof(szError), &szOutput, &cbOutput))
    {
        _snprintf_s(szDetail, cchDetail, _TRUNCATE, "host failed: %s", szError);
        free(pFile);
        return FALSE;
    }
    free(pFile);

    if (pCase->bContains)
    {
        if (szOutput != NULL && strstr(szOutput, pCase->szExpect) != NULL)
        {
            bPassed = TRUE;
        }
        else
        {
            _snprintf_s(szDetail, cchDetail, _TRUNCATE, "expected substring not found");
        }
    }
    else
    {
        DWORD cbExpect = (DWORD)strlen(pCase->szExpect);

        if (cbOutput == cbExpect && memcmp(szOutput, pCase->szExpect, cbExpect) == 0)
        {
            bPassed = TRUE;
        }
        else
        {
            _snprintf_s(szDetail, cchDetail, _TRUNCATE,
                        "output mismatch (got %u bytes)", cbOutput);
        }
    }

    ClrFreeOutput(szOutput);
    return bPassed;
}

static BOOL ClrPsCaseRun(const CLR_PS_CASE* pCase, PCHAR szDetail, DWORD cchDetail)
{
    PCHAR szOutput = NULL;
    DWORD cbOutput = 0;
    CHAR  szError[256];
    BOOL  bPassed = FALSE;

    szDetail[0] = 0;

    if (!ClrRunPowerShell(pCase->szScript, szError, sizeof(szError), &szOutput, &cbOutput))
    {
        _snprintf_s(szDetail, cchDetail, _TRUNCATE, "host failed: %s", szError);
        return FALSE;
    }

    if (szOutput != NULL && strstr(szOutput, pCase->szExpect) != NULL)
    {
        bPassed = TRUE;
    }
    else
    {
        _snprintf_s(szDetail, cchDetail, _TRUNCATE, "expected substring not found");
    }

    ClrFreeOutput(szOutput);
    return bPassed;
}

static int ClrSelftest(PCSTR szDirectory)
{
    DWORD cCases = (DWORD)(sizeof(g_aCases) / sizeof(g_aCases[0]));
    DWORD cPsCases = (DWORD)(sizeof(g_aPsCases) / sizeof(g_aPsCases[0]));
    DWORD dwPassed = 0;
    DWORD i;

    for (i = 0; i < cCases; i++)
    {
        CHAR szDetail[512];
        BOOL bPassed = ClrCaseRun(&g_aCases[i], szDirectory, szDetail, sizeof(szDetail));

        if (bPassed) dwPassed++;
        printf("%s %-16s %s\n", bPassed ? "PASS" : "FAIL", g_aCases[i].szName, szDetail);
    }

    for (i = 0; i < cPsCases; i++)
    {
        CHAR szDetail[512];
        BOOL bPassed = ClrPsCaseRun(&g_aPsCases[i], szDetail, sizeof(szDetail));

        if (bPassed) dwPassed++;
        printf("%s %-16s %s\n", bPassed ? "PASS" : "FAIL", g_aPsCases[i].szName, szDetail);
    }

    printf("\n%u/%u passed\n", dwPassed, cCases + cPsCases);
    return (dwPassed == cCases + cPsCases) ? 0 : 4;
}

/* ------------------------------------------------------------------ */
/* entry                                                               */
/* ------------------------------------------------------------------ */

static void ClrUsage(void)
{
    printf("clrldr -- in-memory .NET Framework assembly / PowerShell loader\n\n");
    printf("  clrldr run <assembly.dll> [--args \"a b\"]\n");
    printf("  clrldr ps <script>\n");
    printf("  clrldr selftest [--dir <path>]\n\n");
    printf("Exit codes: 0 ok, 1 input, 2 CLR, 4 verification\n");
}

int main(int argc, PCHAR* argv)
{
    static PCSTR s_apValueOptions[] = { "--args", "--dir", NULL };
    PEX_ARGS args;
    PCSTR    szCommand;

    if (!NativeInit()) return 1;

    PexArgsInit(&args, argc, argv, s_apValueOptions);

    szCommand = PexArgsPositional(&args, 0);
    if (szCommand == NULL)
    {
        ClrUsage();
        return 1;
    }

    if (lstrcmpA(szCommand, "run") == 0)
    {
        PCSTR szPath = PexArgsPositional(&args, 1);
        PCSTR szArguments = PexArgsValue(&args, "--args");

        if (szPath == NULL) { ClrUsage(); return 1; }
        return ClrRun(szPath, szArguments != NULL ? szArguments : "");
    }

    if (lstrcmpA(szCommand, "ps") == 0)
    {
        PCSTR szScript = NativeJoinArgsUtf8(2);

        if (szScript[0] == 0) { ClrUsage(); return 1; }
        return ClrRunPs(szScript);
    }

    if (lstrcmpA(szCommand, "selftest") == 0)
    {
        PCSTR szDirectory = PexArgsValue(&args, "--dir");

        if (szDirectory == NULL) szDirectory = ".";
        return ClrSelftest(szDirectory);
    }

    ClrUsage();
    return 1;
}
