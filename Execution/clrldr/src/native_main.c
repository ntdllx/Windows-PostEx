#include "pex_native.h"

#include "clr_host.h"

/*
 * Native entry for clrldr.
 *
 *   clrldr run <assembly.dll> [--args "a b"]
 *   clrldr ps  <script>
 *
 * The target assembly is read into memory and handed to the managed runner as
 * base64; PowerShell 5.1 runs through the same runner and its SMA assembly.
 * Output goes through NativeWriteText so a console gets UTF-16 and redirected
 * stdout gets UTF-8.
 */

void NativeEntry(void)
{
    PCHAR szOutput = NULL;
    DWORD cbOutput = 0;
    CHAR  szError[1];
    PCSTR szCommand;

    if (!NativeInit()) NativeExit(1);
    if (NativeArgc() < 2) NativeExit(1);

    szCommand = NativeArgv(1);

    if (NativeHash(szCommand) == HASH_PS)
    {
        PCSTR szScript = NativeJoinArgsUtf8(2);

        if (szScript[0] == 0) NativeExit(1);
        if (!ClrRunPowerShell(szScript, szError, sizeof(szError), &szOutput, &cbOutput))
        {
            NativeExit(2);
        }
        NativeWriteText(szOutput, cbOutput);
        ClrFreeOutput(szOutput);
        NativeExit(0);
    }

    if (NativeHash(szCommand) != HASH_RUN) NativeExit(1);
    if (NativeArgc() < 3) NativeExit(1);

    {
        PVOID pFile = NULL;
        DWORD cbFile = 0;
        PCSTR szPath = NativeArgv(2);
        PCSTR szArguments = NativeOptionValue(HASH___ARGS);

        if (szArguments == NULL) szArguments = "";
        if (!NativeReadFile(szPath, &pFile, &cbFile)) NativeExit(1);

        if (!ClrRunAssembly((const BYTE*)pFile, cbFile, szArguments,
                            szError, sizeof(szError), &szOutput, &cbOutput))
        {
            ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pFile, 0, MEM_RELEASE);
            NativeExit(2);
        }

        if (cbOutput != 0) NativeWriteText(szOutput, cbOutput);

        ClrFreeOutput(szOutput);
        ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pFile, 0, MEM_RELEASE);
    }

    NativeExit(0);
}
