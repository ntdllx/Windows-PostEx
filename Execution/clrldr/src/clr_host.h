#pragma once

#include <windows.h>

/*
 * Minimal in-process CLR v4 host.
 *
 * The target assembly is loaded into a private AppDomain through the managed
 * runner (Assembly.Load on a byte array), so the target file never has to be
 * mapped by the Windows loader. Output is the runner's captured Console text.
 *
 * The returned buffer is allocated with VirtualAlloc; release it with
 * ClrFreeOutput.
 */
BOOL ClrRunAssembly(const BYTE* pbAssembly, DWORD cbAssembly, PCSTR szArguments,
                    PCHAR szError, DWORD cchError,
                    PCHAR* ppszOutput, PDWORD pcbOutput);

BOOL ClrRunPowerShell(PCSTR szScript, PCHAR szError, DWORD cchError,
                      PCHAR* ppszOutput, PDWORD pcbOutput);

VOID ClrFreeOutput(PCHAR pszOutput);
