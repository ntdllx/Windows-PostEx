#include "pex_args.h"

#include <string.h>

static BOOL PexArgsIsValueOption(PCSTR const* ppszValueOptions, PCSTR szName)
{
    int i;

    if (ppszValueOptions == NULL) return FALSE;
    for (i = 0; ppszValueOptions[i] != NULL; i++)
    {
        if (lstrcmpA(ppszValueOptions[i], szName) == 0) return TRUE;
    }
    return FALSE;
}

static BOOL PexArgsTokenConsumed(const PEX_ARGS* pArgs, int nIndex)
{
    int i;

    for (i = 0; i < pArgs->cPositional; i++)
    {
        if (pArgs->aPositional[i] == nIndex) return TRUE;
    }
    return FALSE;
}

void PexArgsInit(PEX_ARGS* pArgs, int cArgc, PCHAR* ppszArgv,
                  PCSTR const* ppszValueOptions)
{
    int i;

    pArgs->cArgc = cArgc;
    pArgs->ppszArgv = ppszArgv;
    pArgs->cPositional = 0;

    for (i = 1; i < cArgc; i++)
    {
        PCSTR szToken = ppszArgv[i];
        BOOL        bSkipValue;

        if (szToken == NULL) continue;

        bSkipValue = FALSE;
        if (strncmp(szToken, "--", 2) == 0 &&
            PexArgsIsValueOption(ppszValueOptions, szToken))
        {
            bSkipValue = TRUE;
        }

        if (strncmp(szToken, "--", 2) == 0)
        {
            if (bSkipValue) i++;   /* consume the value slot */
            continue;
        }

        if (pArgs->cPositional < PEX_ARGS_MAX)
        {
            pArgs->aPositional[pArgs->cPositional++] = i;
        }
    }

    (void)PexArgsTokenConsumed;
}

PCSTR PexArgsValue(const PEX_ARGS* pArgs, PCSTR szName)
{
    int i;

    for (i = 1; i + 1 < pArgs->cArgc; i++)
    {
        if (lstrcmpA(pArgs->ppszArgv[i], szName) == 0)
        {
            return pArgs->ppszArgv[i + 1];
        }
    }
    return NULL;
}

BOOL PexArgsFlag(const PEX_ARGS* pArgs, PCSTR szName)
{
    int i;

    for (i = 1; i < pArgs->cArgc; i++)
    {
        if (lstrcmpA(pArgs->ppszArgv[i], szName) == 0) return TRUE;
    }
    return FALSE;
}

int PexArgsPositionalCount(const PEX_ARGS* pArgs)
{
    return pArgs->cPositional;
}

PCSTR PexArgsPositional(const PEX_ARGS* pArgs, int nIndex)
{
    if (nIndex < 0 || nIndex >= pArgs->cPositional) return NULL;
    return pArgs->ppszArgv[pArgs->aPositional[nIndex]];
}
