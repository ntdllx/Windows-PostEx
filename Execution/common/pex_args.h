#pragma once

#include <windows.h>

/*
 * Tiny argument reader.
 *
 * Options are split into two groups at parse time: value options are declared
 * by the caller (so a following bare token is consumed as their value), every
 * other "--name" token is a boolean flag. Anything left over is positional.
 * This keeps "--args a,b" and "--json" unambiguous without a schema parser.
 */

#define PEX_ARGS_MAX 64

typedef struct _PEX_ARGS
{
    int    cArgc;
    PCHAR* ppszArgv;
    int    cPositional;
    int    aPositional[PEX_ARGS_MAX];
} PEX_ARGS;

void        PexArgsInit(PEX_ARGS* pArgs, int cArgc, PCHAR* ppszArgv,
                         PCSTR const* ppszValueOptions);
PCSTR PexArgsValue(const PEX_ARGS* pArgs, PCSTR szName);
BOOL        PexArgsFlag(const PEX_ARGS* pArgs, PCSTR szName);
int         PexArgsPositionalCount(const PEX_ARGS* pArgs);
PCSTR PexArgsPositional(const PEX_ARGS* pArgs, int nIndex);
