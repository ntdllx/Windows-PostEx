#pragma once

#include <windows.h>

/*
 * bof_api -- the smallest runtime a COFF object needs in order to print and
 * read its argument blob. It is an adapter, not part of the loader: the core
 * resolves names through a callback, and the tool decides what those names map
 * to. Nothing here knows about a network, a queue, or a task id.
 *
 * Threading: the BOF API has no context argument, so this adapter
 * keeps one active context per process. That is fine for a CLI that runs one
 * object at a time and is documented as a deliberate limit.
 */

typedef void (WINAPI* PFN_BOF_OUTPUT)(PVOID pUser, int nType, const VOID* pData, int cbData);

typedef struct _BOF_API_CTX
{
    PCSTR    pArgs;
    int            cbArgs;
    PFN_BOF_OUTPUT pfnOutput;
    PVOID          pUser;
} BOF_API_CTX, *PBOF_API_CTX;

void  BofApiInit(PBOF_API_CTX pCtx, PCSTR pArgs, int cbArgs,
                 PFN_BOF_OUTPUT pfnOutput, PVOID pUser);
void  BofApiRelease(PBOF_API_CTX pCtx);
PVOID BofApiResolve(PBOF_API_CTX pCtx, PCSTR szName);

/*
 * Packs "name,42" into the length-prefixed blob that BeaconDataParse expects:
 *   [total:4][len:4][bytes...][len:4][bytes...]
 * Tokens made only of digits (with an optional leading '-') become 32-bit
 * integers; everything else becomes a byte string.
 */
BOOL BofApiPackArgs(PCSTR szArguments, BYTE** ppBlob, DWORD* pcbBlob);
void BofApiFreeArgs(PVOID pBlob);
