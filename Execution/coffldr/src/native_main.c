#include "pex_native.h"

#include "bof_api.h"
#include "coff_core.h"

/*
 * Native entry for coffldr.
 *
 * The core and the BOF adapter are shared with the development build; this
 * file only supplies the host services (allocation, protection, resolution)
 * through the runtime pointers resolved at startup. There is no CRT, so the
 * command surface is limited to "run".
 */

#define TOOL_OUTPUT_MAX 65536

typedef struct _TOOL_CTX
{
    BOF_API_CTX BofApi;
    BYTE        abOutput[TOOL_OUTPUT_MAX];
    DWORD       cbOutput;
} TOOL_CTX, *PTOOL_CTX;

static TOOL_CTX g_Ctx;

static PVOID WINAPI ToolAlloc(PVOID pUser, SIZE_T cbSize)
{
    PBYTE pAnchor = (PBYTE)(ULONG_PTR)&ToolAlloc;
    DWORD i;

    (void)pUser;

    /* Keep the image within REL32 range of the loader. */
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

#define OBF_CHAR(c) ((BYTE)((c) ^ 0x41))

static const BYTE s_abKernel32[] =
{
    OBF_CHAR('k'), OBF_CHAR('e'), OBF_CHAR('r'), OBF_CHAR('n'), OBF_CHAR('e'),
    OBF_CHAR('l'), OBF_CHAR('3'), OBF_CHAR('2'), OBF_CHAR('.'), OBF_CHAR('d'),
    OBF_CHAR('l'), OBF_CHAR('l')
};

static const BYTE s_abAdvapi32[] =
{
    OBF_CHAR('a'), OBF_CHAR('d'), OBF_CHAR('v'), OBF_CHAR('a'), OBF_CHAR('p'),
    OBF_CHAR('i'), OBF_CHAR('3'), OBF_CHAR('2'), OBF_CHAR('.'), OBF_CHAR('d'),
    OBF_CHAR('l'), OBF_CHAR('l')
};

static const BYTE s_abUser32[] =
{
    OBF_CHAR('u'), OBF_CHAR('s'), OBF_CHAR('e'), OBF_CHAR('r'), OBF_CHAR('3'),
    OBF_CHAR('2'), OBF_CHAR('.'), OBF_CHAR('d'), OBF_CHAR('l'), OBF_CHAR('l')
};

static const BYTE s_abWs2_32[] =
{
    OBF_CHAR('w'), OBF_CHAR('s'), OBF_CHAR('2'), OBF_CHAR('_'), OBF_CHAR('3'),
    OBF_CHAR('2'), OBF_CHAR('.'), OBF_CHAR('d'), OBF_CHAR('l'), OBF_CHAR('l')
};

static const BYTE s_abNtdll[] =
{
    OBF_CHAR('n'), OBF_CHAR('t'), OBF_CHAR('d'), OBF_CHAR('l'), OBF_CHAR('l'),
    OBF_CHAR('.'), OBF_CHAR('d'), OBF_CHAR('l'), OBF_CHAR('l')
};

typedef struct _TOOL_MODULE
{
    const BYTE* pName;
    DWORD       cbName;
} TOOL_MODULE;

static const TOOL_MODULE s_aModules[] =
{
    { s_abKernel32, sizeof(s_abKernel32) },
    { s_abAdvapi32, sizeof(s_abAdvapi32) },
    { s_abUser32,   sizeof(s_abUser32) },
    { s_abWs2_32,   sizeof(s_abWs2_32) },
    { s_abNtdll,    sizeof(s_abNtdll) }
};

static HMODULE ToolGetModule(const TOOL_MODULE* pModule)
{
    CHAR  szName[32];
    DWORD i;
    HMODULE hModule;

    for (i = 0; i < pModule->cbName && i < sizeof(szName) - 1; i++)
    {
        szName[i] = (CHAR)(pModule->pName[i] ^ 0x41);
    }
    szName[i] = 0;

    hModule = (HMODULE)NativeGetModuleByHash(NativeHash(szName));
    if (hModule == NULL && g_pfnLoadLibraryA != NULL)
    {
        hModule = ((HMODULE (WINAPI*)(PCSTR))g_pfnLoadLibraryA)(szName);
    }
    return hModule;
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
    TOOL_CTX* pCtx = (TOOL_CTX*)pUser;
    PVOID     pAddress;
    DWORD     i;

    pAddress = BofApiResolve(&pCtx->BofApi, szName);
    if (pAddress != NULL) return pAddress;

    for (i = 0; i < sizeof(s_aModules) / sizeof(s_aModules[0]); i++)
    {
        HMODULE hModule = ToolGetModule(&s_aModules[i]);

        if (hModule == NULL) continue;

        pAddress = NativeGetProcFromModule(hModule, NativeHash(szName));
        if (pAddress == NULL) pAddress = ToolGetProcAddress(hModule, szName);
        if (pAddress != NULL) return pAddress;
    }

    return NULL;
}

static void WINAPI ToolLog(PVOID pUser, int nLevel, PCSTR szMessage)
{
    (void)pUser;
    (void)nLevel;
    (void)szMessage;
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

void NativeEntry(void)
{
    TOOL_CTX*   pCtx = &g_Ctx;
    COFF_OPS    ops;
    PCOFF_IMAGE pImage = NULL;
    PVOID       pObject = NULL;
    DWORD       cbObject = 0;
    BYTE*       pbArgs = NULL;
    DWORD       cbArgs = 0;
    COFF_STATUS status;
    PCSTR       szPath;
    PCSTR       szArguments;
    PCSTR       szEntry;
    if (!NativeInit()) NativeExit(1);
    if (NativeArgc() < 3) NativeExit(1);
    if (NativeHash(NativeArgv(1)) != HASH_RUN) NativeExit(1);

    szPath = NativeArgv(2);
    szArguments = NativeOptionValue(HASH___ARGS);
    szEntry = NativeOptionValue(HASH___ENTRY);
    if (!NativeReadFile(szPath, &pObject, &cbObject)) NativeExit(1);

    if (!BofApiPackArgs(szArguments, &pbArgs, &cbArgs))
    {
        ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pObject, 0, MEM_RELEASE);
        NativeExit(1);
    }
    ZeroMemory(pCtx, sizeof(*pCtx));
    BofApiInit(&pCtx->BofApi, (PCSTR)pbArgs, (int)cbArgs, ToolOutput, pCtx);

    ops.pfnAlloc = ToolAlloc;
    ops.pfnFree = ToolFree;
    ops.pfnProtect = ToolProtect;
    ops.pfnResolve = ToolResolve;
    ops.pfnLog = ToolLog;
    ops.pUser = pCtx;
    status = CoffLoadImage(pObject, cbObject, &ops, &pImage);
    if (status != COFF_OK)
    {
        BofApiRelease(&pCtx->BofApi);
        BofApiFreeArgs(pbArgs);
        ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pObject, 0, MEM_RELEASE);
        NativeExit(2);
    }
    status = CoffRunEntry(pImage, szEntry, (PCSTR)pbArgs, cbArgs, NULL);
    if (status != COFF_OK)
    {
        CoffFreeImage(pImage);
        BofApiRelease(&pCtx->BofApi);
        BofApiFreeArgs(pbArgs);
        ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pObject, 0, MEM_RELEASE);
        NativeExit(3);
    }

    if (pCtx->cbOutput != 0)
    {
        NativeWriteStdout((PCSTR)pCtx->abOutput, pCtx->cbOutput);
    }

    CoffFreeImage(pImage);
    BofApiRelease(&pCtx->BofApi);
    BofApiFreeArgs(pbArgs);
    ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pObject, 0, MEM_RELEASE);

    NativeExit(0);
}
