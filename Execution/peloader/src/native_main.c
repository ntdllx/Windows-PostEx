#include "pex_native.h"
#include "pex_syscall.h"

#include "mapper.h"

/* Option and value hashes:
 *   "--mode" 0x74310A04  "--host" 0x742E4E1D  "--export" 0x329BFC81
 *   "image"  0x0D535408  "stomp"  0x0E0C5C18
 */
#define PEX_OPT_MODE    0x74310A04UL
#define PEX_OPT_HOST    0x742E4E1DUL
#define PEX_OPT_EXPORT  0x329BFC81UL
#define PEX_VAL_IMAGE   0x0D535408UL
#define PEX_VAL_STOMP   0x0E0C5C18UL

static DWORD PelNativeFlags(VOID* pBase)
{
    MEMORY_BASIC_INFORMATION mbi;
    HMODULE hOwner = NULL;
    DWORD   dwFlags = 0;

    if (((SIZE_T (WINAPI*)(PVOID, PMEMORY_BASIC_INFORMATION, SIZE_T))g_pfnVirtualQuery)(
            pBase, &mbi, sizeof(mbi)) != 0 &&
        mbi.Type == MEM_IMAGE)
    {
        dwFlags |= 1;
    }

    if (((BOOL (WINAPI*)(DWORD, PCSTR, HMODULE*))g_pfnGetModuleHandleExA)(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (PCSTR)pBase, &hOwner))
    {
        dwFlags |= 2;
        ((BOOL (WINAPI*)(HMODULE))g_pfnFreeLibrary)(hOwner);
    }

    return dwFlags;
}

void NativeEntry(void)
{
    PEX_SYSCALL sys;
    PEL_IMAGE   image;
    CHAR        szError[1];
    PCSTR       szPath;
    PCSTR       szMode;
    PCSTR       szHost;
    PCSTR       szExport;
    PEL_MODE    mode = PEL_MODE_IMAGE;
    ULONG_PTR   ulValue = 0;

    if (!NativeInit()) NativeExit(1);
    if (!PexSysInit(&sys)) NativeExit(2);

    szPath = NativeArgv(2);
    if (szPath == NULL) NativeExit(1);

    szMode = NativeOptionValue(PEX_OPT_MODE);
    if (szMode != NULL && NativeHash(szMode) == PEX_VAL_STOMP)
    {
        mode = PEL_MODE_STOMP;
    }

    szHost = NativeOptionValue(PEX_OPT_HOST);
    szExport = NativeOptionValue(PEX_OPT_EXPORT);

    if (!PelMapFile(&sys, szPath, mode, szHost, &image, szError, sizeof(szError)))
    {
        NativeExit(3);
    }

    NativePrintHex((ULONG_PTR)image.pBase);
    NativePrintChar('\n');
    NativePrintHex((ULONG_PTR)PelNativeFlags(image.pBase));
    NativePrintChar('\n');

    if (szExport != NULL && PelInvoke(&image, szExport, &ulValue))
    {
        NativePrintHex(ulValue);
        NativePrintChar('\n');
    }

    PelRelease(&image);
    NativeExit(0);
}
