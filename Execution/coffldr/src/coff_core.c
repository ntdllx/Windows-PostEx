#include "coff_core.h"

#include <intrin.h>
#include <stdint.h>

/*
 * Implementation notes
 * --------------------
 *  - Sections are page-aligned on purpose. MSVC emits .text/.data/.rdata in a
 *    few hundred bytes each; packing them 16-byte aligned would place
 *    read-only, writable and executable bytes on the same page and make a real
 *    W^X split impossible. One page per section wastes at most a few KB.
 *  - Symbol resolution is cached per symbol index. A relocation-heavy object
 *    would otherwise ask the host for the same import dozens of times and
 *    allocate a new __imp_ slot for every reference.
 *  - The __imp_X convention belongs here, not in the host: the prefix is a COFF
 *    artifact. The host resolver sees the undecorated name and returns a
 *    function address; the core owns the pointer slot the object calls through.
 *  - The object buffer is only read during CoffLoadImage. The returned handle
 *    owns its own memory and does not alias the input.
 */

#define COFF_SYMBOL_STATE_EMPTY  0
#define COFF_SYMBOL_STATE_OK     1
#define COFF_SYMBOL_STATE_FAILED 2

#define COFF_PAGE_READ  0x1
#define COFF_PAGE_WRITE 0x2
#define COFF_PAGE_EXEC  0x4

#define COFF_MAX_IMAGE_BYTES (64u * 1024u * 1024u)

typedef struct _COFF_SYMBOL_SLOT
{
    PVOID pAddress;
    WORD  wSection;
    BYTE  bState;
    BYTE  bReserved;
} COFF_SYMBOL_SLOT, *PCOFF_SYMBOL_SLOT;

struct _COFF_IMAGE
{
    const COFF_OPS*    pOps;
    PBYTE              pBase;
    SIZE_T             cbTotal;
    SIZE_T             cbBlock;
    WORD               cSections;
    DWORD              cSymbols;
    PIMAGE_SYMBOL      pSymbolTable;
    PBYTE              pStringTable;
    DWORD              cbSymbolTable;
    DWORD              cbStringTable;
    PCOFF_SECTION_VIEW pSections;
    PDWORD             pdwSectionOffset;
    PCOFF_SYMBOL_SLOT  pSymbols;
    DWORD              cRelocations;
    DWORD              cExternals;
    DWORD              cImportSlots;
    DWORD              cbImportSlotsUsed;
};

/* ------------------------------------------------------------------ */
/* Freestanding memory helpers (no CRT linkage)                        */
/* ------------------------------------------------------------------ */

static void CoffZeroMemory(PVOID pDestination, SIZE_T cbSize)
{
    __stosb((PBYTE)pDestination, 0, cbSize);
}

static void CoffCopyMemory(PVOID pDestination, const VOID* pSource, SIZE_T cbSize)
{
    __movsb((PBYTE)pDestination, (const BYTE*)pSource, cbSize);
}

static BOOL CoffStringEqual(PCSTR szLeft, PCSTR szRight)
{
    while (*szLeft != 0 && *szLeft == *szRight)
    {
        szLeft++;
        szRight++;
    }
    return (*szLeft == *szRight);
}

static void CoffLog(PCOFF_IMAGE pImage, int nLevel, PCSTR szMessage)
{
    if (pImage != NULL && pImage->pOps != NULL && pImage->pOps->pfnLog != NULL)
    {
        pImage->pOps->pfnLog(pImage->pOps->pUser, nLevel, szMessage);
    }
}

/* ------------------------------------------------------------------ */
/* Symbols                                                             */
/* ------------------------------------------------------------------ */

static PCSTR CoffSymbolName(PCOFF_IMAGE pImage, PIMAGE_SYMBOL pSymbol,
                                  PCHAR szBuffer, DWORD cchBuffer)
{
    DWORD i;

    if (cchBuffer == 0)
    {
        return "";
    }

    if (pSymbol->N.Name.Short != 0)
    {
        for (i = 0; i < 8 && (i + 1) < cchBuffer; i++)
        {
            szBuffer[i] = pSymbol->N.ShortName[i];
            if (szBuffer[i] == 0) break;
        }
        szBuffer[i] = 0;
        return szBuffer;
    }

    if (pImage->pStringTable != NULL && pSymbol->N.Name.Long < pImage->cbStringTable)
    {
        return (PCSTR)(pImage->pStringTable + pSymbol->N.Name.Long);
    }

    szBuffer[0] = 0;
    return szBuffer;
}

static COFF_STATUS CoffAllocateImportSlot(PCOFF_IMAGE pImage, PVOID pAddress, PVOID* ppSlot)
{
    PBYTE pSlot;

    if (pImage->cbImportSlotsUsed + sizeof(PVOID) > COFF_IMPORT_RESERVE)
    {
        return COFF_ERR_MEMORY;
    }

    pSlot = pImage->pBase + pImage->cbImportSlotsUsed;
    *(PVOID*)pSlot = pAddress;
    pImage->cbImportSlotsUsed += (DWORD)sizeof(PVOID);
    pImage->cImportSlots++;

    *ppSlot = pSlot;
    return COFF_OK;
}

static COFF_STATUS CoffResolveSymbol(PCOFF_IMAGE pImage, DWORD dwIndex,
                                     PVOID* ppAddress, PWORD pwSection)
{
    PIMAGE_SYMBOL     pSymbol;
    PCOFF_SYMBOL_SLOT pSlot;
    char              szNameBuffer[256];
    PCSTR       szName;
    PCSTR       szResolveName;
    BOOL              bImport;
    PVOID             pAddress;

    *ppAddress = NULL;
    *pwSection = 0;

    if (dwIndex >= pImage->cSymbols || pImage->pSymbolTable == NULL)
    {
        return COFF_ERR_SYMBOL;
    }

    pSlot = &pImage->pSymbols[dwIndex];
    if (pSlot->bState == COFF_SYMBOL_STATE_OK)
    {
        *ppAddress = pSlot->pAddress;
        *pwSection = pSlot->wSection;
        return COFF_OK;
    }
    if (pSlot->bState == COFF_SYMBOL_STATE_FAILED)
    {
        return COFF_ERR_SYMBOL;
    }

    pSymbol = &pImage->pSymbolTable[dwIndex];

    if (pSymbol->SectionNumber > 0)
    {
        if ((WORD)pSymbol->SectionNumber > pImage->cSections)
        {
            pSlot->bState = COFF_SYMBOL_STATE_FAILED;
            return COFF_ERR_SYMBOL;
        }
        pSlot->wSection = (WORD)pSymbol->SectionNumber;
        pSlot->pAddress = (PBYTE)pImage->pSections[pSymbol->SectionNumber - 1].pBase + pSymbol->Value;
        pSlot->bState = COFF_SYMBOL_STATE_OK;
        *ppAddress = pSlot->pAddress;
        *pwSection = pSlot->wSection;
        return COFF_OK;
    }

    if (pSymbol->SectionNumber == IMAGE_SYM_ABSOLUTE)
    {
        pSlot->pAddress = (PVOID)(ULONG_PTR)pSymbol->Value;
        pSlot->bState = COFF_SYMBOL_STATE_OK;
        *ppAddress = pSlot->pAddress;
        return COFF_OK;
    }

    if (pSymbol->SectionNumber != IMAGE_SYM_UNDEFINED)
    {
        /* Debug records and other non-addressable symbol classes. */
        pSlot->bState = COFF_SYMBOL_STATE_FAILED;
        return COFF_ERR_SYMBOL;
    }

    szName = CoffSymbolName(pImage, pSymbol, szNameBuffer, sizeof(szNameBuffer));
    if (szName[0] == 0)
    {
        pSlot->bState = COFF_SYMBOL_STATE_FAILED;
        return COFF_ERR_SYMBOL;
    }

    bImport = FALSE;
    szResolveName = szName;
    if (szName[0] == '_' && szName[1] == '_' && szName[2] == 'i' &&
        szName[3] == 'm' && szName[4] == 'p' && szName[5] == '_')
    {
        bImport = TRUE;
        szResolveName = szName + 6;
    }

    if (CoffStringEqual(szResolveName, "__ImageBase"))
    {
        pAddress = pImage->pBase;
    }
    else
    {
        if (pImage->pOps->pfnResolve == NULL)
        {
            pSlot->bState = COFF_SYMBOL_STATE_FAILED;
            return COFF_ERR_SYMBOL;
        }
        pAddress = pImage->pOps->pfnResolve(pImage->pOps->pUser, szResolveName);
        pImage->cExternals++;
    }

    if (pAddress == NULL)
    {
        pSlot->bState = COFF_SYMBOL_STATE_FAILED;
        return COFF_ERR_SYMBOL;
    }

    if (bImport)
    {
        COFF_STATUS status = CoffAllocateImportSlot(pImage, pAddress, &pAddress);
        if (status != COFF_OK)
        {
            pSlot->bState = COFF_SYMBOL_STATE_FAILED;
            return status;
        }
    }

    pSlot->pAddress = pAddress;
    pSlot->bState = COFF_SYMBOL_STATE_OK;
    *ppAddress = pAddress;
    return COFF_OK;
}

/* ------------------------------------------------------------------ */
/* Mapping                                                             */
/* ------------------------------------------------------------------ */

static COFF_STATUS CoffMapSections(PCOFF_IMAGE pImage, const VOID* pObject, SIZE_T cbObject)
{
    PIMAGE_SECTION_HEADER pSectionHeaders;
    SIZE_T                cbOffset;
    WORD                  i;
    WORD                  j;

    pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pObject + sizeof(IMAGE_FILE_HEADER));
    cbOffset = COFF_IMPORT_RESERVE;

    for (i = 0; i < pImage->cSections; i++)
    {
        PIMAGE_SECTION_HEADER pHeader = &pSectionHeaders[i];
        PCOFF_SECTION_VIEW    pView = &pImage->pSections[i];
        SIZE_T                cbSection;

        cbSection = ((pHeader->Characteristics & IMAGE_SCN_LNK_REMOVE) != 0)
                        ? 0
                        : (SIZE_T)pHeader->SizeOfRawData;

        pImage->pdwSectionOffset[i] = (DWORD)cbOffset;
        pView->pBase = pImage->pBase + cbOffset;
        pView->cbSize = (DWORD)cbSection;
        pView->flCharacteristics = pHeader->Characteristics;
        pView->flProtect = PAGE_NOACCESS;

        for (j = 0; j < 8; j++)
        {
            pView->szName[j] = (char)pHeader->Name[j];
            if (pView->szName[j] == 0) break;
        }
        pView->szName[8] = 0;

        if (cbSection != 0 && pHeader->PointerToRawData != 0)
        {
            if ((SIZE_T)pHeader->PointerToRawData + cbSection > cbObject)
            {
                return COFF_ERR_FORMAT;
            }
            CoffCopyMemory(pView->pBase, (const BYTE*)pObject + pHeader->PointerToRawData, cbSection);
        }

        cbOffset += (cbSection + COFF_PAGE_SIZE - 1) & ~(SIZE_T)(COFF_PAGE_SIZE - 1);
    }

    return COFF_OK;
}

/* ------------------------------------------------------------------ */
/* Relocations                                                         */
/* ------------------------------------------------------------------ */

static DWORD CoffRelocationWidth(WORD wType)
{
    switch (wType)
    {
    case IMAGE_REL_AMD64_ADDR64:   return 8;
    case IMAGE_REL_AMD64_ADDR32:
    case IMAGE_REL_AMD64_ADDR32NB:
    case IMAGE_REL_AMD64_REL32:
    case IMAGE_REL_AMD64_REL32_1:
    case IMAGE_REL_AMD64_REL32_2:
    case IMAGE_REL_AMD64_REL32_3:
    case IMAGE_REL_AMD64_REL32_4:
    case IMAGE_REL_AMD64_REL32_5:
    case IMAGE_REL_AMD64_SECREL:   return 4;
    case IMAGE_REL_AMD64_SECTION:  return 2;
    case IMAGE_REL_AMD64_SECREL7:  return 1;
    default:                       return 0;
    }
}

static COFF_STATUS CoffApplyRelocations(PCOFF_IMAGE pImage, const VOID* pObject, SIZE_T cbObject)
{
    PIMAGE_SECTION_HEADER pSectionHeaders;
    WORD                  i;

    pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pObject + sizeof(IMAGE_FILE_HEADER));

    for (i = 0; i < pImage->cSections; i++)
    {
        PIMAGE_SECTION_HEADER pHeader = &pSectionHeaders[i];
        PIMAGE_RELOCATION     pRelocations;
        WORD                  j;

        if (pHeader->NumberOfRelocations == 0 || pHeader->PointerToRelocations == 0)
        {
            continue;
        }
        if ((SIZE_T)pHeader->PointerToRelocations +
                (SIZE_T)pHeader->NumberOfRelocations * sizeof(IMAGE_RELOCATION) > cbObject)
        {
            return COFF_ERR_FORMAT;
        }

        pRelocations = (PIMAGE_RELOCATION)((PBYTE)pObject + pHeader->PointerToRelocations);

        for (j = 0; j < pHeader->NumberOfRelocations; j++)
        {
            PIMAGE_RELOCATION pRelocation = &pRelocations[j];
            PCOFF_SECTION_VIEW pView = &pImage->pSections[i];
            WORD              wType = pRelocation->Type;
            DWORD             cbWidth;
            PBYTE             pTarget;
            PVOID             pSymbolAddress;
            WORD              wSymbolSection;
            COFF_STATUS       status;

            if (wType == IMAGE_REL_AMD64_ABSOLUTE)
            {
                continue;
            }

            cbWidth = CoffRelocationWidth(wType);
            if (cbWidth == 0)
            {
                return COFF_ERR_RELOCATION;
            }
            if ((SIZE_T)pRelocation->VirtualAddress + cbWidth > pView->cbSize)
            {
                return COFF_ERR_RELOCATION;
            }

            status = CoffResolveSymbol(pImage, pRelocation->SymbolTableIndex,
                                       &pSymbolAddress, &wSymbolSection);
            if (status != COFF_OK)
            {
                return status;
            }

            pTarget = (PBYTE)pView->pBase + pRelocation->VirtualAddress;

            switch (wType)
            {
            case IMAGE_REL_AMD64_ADDR64:
                *(UINT64*)pTarget = *(UINT64*)pTarget + (UINT64)(ULONG_PTR)pSymbolAddress;
                break;

            case IMAGE_REL_AMD64_ADDR32:
                *(UINT32*)pTarget = *(UINT32*)pTarget + (UINT32)(ULONG_PTR)pSymbolAddress;
                break;

            case IMAGE_REL_AMD64_ADDR32NB:
                *(UINT32*)pTarget = *(UINT32*)pTarget +
                                    (UINT32)((ULONG_PTR)pSymbolAddress - (ULONG_PTR)pImage->pBase);
                break;

            case IMAGE_REL_AMD64_REL32:
            case IMAGE_REL_AMD64_REL32_1:
            case IMAGE_REL_AMD64_REL32_2:
            case IMAGE_REL_AMD64_REL32_3:
            case IMAGE_REL_AMD64_REL32_4:
            case IMAGE_REL_AMD64_REL32_5:
            {
                INT64 i64Delta = (INT64)(ULONG_PTR)pSymbolAddress + (INT64)*(INT32*)pTarget -
                                 (INT64)(ULONG_PTR)pTarget - 4 -
                                 (INT64)(wType - IMAGE_REL_AMD64_REL32);

                if (i64Delta > INT32_MAX || i64Delta < INT32_MIN)
                {
                    return COFF_ERR_RELOCATION;
                }
                *(INT32*)pTarget = (INT32)i64Delta;
                break;
            }

            case IMAGE_REL_AMD64_SECTION:
                if (wSymbolSection == 0) return COFF_ERR_RELOCATION;
                *(UINT16*)pTarget = wSymbolSection;
                break;

            case IMAGE_REL_AMD64_SECREL:
                if (wSymbolSection == 0) return COFF_ERR_RELOCATION;
                *(UINT32*)pTarget = (UINT32)((ULONG_PTR)pSymbolAddress -
                                             (ULONG_PTR)pImage->pSections[wSymbolSection - 1].pBase);
                break;

            case IMAGE_REL_AMD64_SECREL7:
                if (wSymbolSection == 0) return COFF_ERR_RELOCATION;
                *(BYTE*)pTarget = (BYTE)((ULONG_PTR)pSymbolAddress -
                                         (ULONG_PTR)pImage->pSections[wSymbolSection - 1].pBase);
                break;

            default:
                return COFF_ERR_RELOCATION;
            }

            pImage->cRelocations++;
        }
    }

    return COFF_OK;
}

/* ------------------------------------------------------------------ */
/* Protection                                                          */
/* ------------------------------------------------------------------ */

static COFF_STATUS CoffProtectSections(PCOFF_IMAGE pImage)
{
    DWORD cPages = (DWORD)((pImage->cbTotal + COFF_PAGE_SIZE - 1) >> 12);
    DWORD dwPage;

    for (dwPage = 0; dwPage < cPages; dwPage++)
    {
        SIZE_T cbPageStart = (SIZE_T)dwPage * COFF_PAGE_SIZE;
        SIZE_T cbPageEnd = cbPageStart + COFF_PAGE_SIZE;
        DWORD  flFlags = (dwPage == 0) ? COFF_PAGE_READ : 0;
        DWORD  flProtect;
        WORD   i;

        for (i = 0; i < pImage->cSections; i++)
        {
            PCOFF_SECTION_VIEW pView = &pImage->pSections[i];
            SIZE_T             cbSectionStart = pImage->pdwSectionOffset[i];
            SIZE_T             cbSectionEnd = cbSectionStart + pView->cbSize;

            if (pView->cbSize == 0) continue;
            if (cbSectionStart >= cbPageEnd || cbSectionEnd <= cbPageStart) continue;

            flFlags |= COFF_PAGE_READ;
            if ((pView->flCharacteristics & IMAGE_SCN_MEM_EXECUTE) != 0) flFlags |= COFF_PAGE_EXEC;
            if ((pView->flCharacteristics & IMAGE_SCN_MEM_WRITE) != 0) flFlags |= COFF_PAGE_WRITE;
        }

        if ((flFlags & COFF_PAGE_EXEC) != 0 && (flFlags & COFF_PAGE_WRITE) != 0)
        {
#ifndef PEX_NATIVE
            CoffLog(pImage, COFF_LOG_ERROR, "refusing to map a writable+executable page");
#endif
            return COFF_ERR_RWX;
        }

        if ((flFlags & COFF_PAGE_EXEC) != 0)
        {
            flProtect = PAGE_EXECUTE_READ;
        }
        else if ((flFlags & COFF_PAGE_WRITE) != 0)
        {
            flProtect = PAGE_READWRITE;
        }
        else
        {
            flProtect = PAGE_READONLY;
        }

        if (!pImage->pOps->pfnProtect(pImage->pOps->pUser,
                                      pImage->pBase + cbPageStart,
                                      COFF_PAGE_SIZE, flProtect))
        {
            return COFF_ERR_PROTECT;
        }

        for (i = 0; i < pImage->cSections; i++)
        {
            PCOFF_SECTION_VIEW pView = &pImage->pSections[i];
            SIZE_T cbSectionStart = pImage->pdwSectionOffset[i];
            SIZE_T cbSectionEnd = cbSectionStart + pView->cbSize;

            if (pView->cbSize == 0) continue;
            if (cbSectionStart < cbPageEnd && cbSectionEnd > cbPageStart)
            {
                pView->flProtect = flProtect;
            }
        }
    }

    return COFF_OK;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

COFF_STATUS CoffLoadImage(const VOID* pObject, SIZE_T cbObject,
                          const COFF_OPS* pOps, PCOFF_IMAGE* ppImage)
{
    PIMAGE_FILE_HEADER pHeader;
    PCOFF_IMAGE        pImage = NULL;
    SIZE_T             cbTotal;
    SIZE_T             cbBlock;
    DWORD              cbSymbolTable;
    DWORD              cbStringTable;
    WORD               i;

    if (ppImage == NULL) return COFF_ERR_ARGUMENT;
    *ppImage = NULL;

    if (pObject == NULL || cbObject < sizeof(IMAGE_FILE_HEADER)) return COFF_ERR_ARGUMENT;
    if (pOps == NULL || pOps->pfnAlloc == NULL || pOps->pfnFree == NULL ||
        pOps->pfnProtect == NULL)
    {
        return COFF_ERR_ARGUMENT;
    }

    pHeader = (PIMAGE_FILE_HEADER)pObject;
    if (pHeader->Machine != IMAGE_FILE_MACHINE_AMD64) return COFF_ERR_MACHINE;
    if (pHeader->SizeOfOptionalHeader != 0) return COFF_ERR_FORMAT;
    if (pHeader->NumberOfSections == 0 ||
        pHeader->NumberOfSections > COFF_MAX_SECTIONS) return COFF_ERR_FORMAT;

    if ((SIZE_T)sizeof(IMAGE_FILE_HEADER) +
            (SIZE_T)pHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > cbObject)
    {
        return COFF_ERR_FORMAT;
    }

    /* ---- size the page-aligned image ---- */
    cbTotal = COFF_IMPORT_RESERVE;
    for (i = 0; i < pHeader->NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER pSectionHeader =
            &((PIMAGE_SECTION_HEADER)((PBYTE)pObject + sizeof(IMAGE_FILE_HEADER)))[i];
        SIZE_T cbSection;

        cbSection = ((pSectionHeader->Characteristics & IMAGE_SCN_LNK_REMOVE) != 0)
                        ? 0
                        : (SIZE_T)pSectionHeader->SizeOfRawData;
        cbTotal += (cbSection + COFF_PAGE_SIZE - 1) & ~(SIZE_T)(COFF_PAGE_SIZE - 1);

        if (cbTotal > COFF_MAX_IMAGE_BYTES) return COFF_ERR_FORMAT;
    }

    /* ---- symbol/string table sizes ---- */
    cbSymbolTable = 0;
    cbStringTable = 0;
    if (pHeader->PointerToSymbolTable != 0 && pHeader->NumberOfSymbols != 0)
    {
        SIZE_T cbSymbolBytes = (SIZE_T)pHeader->NumberOfSymbols * sizeof(IMAGE_SYMBOL);

        if ((SIZE_T)pHeader->PointerToSymbolTable + cbSymbolBytes > cbObject)
        {
            return COFF_ERR_FORMAT;
        }
        cbSymbolTable = (DWORD)cbSymbolBytes;

        if ((SIZE_T)pHeader->PointerToSymbolTable + cbSymbolBytes + 4 <= cbObject)
        {
            DWORD cbDeclared = *(DWORD*)((PBYTE)pObject + pHeader->PointerToSymbolTable + cbSymbolBytes);

            cbStringTable = (DWORD)(cbObject -
                ((SIZE_T)pHeader->PointerToSymbolTable + cbSymbolBytes));
            if (cbDeclared < cbStringTable) cbStringTable = cbDeclared;
            if (cbStringTable < 4) cbStringTable = 0;
        }
    }

    /* The handle block is page-aligned so that pBase lands on a page boundary;
     * the page-based protection pass depends on it. The symbol and string
     * tables are copied in so the returned handle never aliases the input. */
    cbBlock = sizeof(COFF_IMAGE) +
              (SIZE_T)pHeader->NumberOfSections * (sizeof(DWORD) + sizeof(COFF_SECTION_VIEW)) +
              (SIZE_T)pHeader->NumberOfSymbols * sizeof(COFF_SYMBOL_SLOT) +
              cbSymbolTable + cbStringTable;
    cbBlock = (cbBlock + COFF_PAGE_SIZE - 1) & ~(SIZE_T)(COFF_PAGE_SIZE - 1);

    pImage = (PCOFF_IMAGE)pOps->pfnAlloc(pOps->pUser, cbBlock + cbTotal);
    if (pImage == NULL) return COFF_ERR_MEMORY;
    CoffZeroMemory(pImage, cbBlock + cbTotal);

    pImage->pOps = pOps;
    pImage->pBase = (PBYTE)pImage + cbBlock;
    pImage->cbTotal = cbTotal;
    pImage->cbBlock = cbBlock;
    pImage->cSections = pHeader->NumberOfSections;
    pImage->cSymbols = pHeader->NumberOfSymbols;

    pImage->pdwSectionOffset = (PDWORD)(pImage + 1);
    pImage->pSections = (PCOFF_SECTION_VIEW)(pImage->pdwSectionOffset + pImage->cSections);
    pImage->pSymbols = (PCOFF_SYMBOL_SLOT)(pImage->pSections + pImage->cSections);

    /* ---- copy the symbol and string tables into the handle ---- */
    if (cbSymbolTable != 0)
    {
        pImage->cbSymbolTable = cbSymbolTable;
        pImage->cbStringTable = cbStringTable;
        pImage->pSymbolTable = (PIMAGE_SYMBOL)(pImage->pSymbols + pImage->cSymbols);
        CoffCopyMemory(pImage->pSymbolTable,
                       (const BYTE*)pObject + pHeader->PointerToSymbolTable,
                       cbSymbolTable);

        if (cbStringTable != 0)
        {
            pImage->pStringTable = (PBYTE)pImage->pSymbolTable + cbSymbolTable;
            CoffCopyMemory(pImage->pStringTable,
                           (const BYTE*)pObject + pHeader->PointerToSymbolTable + cbSymbolTable,
                           cbStringTable);
        }
        else
        {
            pImage->pStringTable = NULL;
        }
    }

    {
        COFF_STATUS status;

        status = CoffMapSections(pImage, pObject, cbObject);
        if (status == COFF_OK) status = CoffApplyRelocations(pImage, pObject, cbObject);
        if (status == COFF_OK) status = CoffProtectSections(pImage);

        if (status != COFF_OK)
        {
            pOps->pfnFree(pOps->pUser, pImage, cbBlock + cbTotal);
            return status;
        }
    }

    *ppImage = pImage;
    return COFF_OK;
}

COFF_STATUS CoffGetStats(PCOFF_IMAGE pImage, PCOFF_STATS pStats)
{
    if (pImage == NULL || pStats == NULL) return COFF_ERR_ARGUMENT;

    pStats->cSections = pImage->cSections;
    pStats->cSymbols = pImage->cSymbols;
    pStats->cRelocations = pImage->cRelocations;
    pStats->cExternals = pImage->cExternals;
    pStats->cImportSlots = pImage->cImportSlots;
    pStats->cbImage = (DWORD)pImage->cbTotal;
    return COFF_OK;
}

COFF_STATUS CoffGetSection(PCOFF_IMAGE pImage, DWORD dwIndex, PCOFF_SECTION_VIEW pView)
{
    if (pImage == NULL || pView == NULL) return COFF_ERR_ARGUMENT;
    if (dwIndex >= pImage->cSections) return COFF_ERR_ARGUMENT;

    *pView = pImage->pSections[dwIndex];
    return COFF_OK;
}

COFF_STATUS CoffFindEntry(PCOFF_IMAGE pImage, PCSTR szName, PVOID* ppEntry)
{
    DWORD       i;
    PCSTR szWanted;

    if (pImage == NULL || ppEntry == NULL) return COFF_ERR_ARGUMENT;
    *ppEntry = NULL;

    if (pImage->pSymbolTable == NULL) return COFF_ERR_ENTRY;

    szWanted = (szName != NULL) ? szName : "go";

    i = 0;
    while (i < pImage->cSymbols)
    {
        PIMAGE_SYMBOL pSymbol = &pImage->pSymbolTable[i];
        char          szNameBuffer[256];
        PCSTR   szSymbol = CoffSymbolName(pImage, pSymbol, szNameBuffer,
                                                sizeof(szNameBuffer));

        if (pSymbol->SectionNumber > 0 && CoffStringEqual(szSymbol, szWanted))
        {
            if ((WORD)pSymbol->SectionNumber > pImage->cSections)
            {
                return COFF_ERR_ENTRY;
            }
            *ppEntry = (PBYTE)pImage->pSections[pSymbol->SectionNumber - 1].pBase + pSymbol->Value;
            return COFF_OK;
        }

        i += 1 + pSymbol->NumberOfAuxSymbols;
    }

    return COFF_ERR_ENTRY;
}

COFF_STATUS CoffRunEntry(PCOFF_IMAGE pImage, PCSTR szName,
                         PCSTR pArgs, DWORD cbArgs, DWORD* pdwExitCode)
{
    typedef void (*PFN_COFF_ENTRY)(PCHAR pArgBuffer, int cbArgBuffer);

    COFF_STATUS status;
    PVOID       pEntry = NULL;

    if (pdwExitCode != NULL) *pdwExitCode = 0;

    status = CoffFindEntry(pImage, szName, &pEntry);
    if (status != COFF_OK) return status;

    ((PFN_COFF_ENTRY)pEntry)((PCHAR)pArgs, (int)cbArgs);
    return COFF_OK;
}

void CoffFreeImage(PCOFF_IMAGE pImage)
{
    const COFF_OPS* pOps;

    if (pImage == NULL) return;

    pOps = pImage->pOps;
    if (pOps != NULL && pOps->pfnFree != NULL)
    {
        pOps->pfnFree(pOps->pUser, pImage, pImage->cbBlock + pImage->cbTotal);
    }
}

#ifndef PEX_NATIVE
PCSTR CoffStatusName(COFF_STATUS status)
{
    switch (status)
    {
    case COFF_OK:              return "ok";
    case COFF_ERR_ARGUMENT:    return "bad argument";
    case COFF_ERR_FORMAT:      return "malformed object";
    case COFF_ERR_MACHINE:     return "unsupported machine";
    case COFF_ERR_MEMORY:      return "out of memory";
    case COFF_ERR_SYMBOL:      return "unresolved symbol";
    case COFF_ERR_RELOCATION:  return "bad relocation";
    case COFF_ERR_PROTECT:     return "protection failure";
    case COFF_ERR_RWX:         return "writable+executable section refused";
    case COFF_ERR_ENTRY:       return "entry point not found";
    default:                   return "unknown";
    }
}
#endif
