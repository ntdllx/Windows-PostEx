#pragma once

#include <windows.h>

/*
 * coff_core -- a COFF object mapper with no knowledge of its host.
 *
 * The core parses an AMD64 COFF object, lays the sections out page-aligned,
 * resolves symbols through a caller-supplied callback, applies relocations,
 * and hands back a callable address. It does not allocate with the CRT, does
 * not print, and does not know what a BOF is or which host it runs under.
 *
 * Layering rule: tool -> core -> (allocator / resolver / protector injected by
 * the tool). Everything host-specific lives on the other side of COFF_OPS.
 */

#define COFF_MAX_SECTIONS       96
#define COFF_IMPORT_RESERVE     0x1000
#define COFF_PAGE_SIZE          0x1000

typedef enum _COFF_STATUS
{
    COFF_OK = 0,
    COFF_ERR_ARGUMENT = 1,
    COFF_ERR_FORMAT = 2,
    COFF_ERR_MACHINE = 3,
    COFF_ERR_MEMORY = 4,
    COFF_ERR_SYMBOL = 5,
    COFF_ERR_RELOCATION = 6,
    COFF_ERR_PROTECT = 7,
    COFF_ERR_RWX = 8,
    COFF_ERR_ENTRY = 9
} COFF_STATUS;

#define COFF_LOG_ERROR 0
#define COFF_LOG_WARN  1
#define COFF_LOG_INFO  2

typedef PVOID (WINAPI* PFN_COFF_ALLOC)(PVOID pUser, SIZE_T cbSize);
typedef void  (WINAPI* PFN_COFF_FREE)(PVOID pUser, PVOID pMemory, SIZE_T cbSize);
typedef BOOL  (WINAPI* PFN_COFF_PROTECT)(PVOID pUser, PVOID pAddress, SIZE_T cbSize, DWORD flProtect);
typedef PVOID (WINAPI* PFN_COFF_RESOLVE)(PVOID pUser, PCSTR szName);
typedef void  (WINAPI* PFN_COFF_LOG)(PVOID pUser, int nLevel, PCSTR szMessage);

typedef struct _COFF_OPS
{
    PFN_COFF_ALLOC   pfnAlloc;
    PFN_COFF_FREE    pfnFree;
    PFN_COFF_PROTECT pfnProtect;
    PFN_COFF_RESOLVE pfnResolve;
    PFN_COFF_LOG     pfnLog;      /* optional */
    PVOID            pUser;
} COFF_OPS;

typedef struct _COFF_IMAGE COFF_IMAGE, *PCOFF_IMAGE;

typedef struct _COFF_SECTION_VIEW
{
    char  szName[9];
    PVOID pBase;
    DWORD cbSize;
    DWORD flCharacteristics;
    DWORD flProtect;
} COFF_SECTION_VIEW, *PCOFF_SECTION_VIEW;

typedef struct _COFF_STATS
{
    DWORD cSections;
    DWORD cSymbols;
    DWORD cRelocations;
    DWORD cExternals;
    DWORD cImportSlots;
    DWORD cbImage;
} COFF_STATS, *PCOFF_STATS;

/*
 * Loads and relocates an object. On success the caller owns *ppImage and must
 * release it with CoffFreeImage. Every section is mapped read-only, read/write
 * or read/execute; a section that would require write+execute is refused with
 * COFF_ERR_RWX instead of being mapped RWX.
 */
COFF_STATUS CoffLoadImage(const VOID* pImage, SIZE_T cbImage,
                          const COFF_OPS* pOps, PCOFF_IMAGE* ppImage);

COFF_STATUS CoffGetStats(PCOFF_IMAGE pImage, PCOFF_STATS pStats);
COFF_STATUS CoffGetSection(PCOFF_IMAGE pImage, DWORD dwIndex, PCOFF_SECTION_VIEW pView);

/* Looks up a defined symbol and returns its absolute address. */
COFF_STATUS CoffFindEntry(PCOFF_IMAGE pImage, PCSTR szName, PVOID* ppEntry);

/* Calls the entry with the (PCHAR args, int len) convention. */
COFF_STATUS CoffRunEntry(PCOFF_IMAGE pImage, PCSTR szName,
                         PCSTR pArgs, DWORD cbArgs, DWORD* pdwExitCode);

void        CoffFreeImage(PCOFF_IMAGE pImage);
PCSTR CoffStatusName(COFF_STATUS status);
