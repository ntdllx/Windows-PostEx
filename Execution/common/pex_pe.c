#include "pex_pe.h"
#include "pex_native.h"

/*
 * All helpers take the full image size so that a truncated or corrupted file
 * is rejected instead of walking off the end of the buffer. The caller passes
 * SizeOfImage for mapped images.
 */

static PIMAGE_NT_HEADERS PexPeNtHeaders(PVOID pImage, DWORD cbImage)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImage;
    PIMAGE_NT_HEADERS pNt;

    if (pImage == NULL || cbImage < sizeof(IMAGE_DOS_HEADER)) return NULL;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    if (pDos->e_lfanew < 0 || (DWORD)pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > cbImage) return NULL;

    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pImage + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (pNt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return NULL;
    if (pNt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return NULL;

    return pNt;
}

BOOL PexPeValidate(PVOID pImage, DWORD cbImage, PEX_PE_LAYOUT layout)
{
    PIMAGE_NT_HEADERS     pNt;
    PIMAGE_SECTION_HEADER pSection;
    WORD                  i;

    pNt = PexPeNtHeaders(pImage, cbImage);
    if (pNt == NULL) return FALSE;

    if (pNt->FileHeader.NumberOfSections == 0) return FALSE;

    if (layout == PEX_PE_MAPPED)
    {
        if (pNt->OptionalHeader.SizeOfImage > cbImage) return FALSE;
    }

    pSection = IMAGE_FIRST_SECTION(pNt);
    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {
        SIZE_T cbSection = pSection[i].Misc.VirtualSize;
        if (pSection[i].SizeOfRawData > cbSection) cbSection = pSection[i].SizeOfRawData;

        if (pSection[i].VirtualAddress + cbSection > pNt->OptionalHeader.SizeOfImage)
        {
            return FALSE;
        }
        if (layout == PEX_PE_FILE && pSection[i].SizeOfRawData != 0 &&
            (SIZE_T)pSection[i].PointerToRawData + pSection[i].SizeOfRawData > cbImage)
        {
            return FALSE;
        }
    }

    return TRUE;
}

BOOL PexPeRvaToOffset(PVOID pImage, DWORD cbImage, DWORD dwRva, PDWORD pdwOffset)
{
    PIMAGE_NT_HEADERS     pNt;
    PIMAGE_SECTION_HEADER pSection;
    WORD                  i;

    if (pdwOffset == NULL) return FALSE;
    *pdwOffset = 0;

    pNt = PexPeNtHeaders(pImage, cbImage);
    if (pNt == NULL) return FALSE;

    if (dwRva < pNt->OptionalHeader.SizeOfHeaders)
    {
        *pdwOffset = dwRva;
        return TRUE;
    }

    pSection = IMAGE_FIRST_SECTION(pNt);
    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {
        DWORD dwStart = pSection[i].VirtualAddress;
        DWORD cbRaw = pSection[i].SizeOfRawData;

        if (dwRva >= dwStart && dwRva < dwStart + cbRaw)
        {
            *pdwOffset = pSection[i].PointerToRawData + (dwRva - dwStart);
            return (*pdwOffset < cbImage);
        }
    }

    return FALSE;
}

static BOOL PexPeRvaToPointer(PVOID pImage, DWORD cbImage, PEX_PE_LAYOUT layout,
                               DWORD dwRva, PVOID* ppPointer)
{
    DWORD dwOffset;

    if (ppPointer == NULL) return FALSE;

    if (layout == PEX_PE_MAPPED)
    {
        if (dwRva >= cbImage) return FALSE;
        *ppPointer = (PBYTE)pImage + dwRva;
        return TRUE;
    }

    if (!PexPeRvaToOffset(pImage, cbImage, dwRva, &dwOffset)) return FALSE;
    *ppPointer = (PBYTE)pImage + dwOffset;
    return TRUE;
}



static BOOL PexPeFindExportHashInternal(PVOID pImage, DWORD cbImage, PEX_PE_LAYOUT layout,
                                        DWORD dwNameHash, PVOID* ppAddress, PDWORD pdwFileOffset)
{
    PIMAGE_NT_HEADERS       pNt;
    PIMAGE_EXPORT_DIRECTORY pExport;
    PDWORD                  pdwNames;
    PDWORD                  pdwFunctions;
    PWORD                   pwOrdinals;
    DWORD                   dwExportRva;
    DWORD                   dwExportSize;
    DWORD                   i;

    if (ppAddress != NULL) *ppAddress = NULL;
    if (pdwFileOffset != NULL) *pdwFileOffset = 0;

    pNt = PexPeNtHeaders(pImage, cbImage);
    if (pNt == NULL) return FALSE;

    dwExportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    dwExportSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (dwExportRva == 0 || dwExportRva >= pNt->OptionalHeader.SizeOfImage) return FALSE;

    if (!PexPeRvaToPointer(pImage, cbImage, layout, dwExportRva, (PVOID*)&pExport)) return FALSE;
    if (pExport->NumberOfNames == 0 || pExport->NumberOfNames > 65536) return FALSE;

    if (!PexPeRvaToPointer(pImage, cbImage, layout, pExport->AddressOfNames, (PVOID*)&pdwNames)) return FALSE;
    if (!PexPeRvaToPointer(pImage, cbImage, layout, pExport->AddressOfFunctions, (PVOID*)&pdwFunctions)) return FALSE;
    if (!PexPeRvaToPointer(pImage, cbImage, layout, pExport->AddressOfNameOrdinals, (PVOID*)&pwOrdinals)) return FALSE;

    for (i = 0; i < pExport->NumberOfNames; i++)
    {
        PCSTR szExport = NULL;
        DWORD dwFunctionRva;

        if (!PexPeRvaToPointer(pImage, cbImage, layout, pdwNames[i], (PVOID*)&szExport)) return FALSE;
        if (NativeHash(szExport) != dwNameHash) continue;

        dwFunctionRva = pdwFunctions[pwOrdinals[i]];

        /* A forwarder points inside the export directory; the stub itself is
         * never forwarded, so report it as unsupported rather than wrong. */
        if (dwFunctionRva >= dwExportRva && dwFunctionRva < dwExportRva + dwExportSize)
        {
            return FALSE;
        }

        if (ppAddress != NULL)
        {
            if (layout == PEX_PE_MAPPED)
            {
                if (dwFunctionRva >= cbImage) return FALSE;
                *ppAddress = (PBYTE)pImage + dwFunctionRva;
            }
            else
            {
                DWORD dwOffset;
                if (!PexPeRvaToOffset(pImage, cbImage, dwFunctionRva, &dwOffset)) return FALSE;
                *ppAddress = (PBYTE)pImage + dwOffset;
            }
        }
        if (pdwFileOffset != NULL)
        {
            if (layout == PEX_PE_FILE)
            {
                if (!PexPeRvaToOffset(pImage, cbImage, dwFunctionRva, pdwFileOffset)) return FALSE;
            }
            else
            {
                *pdwFileOffset = dwFunctionRva;
            }
        }
        return TRUE;
    }

    return FALSE;
}

BOOL PexPeFindExport(PVOID pImage, DWORD cbImage, PEX_PE_LAYOUT layout,
                      PCSTR szName, PVOID* ppAddress, PDWORD pdwFileOffset)
{
    if (szName == NULL) return FALSE;
    return PexPeFindExportHashInternal(pImage, cbImage, layout,
                                       NativeHash(szName), ppAddress, pdwFileOffset);
}

BOOL PexPeFindExportHash(PVOID pImage, DWORD cbImage, PEX_PE_LAYOUT layout,
                          DWORD dwNameHash, PVOID* ppAddress, PDWORD pdwFileOffset)
{
    return PexPeFindExportHashInternal(pImage, cbImage, layout,
                                       dwNameHash, ppAddress, pdwFileOffset);
}

BOOL PexPeGetSizeOfImage(PVOID pImage, DWORD cbImage, PDWORD pdwSizeOfImage)
{
    PIMAGE_NT_HEADERS pNt;

    if (pdwSizeOfImage == NULL) return FALSE;

    pNt = PexPeNtHeaders(pImage, cbImage);
    if (pNt == NULL) return FALSE;

    *pdwSizeOfImage = pNt->OptionalHeader.SizeOfImage;
    return TRUE;
}
