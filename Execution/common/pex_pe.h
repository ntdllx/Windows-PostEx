#pragma once

#include <windows.h>

/*
 * Minimal PE reader.
 *
 * Two layouts are supported on purpose:
 *   - file layout  : the bytes as they sit on disk (what the host copies into
 *                    the staging buffer before calling the stub)
 *   - mapped layout: the image after the stub has laid it out (what the host
 *                    uses to find and call exports)
 *
 * Every RVA is range-checked; a malformed image yields FALSE instead of an
 * out-of-bounds access.
 */

typedef enum _PEX_PE_LAYOUT
{
    PEX_PE_FILE = 0,
    PEX_PE_MAPPED = 1
} PEX_PE_LAYOUT;

BOOL PexPeValidate(PVOID pImage, DWORD cbImage, PEX_PE_LAYOUT layout);

BOOL PexPeRvaToOffset(PVOID pImage, DWORD cbImage, DWORD dwRva, PDWORD pdwOffset);

BOOL PexPeFindExport(PVOID pImage, DWORD cbImage, PEX_PE_LAYOUT layout,
                      PCSTR szName, PVOID* ppAddress, PDWORD pdwFileOffset);

BOOL PexPeFindExportHash(PVOID pImage, DWORD cbImage, PEX_PE_LAYOUT layout,
                          DWORD dwNameHash, PVOID* ppAddress, PDWORD pdwFileOffset);

BOOL PexPeGetSizeOfImage(PVOID pImage, DWORD cbImage, PDWORD pdwSizeOfImage);
