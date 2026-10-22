#pragma once

#include <windows.h>

/*
 * Standard base64 (RFC 4648) without a lookup table: the alphabet is derived
 * arithmetically so the host carries no printable table.
 *
 * Returns the number of characters written, or 0 when the buffer is too
 * small. The output is always NUL-terminated.
 */
DWORD PexBase64Encode(const BYTE* pData, DWORD cbData, PCHAR szOut, DWORD cchOut);
