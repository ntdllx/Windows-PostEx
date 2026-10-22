#include "base64.h"

static CHAR B64Char(DWORD dwValue)
{
    if (dwValue < 26) return (CHAR)('A' + dwValue);
    if (dwValue < 52) return (CHAR)('a' + (dwValue - 26));
    if (dwValue < 62) return (CHAR)('0' + (dwValue - 52));
    return (dwValue == 62) ? '+' : '/';
}

DWORD PexBase64Encode(const BYTE* pData, DWORD cbData, PCHAR szOut, DWORD cchOut)
{
    DWORD i = 0;
    DWORD o = 0;

    if (szOut == NULL || cchOut == 0) return 0;
    szOut[0] = 0;

    while (i + 2 < cbData)
    {
        DWORD dwValue = ((DWORD)pData[i] << 16) |
                        ((DWORD)pData[i + 1] << 8) |
                        (DWORD)pData[i + 2];

        if (o + 4 >= cchOut) return 0;
        szOut[o++] = B64Char((dwValue >> 18) & 0x3F);
        szOut[o++] = B64Char((dwValue >> 12) & 0x3F);
        szOut[o++] = B64Char((dwValue >> 6) & 0x3F);
        szOut[o++] = B64Char(dwValue & 0x3F);
        i += 3;
    }

    if (i < cbData)
    {
        DWORD dwValue = (DWORD)pData[i] << 16;

        if (i + 1 < cbData) dwValue |= (DWORD)pData[i + 1] << 8;

        if (o + 4 >= cchOut) return 0;
        szOut[o++] = B64Char((dwValue >> 18) & 0x3F);
        szOut[o++] = B64Char((dwValue >> 12) & 0x3F);
        szOut[o++] = (i + 1 < cbData) ? B64Char((dwValue >> 6) & 0x3F) : '=';
        szOut[o++] = '=';
    }

    szOut[o] = 0;
    return o;
}
