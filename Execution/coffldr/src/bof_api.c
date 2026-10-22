#include "bof_api.h"
#include "pex_native.h"

#include <stdarg.h>
#ifndef PEX_NATIVE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

/*
 * The parser layout below is the de-facto BOF convention. It is kept as a
 * plain struct because objects address its fields directly.
 */
typedef struct _BOF_DATAP
{
    PCHAR pOriginal;
    PCHAR pBuffer;
    int   cbLength;
    int   cbSize;
} BOF_DATAP, *PBOF_DATAP;

static PBOF_API_CTX g_pActiveCtx = NULL;

/* ------------------------------------------------------------------ */
/* BOF-compatible primitives                                        */
/* ------------------------------------------------------------------ */

void BeaconOutput(int nType, PCSTR pData, int cbData)
{
    if (g_pActiveCtx == NULL || g_pActiveCtx->pfnOutput == NULL) return;
    g_pActiveCtx->pfnOutput(g_pActiveCtx->pUser, nType, pData, cbData);
}

static int BofStrLen(PCSTR szText)
{
    int cch = 0;

    if (szText == NULL) return 0;
    while (szText[cch] != 0) cch++;
    return cch;
}

#ifdef PEX_NATIVE
static VOID BofPutChar(PCHAR szBuffer, DWORD cchBuffer, DWORD* pcUsed, CHAR ch)
{
    if (*pcUsed + 1 < cchBuffer)
    {
        szBuffer[*pcUsed] = ch;
        (*pcUsed)++;
        szBuffer[*pcUsed] = 0;
    }
}

static VOID BofPutRepeat(PCHAR szBuffer, DWORD cchBuffer, DWORD* pcUsed, CHAR ch, DWORD cRepeat)
{
    while (cRepeat-- != 0) BofPutChar(szBuffer, cchBuffer, pcUsed, ch);
}

static VOID BofPutUnsigned(PCHAR szBuffer, DWORD cchBuffer, DWORD* pcUsed,
                           ULONGLONG ullValue, DWORD dwBase, BOOL bUpper,
                           DWORD dwWidth, DWORD dwPrecision, BOOL bHasPrecision,
                           BOOL bLeft, BOOL bZero, BOOL bNegative)
{
    CHAR  szDigits[32];
    DWORD cDigits = 0;
    DWORD cPad;
    PCSTR szAlphabet = bUpper ? "0123456789ABCDEF" : "0123456789abcdef";

    if (ullValue == 0 && (!bHasPrecision || dwPrecision != 0))
    {
        szDigits[cDigits++] = '0';
    }
    while (ullValue != 0 && cDigits < sizeof(szDigits))
    {
        szDigits[cDigits++] = szAlphabet[ullValue % dwBase];
        ullValue /= dwBase;
    }
    while (bHasPrecision && cDigits < dwPrecision && cDigits < sizeof(szDigits))
    {
        szDigits[cDigits++] = '0';
    }

    cPad = dwWidth > cDigits + (bNegative ? 1u : 0u)
         ? dwWidth - cDigits - (bNegative ? 1u : 0u) : 0;

    if (!bLeft && !bZero) BofPutRepeat(szBuffer, cchBuffer, pcUsed, ' ', cPad);
    if (bNegative) BofPutChar(szBuffer, cchBuffer, pcUsed, '-');
    if (!bLeft && bZero) BofPutRepeat(szBuffer, cchBuffer, pcUsed, '0', cPad);
    while (cDigits != 0) BofPutChar(szBuffer, cchBuffer, pcUsed, szDigits[--cDigits]);
    if (bLeft) BofPutRepeat(szBuffer, cchBuffer, pcUsed, ' ', cPad);
}

static VOID BofPutString(PCHAR szBuffer, DWORD cchBuffer, DWORD* pcUsed,
                         PCSTR szText, DWORD cchMax, DWORD dwWidth, BOOL bLeft)
{
    DWORD cch = 0;
    DWORD cPad;

    if (szText == NULL) szText = "";
    while (szText[cch] != 0 && cch < cchMax) cch++;

    cPad = dwWidth > cch ? dwWidth - cch : 0;
    if (!bLeft) BofPutRepeat(szBuffer, cchBuffer, pcUsed, ' ', cPad);
    while (cch != 0)
    {
        BofPutChar(szBuffer, cchBuffer, pcUsed, szText[0]);
        szText++;
        cch--;
    }
    if (bLeft) BofPutRepeat(szBuffer, cchBuffer, pcUsed, ' ', cPad);
}

static VOID BofFormatV(PCHAR szBuffer, DWORD cchBuffer, PCSTR szFormat, va_list pArgs)
{
    DWORD cUsed = 0;

    if (cchBuffer == 0) return;
    szBuffer[0] = 0;
    if (szFormat == NULL) return;

    while (*szFormat != 0)
    {
        BOOL  bLeft = FALSE;
        BOOL  bZero = FALSE;
        BOOL  bHasPrecision = FALSE;
        DWORD dwWidth = 0;
        DWORD dwPrecision = 0;
        int   nLength = 0;
        CHAR  chConv;

        if (*szFormat != '%')
        {
            BofPutChar(szBuffer, cchBuffer, &cUsed, *szFormat++);
            continue;
        }

        szFormat++;
        if (*szFormat == '%')
        {
            BofPutChar(szBuffer, cchBuffer, &cUsed, '%');
            szFormat++;
            continue;
        }

        for (;;)
        {
            if (*szFormat == '-') { bLeft = TRUE; szFormat++; }
            else if (*szFormat == '0') { bZero = TRUE; szFormat++; }
            else if (*szFormat == '+' || *szFormat == ' ' || *szFormat == '#') szFormat++;
            else break;
        }

        if (*szFormat == '*')
        {
            int nWidth = va_arg(pArgs, int);
            if (nWidth < 0) { bLeft = TRUE; nWidth = -nWidth; }
            dwWidth = (DWORD)nWidth;
            szFormat++;
        }
        else
        {
            while (*szFormat >= '0' && *szFormat <= '9')
            {
                dwWidth = dwWidth * 10 + (DWORD)(*szFormat - '0');
                szFormat++;
            }
        }

        if (*szFormat == '.')
        {
            szFormat++;
            bHasPrecision = TRUE;
            if (*szFormat == '*')
            {
                int nPrecision = va_arg(pArgs, int);
                dwPrecision = nPrecision < 0 ? 0 : (DWORD)nPrecision;
                szFormat++;
            }
            else
            {
                while (*szFormat >= '0' && *szFormat <= '9')
                {
                    dwPrecision = dwPrecision * 10 + (DWORD)(*szFormat - '0');
                    szFormat++;
                }
            }
        }

        if (szFormat[0] == 'I' && szFormat[1] == '6' && szFormat[2] == '4')
        {
            nLength = 2;
            szFormat += 3;
        }
        else if (*szFormat == 'l')
        {
            nLength = 1;
            szFormat++;
            if (*szFormat == 'l') { nLength = 2; szFormat++; }
        }
        else if (*szFormat == 'h')
        {
            nLength = 3;
            szFormat++;
            if (*szFormat == 'h') { nLength = 4; szFormat++; }
        }
        else if (*szFormat == 'z')
        {
            nLength = 5;
            szFormat++;
        }

        chConv = *szFormat;
        if (chConv == 0) break;
        szFormat++;

        switch (chConv)
        {
        case 'd':
        case 'i':
        {
            LONGLONG  llValue;
            BOOL      bNegative;
            ULONGLONG ullValue;

            if (nLength == 2) llValue = va_arg(pArgs, LONGLONG);
            else if (nLength == 1) llValue = va_arg(pArgs, long);
            else llValue = va_arg(pArgs, int);
            if (nLength == 3) llValue = (short)llValue;
            if (nLength == 4) llValue = (signed char)llValue;

            bNegative = (llValue < 0);
            ullValue = bNegative ? (ULONGLONG)(-llValue) : (ULONGLONG)llValue;
            BofPutUnsigned(szBuffer, cchBuffer, &cUsed, ullValue, 10, FALSE,
                           dwWidth, dwPrecision, bHasPrecision, bLeft, bZero, bNegative);
            break;
        }
        case 'u':
        case 'x':
        case 'X':
        case 'o':
        {
            ULONGLONG ullValue;
            DWORD     dwBase = (chConv == 'o') ? 8 : ((chConv == 'u') ? 10 : 16);

            if (nLength == 2) ullValue = va_arg(pArgs, ULONGLONG);
            else if (nLength == 1) ullValue = va_arg(pArgs, unsigned long);
            else ullValue = va_arg(pArgs, unsigned int);
            if (nLength == 3) ullValue = (unsigned short)ullValue;
            if (nLength == 4) ullValue = (unsigned char)ullValue;

            BofPutUnsigned(szBuffer, cchBuffer, &cUsed, ullValue, dwBase,
                           chConv == 'X', dwWidth, dwPrecision, bHasPrecision,
                           bLeft, bZero, FALSE);
            break;
        }
        case 'p':
        {
            ULONGLONG ullValue = (ULONGLONG)(ULONG_PTR)va_arg(pArgs, PVOID);

            BofPutChar(szBuffer, cchBuffer, &cUsed, '0');
            BofPutChar(szBuffer, cchBuffer, &cUsed, 'x');
            BofPutUnsigned(szBuffer, cchBuffer, &cUsed, ullValue, 16, FALSE,
                           16, 0, FALSE, FALSE, TRUE, FALSE);
            break;
        }
        case 'c':
            BofPutChar(szBuffer, cchBuffer, &cUsed, (CHAR)va_arg(pArgs, int));
            break;
        case 's':
        {
            PCSTR szText = va_arg(pArgs, PCSTR);
            DWORD cchMax = bHasPrecision ? dwPrecision : (DWORD)-1;

            BofPutString(szBuffer, cchBuffer, &cUsed, szText, cchMax, dwWidth, bLeft);
            break;
        }
        default:
            BofPutChar(szBuffer, cchBuffer, &cUsed, '%');
            BofPutChar(szBuffer, cchBuffer, &cUsed, chConv);
            break;
        }
    }
}
#endif

void BeaconPrintf(int nType, PCSTR szFormat, ...)
{
    CHAR    szBuffer[4096];
    va_list pArgList;

    if (szFormat == NULL) return;

    va_start(pArgList, szFormat);
#ifdef PEX_NATIVE
    BofFormatV(szBuffer, sizeof(szBuffer), szFormat, pArgList);
#else
    _vsnprintf_s(szBuffer, sizeof(szBuffer), _TRUNCATE, szFormat, pArgList);
#endif
    va_end(pArgList);

    BeaconOutput(nType, szBuffer, BofStrLen(szBuffer));
}

void BeaconDataParse(PBOF_DATAP pParser, PCHAR pBuffer, int cbSize)
{
    if (pParser == NULL) return;

    /* The first four bytes carry the total blob length; the item stream starts
     * after it. This mirrors the established BOF convention. */
    pParser->pOriginal = pBuffer;
    pParser->cbSize = cbSize;
    if (cbSize >= (int)sizeof(int))
    {
        pParser->pBuffer = pBuffer + sizeof(int);
        pParser->cbLength = (int)sizeof(int);
    }
    else
    {
        pParser->pBuffer = pBuffer;
        pParser->cbLength = 0;
    }
}

PCHAR BeaconDataExtract(PBOF_DATAP pParser, int* pcbSize)
{
    int cbItem;

    if (pcbSize != NULL) *pcbSize = 0;
    if (pParser == NULL || pParser->pBuffer == NULL) return NULL;
    if (pParser->cbLength + (int)sizeof(int) > pParser->cbSize) return NULL;

    CopyMemory(&cbItem, pParser->pBuffer, sizeof(int));
    pParser->pBuffer += sizeof(int);
    pParser->cbLength += (int)sizeof(int);

    if (cbItem < 0 || pParser->cbLength + cbItem > pParser->cbSize) return NULL;

    if (pcbSize != NULL) *pcbSize = cbItem;
    pParser->pBuffer += cbItem;
    pParser->cbLength += cbItem;

    return pParser->pBuffer - cbItem;
}

int BeaconDataInt(PBOF_DATAP pParser)
{
    int nValue = 0;

    if (pParser == NULL || pParser->pBuffer == NULL) return 0;
    if (pParser->cbLength + (int)sizeof(int) > pParser->cbSize) return 0;

    CopyMemory(&nValue, pParser->pBuffer, sizeof(int));
    pParser->pBuffer += sizeof(int);
    pParser->cbLength += (int)sizeof(int);
    return nValue;
}

short BeaconDataShort(PBOF_DATAP pParser)
{
    short sValue = 0;

    if (pParser == NULL || pParser->pBuffer == NULL) return 0;
    if (pParser->cbLength + (int)sizeof(short) > pParser->cbSize) return 0;

    CopyMemory(&sValue, pParser->pBuffer, sizeof(short));
    pParser->pBuffer += sizeof(short);
    pParser->cbLength += (int)sizeof(short);
    return sValue;
}

int BeaconDataLength(PBOF_DATAP pParser)
{
    if (pParser == NULL) return 0;
    return pParser->cbSize;
}

/* ------------------------------------------------------------------ */
/* Adapter                                                             */
/* ------------------------------------------------------------------ */

typedef struct _BOF_API_ENTRY
{
    DWORD dwNameHash;
    PVOID pAddress;
} BOF_API_ENTRY;

static const BOF_API_ENTRY g_aEntries[] =
{
    { HASH_BEACONOUTPUT,      (PVOID)&BeaconOutput },
    { HASH_BEACONPRINTF,      (PVOID)&BeaconPrintf },
    { HASH_BEACONDATAPARSE,   (PVOID)&BeaconDataParse },
    { HASH_BEACONDATAEXTRACT, (PVOID)&BeaconDataExtract },
    { HASH_BEACONDATAINT,     (PVOID)&BeaconDataInt },
    { HASH_BEACONDATASHORT,   (PVOID)&BeaconDataShort },
    { HASH_BEACONDATALENGTH,  (PVOID)&BeaconDataLength },
};

void BofApiInit(PBOF_API_CTX pCtx, PCSTR pArgs, int cbArgs,
                PFN_BOF_OUTPUT pfnOutput, PVOID pUser)
{
    if (pCtx == NULL) return;

    pCtx->pArgs = pArgs;
    pCtx->cbArgs = cbArgs;
    pCtx->pfnOutput = pfnOutput;
    pCtx->pUser = pUser;

    g_pActiveCtx = pCtx;
}

void BofApiRelease(PBOF_API_CTX pCtx)
{
    if (g_pActiveCtx == pCtx) g_pActiveCtx = NULL;
}

PVOID BofApiResolve(PBOF_API_CTX pCtx, PCSTR szName)
{
    size_t i;
    DWORD  dwNameHash;

    (void)pCtx;
    if (szName == NULL) return NULL;
    dwNameHash = NativeHash(szName);

    for (i = 0; i < sizeof(g_aEntries) / sizeof(g_aEntries[0]); i++)
    {
        if (g_aEntries[i].dwNameHash == dwNameHash)
        {
            return g_aEntries[i].pAddress;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Argument packing                                                    */
/* ------------------------------------------------------------------ */

static PVOID BofAllocZero(DWORD cbSize)
{
#ifdef PEX_NATIVE
    return ((PVOID (WINAPI*)(PVOID, SIZE_T, DWORD, DWORD))g_pfnVirtualAlloc)(
        NULL, cbSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    return calloc(1, cbSize);
#endif
}

void BofApiFreeArgs(PVOID pBlob)
{
    if (pBlob == NULL) return;
#ifdef PEX_NATIVE
    ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pBlob, 0, MEM_RELEASE);
#else
    free(pBlob);
#endif
}

static BOOL BofTokenIsInteger(PCSTR szToken, DWORD cbToken, int* pnValue)
{
    DWORD   i = 0;
    __int64 i64Value = 0;
    BOOL    bNegative = FALSE;

    if (szToken == NULL || cbToken == 0) return FALSE;

    if (szToken[0] == '-')
    {
        bNegative = TRUE;
        i = 1;
    }
    if (i >= cbToken) return FALSE;

    for (; i < cbToken; i++)
    {
        if (szToken[i] < '0' || szToken[i] > '9') return FALSE;
        i64Value = i64Value * 10 + (szToken[i] - '0');
        if (i64Value > 0x7FFFFFFF) return FALSE;
    }

    *pnValue = (int)(bNegative ? -i64Value : i64Value);
    return TRUE;
}

BOOL BofApiPackArgs(PCSTR szArguments, BYTE** ppBlob, DWORD* pcbBlob)
{
    PCSTR szCursor;
    DWORD       cbTotal;
    BYTE*       pbBlob;
    BYTE*       pbWrite;

    if (ppBlob == NULL || pcbBlob == NULL) return FALSE;
    *ppBlob = NULL;
    *pcbBlob = 0;

    if (szArguments == NULL || szArguments[0] == 0)
    {
        pbBlob = (BYTE*)BofAllocZero(sizeof(int));
        if (pbBlob == NULL) return FALSE;
        *ppBlob = pbBlob;
        *pcbBlob = sizeof(int);
        return TRUE;
    }

    /* First pass: size the blob. Integer tokens occupy four bytes, strings
     * occupy a four-byte length followed by their bytes. */
    cbTotal = sizeof(int);
    szCursor = szArguments;
    for (;;)
    {
        PCSTR szItemEnd = szCursor;
        DWORD       cbItem;
        int         nValue;

        while (*szItemEnd != 0 && *szItemEnd != ',') szItemEnd++;
        cbItem = (DWORD)(szItemEnd - szCursor);

        cbTotal += (DWORD)sizeof(int) +
                   (BofTokenIsInteger(szCursor, cbItem, &nValue) ? (DWORD)sizeof(int) : cbItem);

        if (*szItemEnd == 0) break;
        szCursor = szItemEnd + 1;
    }

    pbBlob = (BYTE*)BofAllocZero(cbTotal);
    if (pbBlob == NULL) return FALSE;

    pbWrite = pbBlob;
    CopyMemory(pbWrite, &cbTotal, sizeof(int));
    pbWrite += sizeof(int);

    szCursor = szArguments;
    for (;;)
    {
        PCSTR szItemEnd = szCursor;
        DWORD       cbItem;
        int         nValue;

        while (*szItemEnd != 0 && *szItemEnd != ',') szItemEnd++;
        cbItem = (DWORD)(szItemEnd - szCursor);

        if (BofTokenIsInteger(szCursor, cbItem, &nValue))
        {
            CopyMemory(pbWrite, &nValue, sizeof(int));
            pbWrite += sizeof(int);
        }
        else
        {
            CopyMemory(pbWrite, &cbItem, sizeof(int));
            pbWrite += sizeof(int);
            if (cbItem != 0)
            {
                CopyMemory(pbWrite, szCursor, cbItem);
                pbWrite += cbItem;
            }
        }

        if (*szItemEnd == 0) break;
        szCursor = szItemEnd + 1;
    }

    *ppBlob = pbBlob;
    *pcbBlob = cbTotal;
    return TRUE;
}
