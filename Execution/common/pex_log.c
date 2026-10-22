#include "pex_log.h"

#include <stdarg.h>
#include <stdio.h>

static int  g_nLevel = PEX_LOG_INFO;
static BOOL g_bQuiet = FALSE;

void PexLogSetLevel(int nLevel)
{
    if (nLevel < PEX_LOG_ERROR) nLevel = PEX_LOG_ERROR;
    if (nLevel > PEX_LOG_DEBUG) nLevel = PEX_LOG_DEBUG;
    g_nLevel = nLevel;
}

void PexLogSetQuiet(BOOL bQuiet)
{
    g_bQuiet = bQuiet;
}

void PexLog(int nLevel, PCSTR szFormat, ...)
{
    static PCSTR s_aszPrefix[] = { "error", "warn ", "info ", "debug" };
    CHAR szBuffer[1024];
    va_list pArgList;

    if (g_bQuiet || nLevel > g_nLevel || szFormat == NULL)
    {
        return;
    }

    va_start(pArgList, szFormat);
    _vsnprintf_s(szBuffer, sizeof(szBuffer), _TRUNCATE, szFormat, pArgList);
    va_end(pArgList);

    fprintf(stderr, "[%s] %s\n", s_aszPrefix[nLevel], szBuffer);
    fflush(stderr);
}

void PexLogHex(int nLevel, PCSTR szLabel, const VOID* pData, DWORD cbData)
{
    const BYTE* pbData = (const BYTE*)pData;
    CHAR        szLine[256];
    DWORD       i;
    DWORD       dwUsed;

    if (g_bQuiet || nLevel > g_nLevel || pbData == NULL)
    {
        return;
    }

    dwUsed = (DWORD)_snprintf_s(szLine, sizeof(szLine), _TRUNCATE, "%-16s ", szLabel ? szLabel : "hex");
    for (i = 0; i < cbData; i++)
    {
        if (dwUsed + 4 >= sizeof(szLine)) break;
        dwUsed += (DWORD)_snprintf_s(szLine + dwUsed, sizeof(szLine) - dwUsed, _TRUNCATE, "%02x", pbData[i]);
    }
    fprintf(stderr, "[%s] %s\n", (nLevel == PEX_LOG_ERROR) ? "error" : "info ", szLine);
    fflush(stderr);
}
