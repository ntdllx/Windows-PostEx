#pragma once

#include <windows.h>

/*
 * Minimal leveled logger for the mechanism tools.
 *
 * The library deliberately owns no formatting policy beyond "one line per
 * record": tools decide what to emit, the logger decides where. Diagnostics
 * always go to stderr so that stdout stays machine-parsable.
 */

#define PEX_LOG_ERROR 0
#define PEX_LOG_WARN  1
#define PEX_LOG_INFO  2
#define PEX_LOG_DEBUG 3

void PexLogSetLevel(int nLevel);
void PexLogSetQuiet(BOOL bQuiet);
void PexLog(int nLevel, PCSTR szFormat, ...);
void PexLogHex(int nLevel, PCSTR szLabel, const VOID* pData, DWORD cbData);
