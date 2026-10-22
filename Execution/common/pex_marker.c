#include "pex_marker.h"
#include "pex_file.h"

#include <stdio.h>
#include <string.h>

static BOOL PexMarkerBuildPath(PCHAR szOut, DWORD cchOut,
                                PCSTR szDirectory, PCSTR szName)
{
    if (!PexPathJoin(szOut, cchOut, szDirectory, szName)) return FALSE;
    return TRUE;
}

BOOL PexMarkerWrite(PCSTR szDirectory, PCSTR szName, PCSTR szText)
{
    CHAR szPath[MAX_PATH];

    if (!PexMarkerBuildPath(szPath, sizeof(szPath), szDirectory, szName)) return FALSE;
    return PexFileWriteAll(szPath, szText, (DWORD)lstrlenA(szText));
}

BOOL PexMarkerVerify(PCSTR szDirectory, PCSTR szName, PCSTR szText)
{
    CHAR szPath[MAX_PATH];

    if (!PexMarkerBuildPath(szPath, sizeof(szPath), szDirectory, szName)) return FALSE;
    return PexFileEquals(szPath, szText, (DWORD)lstrlenA(szText));
}

BOOL PexMarkerRemove(PCSTR szDirectory, PCSTR szName)
{
    CHAR szPath[MAX_PATH];

    if (!PexMarkerBuildPath(szPath, sizeof(szPath), szDirectory, szName)) return FALSE;
    return DeleteFileA(szPath) != FALSE;
}
