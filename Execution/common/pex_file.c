#include "pex_file.h"

#include <stdio.h>
#include <string.h>

BOOL PexFileReadAll(PCSTR szPath, PVOID* ppData, DWORD* pcbData)
{
    FILE* pFile;
    long  lSize;
    PVOID pBuffer;

    if (ppData == NULL || pcbData == NULL || szPath == NULL) return FALSE;

    *ppData = NULL;
    *pcbData = 0;

    pFile = NULL;
    if (fopen_s(&pFile, szPath, "rb") != 0 || pFile == NULL) return FALSE;

    if (fseek(pFile, 0, SEEK_END) != 0) { fclose(pFile); return FALSE; }
    lSize = ftell(pFile);
    if (lSize < 0 || (DWORD)lSize > PEX_FILE_MAX_BYTES)
    {
        fclose(pFile);
        return FALSE;
    }
    rewind(pFile);

    pBuffer = malloc((size_t)lSize + 1);
    if (pBuffer == NULL) { fclose(pFile); return FALSE; }

    if (lSize > 0 && fread(pBuffer, 1, (size_t)lSize, pFile) != (size_t)lSize)
    {
        free(pBuffer);
        fclose(pFile);
        return FALSE;
    }
    fclose(pFile);

    ((BYTE*)pBuffer)[lSize] = 0;
    *ppData = pBuffer;
    *pcbData = (DWORD)lSize;
    return TRUE;
}

BOOL PexFileWriteAll(PCSTR szPath, const VOID* pData, DWORD cbData)
{
    FILE* pFile;

    if (szPath == NULL || (pData == NULL && cbData != 0)) return FALSE;
    pFile = NULL;
    if (fopen_s(&pFile, szPath, "wb") != 0 || pFile == NULL) return FALSE;

    if (cbData != 0 && fwrite(pData, 1, cbData, pFile) != cbData)
    {
        fclose(pFile);
        return FALSE;
    }
    fclose(pFile);
    return TRUE;
}

BOOL PexFileExists(PCSTR szPath)
{
    DWORD dwAttributes;

    if (szPath == NULL) return FALSE;
    dwAttributes = GetFileAttributesA(szPath);
    return (dwAttributes != INVALID_FILE_ATTRIBUTES) &&
           ((dwAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
}

BOOL PexFileEquals(PCSTR szPath, const VOID* pData, DWORD cbData)
{
    PVOID pActual;
    DWORD cbActual;
    BOOL  bEqual;

    if (!PexFileReadAll(szPath, &pActual, &cbActual)) return FALSE;

    bEqual = (cbActual == cbData) &&
             (cbData == 0 || memcmp(pActual, pData, cbData) == 0);
    free(pActual);
    return bEqual;
}

BOOL PexPathJoin(PCHAR szOut, DWORD cchOut, PCSTR szDirectory, PCSTR szName)
{
    int cch;

    if (szOut == NULL || cchOut == 0 || szDirectory == NULL || szName == NULL) return FALSE;

    cch = _snprintf_s(szOut, cchOut, _TRUNCATE, "%s%s%s",
                      szDirectory,
                      (szDirectory[0] != 0 &&
                       szDirectory[lstrlenA(szDirectory) - 1] == '\\') ? "" : "\\",
                      szName);
    return (cch > 0);
}
