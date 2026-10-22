#include "pex_native.h"

#include <intrin.h>

/* ------------------------------------------------------------------ */
/* PEB and export lookup                                               */
/* ------------------------------------------------------------------ */

typedef struct _NATIVE_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} NATIVE_UNICODE_STRING;

typedef struct _NATIVE_PEB_LDR_DATA
{
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} NATIVE_PEB_LDR_DATA;

typedef struct _NATIVE_LDR_ENTRY
{
    LIST_ENTRY            InLoadOrderLinks;
    LIST_ENTRY            InMemoryOrderLinks;
    LIST_ENTRY            InInitializationOrderLinks;
    PVOID                 DllBase;
    PVOID                 EntryPoint;
    ULONG                 SizeOfImage;
    ULONG                 Reserved;
    NATIVE_UNICODE_STRING FullDllName;
    NATIVE_UNICODE_STRING BaseDllName;
} NATIVE_LDR_ENTRY;

typedef struct _NATIVE_PEB
{
    BYTE  Reserved[0x18];
    PVOID LoaderData;
} NATIVE_PEB;

DWORD NativeHash(PCSTR szText)
{
    DWORD dwHash = 5381;

    while (*szText != 0)
    {
        CHAR ch = *szText++;
        if (ch >= 'a' && ch <= 'z') ch -= 32;
        dwHash = dwHash * 33 + (DWORD)(BYTE)ch;
    }
    return dwHash;
}

static DWORD NativeHashWide(PCWSTR wszText, USHORT cchText)
{
    DWORD dwHash = 5381;
    USHORT i;

    for (i = 0; i < cchText; i++)
    {
        WCHAR wc = wszText[i];
        if (wc >= L'a' && wc <= L'z') wc -= 32;
        dwHash = dwHash * 33 + (DWORD)(wc & 0xFF);
    }
    return dwHash;
}

PVOID NativeGetModuleByHash(DWORD dwNameHash)
{
    NATIVE_PEB*         pPeb = (NATIVE_PEB*)__readgsqword(0x60);
    NATIVE_PEB_LDR_DATA* pLdr;
    PLIST_ENTRY         pHead;
    PLIST_ENTRY         pCurrent;

    if (pPeb == NULL || pPeb->LoaderData == NULL) return NULL;

    pLdr = (NATIVE_PEB_LDR_DATA*)pPeb->LoaderData;
    pHead = &pLdr->InMemoryOrderModuleList;
    pCurrent = pHead->Flink;

    while (pCurrent != pHead)
    {
        NATIVE_LDR_ENTRY* pEntry =
            CONTAINING_RECORD(pCurrent, NATIVE_LDR_ENTRY, InMemoryOrderLinks);

        if (pEntry->DllBase != NULL && pEntry->BaseDllName.Buffer != NULL &&
            NativeHashWide(pEntry->BaseDllName.Buffer,
                           pEntry->BaseDllName.Length / sizeof(WCHAR)) == dwNameHash)
        {
            return pEntry->DllBase;
        }

        pCurrent = pCurrent->Flink;
    }

    return NULL;
}

static PVOID NativeForwarded(PVOID pModule, DWORD dwForwardRva, INT nDepth);
static PVOID NativeGetProcFromModuleDepth(PVOID pModule, DWORD dwNameHash, INT nDepth);

PVOID NativeGetProcFromModule(PVOID pModule, DWORD dwNameHash)
{
    return NativeGetProcFromModuleDepth(pModule, dwNameHash, 0);
}

static PVOID NativeGetProcFromModuleDepth(PVOID pModule, DWORD dwNameHash, INT nDepth)
{
    PIMAGE_DOS_HEADER       pDos = (PIMAGE_DOS_HEADER)pModule;
    PIMAGE_NT_HEADERS       pNt;
    PIMAGE_EXPORT_DIRECTORY pExport;
    PDWORD                  pdwNames;
    PDWORD                  pdwFunctions;
    PWORD                   pwOrdinals;
    DWORD                   dwExportRva;
    DWORD                   dwExportSize;
    DWORD                   i;

    if (pModule == NULL || nDepth > 8) return NULL;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModule + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    dwExportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    dwExportSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (dwExportRva == 0) return NULL;

    pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModule + dwExportRva);
    pdwNames = (PDWORD)((PBYTE)pModule + pExport->AddressOfNames);
    pdwFunctions = (PDWORD)((PBYTE)pModule + pExport->AddressOfFunctions);
    pwOrdinals = (PWORD)((PBYTE)pModule + pExport->AddressOfNameOrdinals);

    for (i = 0; i < pExport->NumberOfNames; i++)
    {
        PCSTR szName = (PCSTR)((PBYTE)pModule + pdwNames[i]);
        DWORD dwFunctionRva;

        if (NativeHash(szName) != dwNameHash) continue;

        dwFunctionRva = pdwFunctions[pwOrdinals[i]];

        if (dwFunctionRva >= dwExportRva && dwFunctionRva < dwExportRva + dwExportSize)
        {
            return NativeForwarded(pModule, dwFunctionRva, nDepth);
        }

        return (PBYTE)pModule + dwFunctionRva;
    }

    return NULL;
}

static PVOID NativeForwarded(PVOID pModule, DWORD dwForwardRva, INT nDepth)
{
    PCSTR   szForward = (PCSTR)((PBYTE)pModule + dwForwardRva);
    CHAR    szModule[64];
    SIZE_T  i = 0;
    PVOID   pTarget;

    if (nDepth > 8) return NULL;

    while (szForward[i] != 0 && szForward[i] != '.' && i < sizeof(szModule) - 1)
    {
        szModule[i] = szForward[i];
        i++;
    }
    szModule[i] = 0;

    if (szForward[i] != '.' || szForward[i + 1] == 0) return NULL;

    pTarget = NativeGetModuleByHash(NativeHash(szModule));
    if (pTarget == NULL)
    {
        /* Forwarder strings omit the extension (KERNELBASE.Foo). */
        CHAR szDll[80];
        SIZE_T k = 0;

        while (szModule[k] != 0 && k < sizeof(szDll) - 5)
        {
            szDll[k] = szModule[k];
            k++;
        }
        szDll[k++] = '.';
        szDll[k++] = 'd';
        szDll[k++] = 'l';
        szDll[k++] = 'l';
        szDll[k] = 0;

        pTarget = NativeGetModuleByHash(NativeHash(szDll));
    }
    if (pTarget == NULL && g_pfnLoadLibraryA != NULL)
    {
        pTarget = ((HMODULE (WINAPI*)(PCSTR))g_pfnLoadLibraryA)(szModule);
    }
    if (pTarget == NULL) return NULL;

    /* The forwarded name may itself be a forwarder; walk it with a hash. */
    return NativeGetProcFromModuleDepth(pTarget, NativeHash(szForward + i + 1), nDepth + 1);
}

PVOID NativeResolve(DWORD dwModuleHash, DWORD dwNameHash)
{
    return NativeGetProcFromModule(NativeGetModuleByHash(dwModuleHash), dwNameHash);
}

/* ------------------------------------------------------------------ */
/* Startup                                                             */
/* ------------------------------------------------------------------ */

PVOID g_pfnVirtualAlloc;
PVOID g_pfnVirtualFree;
PVOID g_pfnVirtualProtect;
PVOID g_pfnVirtualQuery;
PVOID g_pfnGetModuleHandleExA;
PVOID g_pfnFreeLibrary;
PVOID g_pfnLoadLibraryA;
PVOID g_pfnGetProcAddress;
PVOID g_pfnGetModuleHandleA;

static PVOID g_pfnGetCommandLineA;
static PVOID g_pfnGetCommandLineW;
static PVOID g_pfnGetStdHandle;
PVOID g_pfnWriteFile;
PVOID g_pfnCreateFileA;
PVOID g_pfnReadFile;
PVOID g_pfnCloseHandle;
PVOID g_pfnWideCharToMultiByte;
PVOID g_pfnMultiByteToWideChar;
PVOID g_pfnGetConsoleMode;
PVOID g_pfnWriteConsoleW;
static PVOID g_pfnGetFileSizeEx;
static PVOID g_pfnGetTempPathA;
static PVOID g_pfnExitProcess;

static HANDLE g_hStdout;
static HANDLE g_hStderr;

static CHAR  g_szCommandLine[8192];
static PCHAR g_apszArgv[64];
static int   g_cArgc;

BOOL NativeInit(VOID)
{
    PVOID pKernel32;

    pKernel32 = NativeGetModuleByHash(HASH_KERNEL32_DLL);
    if (pKernel32 == NULL) return FALSE;

#define NATIVE_RESOLVE(target, hash) \
    target = NativeGetProcFromModule(pKernel32, hash); \
    if (target == NULL) return FALSE

    NATIVE_RESOLVE(g_pfnLoadLibraryA, HASH_LOADLIBRARYA);
    NATIVE_RESOLVE(g_pfnGetCommandLineA, HASH_GETCOMMANDLINEA);
    NATIVE_RESOLVE(g_pfnGetCommandLineW, HASH_GETCOMMANDLINEW);
    NATIVE_RESOLVE(g_pfnGetStdHandle, HASH_GETSTDHANDLE);
    NATIVE_RESOLVE(g_pfnWriteFile, HASH_WRITEFILE);
    NATIVE_RESOLVE(g_pfnCreateFileA, HASH_CREATEFILEA);
    NATIVE_RESOLVE(g_pfnReadFile, HASH_READFILE);
    NATIVE_RESOLVE(g_pfnCloseHandle, HASH_CLOSEHANDLE);
    NATIVE_RESOLVE(g_pfnGetFileSizeEx, HASH_GETFILESIZEEX);
    NATIVE_RESOLVE(g_pfnGetTempPathA, HASH_GETTEMPPATHA);
    NATIVE_RESOLVE(g_pfnExitProcess, HASH_EXITPROCESS);
    NATIVE_RESOLVE(g_pfnWideCharToMultiByte, HASH_WIDECHARTOMULTIBYTE);
    NATIVE_RESOLVE(g_pfnMultiByteToWideChar, HASH_MULTIBYTETOWIDECHAR);
    NATIVE_RESOLVE(g_pfnGetConsoleMode, HASH_GETCONSOLEMODE);
    NATIVE_RESOLVE(g_pfnWriteConsoleW, HASH_WRITECONSOLEW);
    NATIVE_RESOLVE(g_pfnVirtualAlloc, HASH_VIRTUALALLOC);
    NATIVE_RESOLVE(g_pfnVirtualFree, HASH_VIRTUALFREE);
    NATIVE_RESOLVE(g_pfnVirtualProtect, HASH_VIRTUALPROTECT);
    NATIVE_RESOLVE(g_pfnVirtualQuery, HASH_VIRTUALQUERY);
    NATIVE_RESOLVE(g_pfnGetModuleHandleExA, HASH_GETMODULEHANDLEEXA);
    NATIVE_RESOLVE(g_pfnFreeLibrary, HASH_FREELIBRARY);
    NATIVE_RESOLVE(g_pfnLoadLibraryA, HASH_LOADLIBRARYA);
    NATIVE_RESOLVE(g_pfnGetProcAddress, HASH_GETPROCADDRESS);
    NATIVE_RESOLVE(g_pfnGetModuleHandleA, HASH_GETMODULEHANDLEA);

#undef NATIVE_RESOLVE

    g_hStdout = ((HANDLE (WINAPI*)(DWORD))g_pfnGetStdHandle)((DWORD)-11);
    g_hStderr = ((HANDLE (WINAPI*)(DWORD))g_pfnGetStdHandle)((DWORD)-12);

    return TRUE;
}

VOID NativeExit(int nCode)
{
    ((VOID (WINAPI*)(UINT))g_pfnExitProcess)((UINT)nCode);
    for (;;) { }
}

/* ------------------------------------------------------------------ */
/* Arguments                                                           */
/* ------------------------------------------------------------------ */

static BOOL NativeInitArgs(VOID)
{
    PCSTR szCommandLine;
    SIZE_T cch = 0;
    SIZE_T i = 0;
    SIZE_T o = 0;
    BOOL bInQuotes = FALSE;

    if (g_cArgc != 0) return TRUE;

    szCommandLine = ((PCSTR (WINAPI*)(VOID))g_pfnGetCommandLineA)();
    if (szCommandLine == NULL) return FALSE;

    while (szCommandLine[cch] != 0 && cch < sizeof(g_szCommandLine) - 1)
    {
        g_szCommandLine[cch] = szCommandLine[cch];
        cch++;
    }
    g_szCommandLine[cch] = 0;

    while (i < cch && g_cArgc < (int)(sizeof(g_apszArgv) / sizeof(g_apszArgv[0])))
    {
        while (i < cch && (g_szCommandLine[i] == ' ' || g_szCommandLine[i] == '\t')) i++;
        if (i >= cch) break;

        g_apszArgv[g_cArgc++] = &g_szCommandLine[o];
        bInQuotes = FALSE;

        while (i < cch)
        {
            CHAR ch = g_szCommandLine[i];

            if (ch == '"')
            {
                bInQuotes = !bInQuotes;
                i++;
                continue;
            }
            if (!bInQuotes && (ch == ' ' || ch == '\t')) break;

            g_szCommandLine[o++] = ch;
            i++;
        }
        g_szCommandLine[o++] = 0;

        if (i < cch) i++;
    }

    return TRUE;
}

int NativeArgc(VOID)
{
    NativeInitArgs();
    return g_cArgc;
}

PCSTR NativeArgv(int nIndex)
{
    NativeInitArgs();
    if (nIndex < 0 || nIndex >= g_cArgc) return NULL;
    return g_apszArgv[nIndex];
}

PCSTR NativeJoinArgsUtf8(int nStart)
{
    static WCHAR wszJoined[4096];
    static CHAR  szUtf8[8192];
    PWSTR wszCommandLine;
    DWORD o = 0;
    int   i = 0;
    int   nToken = 0;
    int   cb;
    BOOL  bInQuotes;

    if (g_pfnGetCommandLineW == NULL || g_pfnWideCharToMultiByte == NULL) return "";
    wszCommandLine = ((PWSTR (WINAPI*)(VOID))g_pfnGetCommandLineW)();
    if (wszCommandLine == NULL) return "";

    while (wszCommandLine[i] != 0)
    {
        while (wszCommandLine[i] == L' ' || wszCommandLine[i] == L'\t') i++;
        if (wszCommandLine[i] == 0) break;

        if (nToken > nStart && o > 0 && o < 4095) wszJoined[o++] = L' ';

        bInQuotes = FALSE;
        while (wszCommandLine[i] != 0)
        {
            WCHAR wc = wszCommandLine[i];

            if (wc == L'"')
            {
                bInQuotes = !bInQuotes;
                i++;
                continue;
            }
            if (!bInQuotes && (wc == L' ' || wc == L'\t')) break;

            if (nToken >= nStart && o < 4095) wszJoined[o++] = wc;
            i++;
        }
        nToken++;
    }
    wszJoined[o] = 0;

    cb = ((int (WINAPI*)(UINT, DWORD, const WCHAR*, int, PCHAR, int, const CHAR*, int*))g_pfnWideCharToMultiByte)(
        CP_UTF8, 0, wszJoined, -1, NULL, 0, NULL, NULL);
    if (cb <= 0 || cb > (int)sizeof(szUtf8)) return "";

    ((int (WINAPI*)(UINT, DWORD, const WCHAR*, int, PCHAR, int, const CHAR*, int*))g_pfnWideCharToMultiByte)(
        CP_UTF8, 0, wszJoined, -1, szUtf8, (int)sizeof(szUtf8), NULL, NULL);
    return szUtf8;
}

BOOL NativeHasFlag(DWORD dwFlagHash)
{
    int i;

    NativeInitArgs();
    for (i = 1; i < g_cArgc; i++)
    {
        if (NativeHash(g_apszArgv[i]) == dwFlagHash) return TRUE;
    }
    return FALSE;
}

PCSTR NativeOptionValue(DWORD dwOptionHash)
{
    int i;

    NativeInitArgs();
    for (i = 1; i + 1 < g_cArgc; i++)
    {
        if (NativeHash(g_apszArgv[i]) == dwOptionHash)
        {
            return g_apszArgv[i + 1];
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Output                                                              */
/* ------------------------------------------------------------------ */

static VOID NativeWrite(HANDLE hHandle, PCSTR pData, DWORD cbData)
{
    DWORD cbWritten = 0;

    if (hHandle == NULL || hHandle == INVALID_HANDLE_VALUE || cbData == 0) return;
    ((BOOL (WINAPI*)(HANDLE, LPCVOID, DWORD, PDWORD, PVOID))g_pfnWriteFile)(
        hHandle, pData, cbData, &cbWritten, NULL);
}

VOID NativeWriteStdout(PCSTR pData, DWORD cbData)
{
    NativeWrite(g_hStdout, pData, cbData);
}

VOID NativeWriteText(PCSTR pData, DWORD cbData)
{
    DWORD dwMode = 0;

    if (pData == NULL || cbData == 0) return;

    /* A console gets UTF-16 through WriteConsoleW: no code page in the path,
     * so non-ASCII output cannot be mangled. Redirected stdout stays UTF-8. */
    if (g_hStdout != NULL && g_hStdout != INVALID_HANDLE_VALUE &&
        g_pfnGetConsoleMode != NULL && g_pfnWriteConsoleW != NULL &&
        g_pfnMultiByteToWideChar != NULL &&
        ((BOOL (WINAPI*)(HANDLE, PDWORD))g_pfnGetConsoleMode)(g_hStdout, &dwMode))
    {
        int cch = ((int (WINAPI*)(UINT, DWORD, PCSTR, int, PWSTR, int))g_pfnMultiByteToWideChar)(
            CP_UTF8, 0, pData, (int)cbData, NULL, 0);

        if (cch > 0)
        {
            PWSTR pwszText = (PWSTR)((PVOID (WINAPI*)(PVOID, SIZE_T, DWORD, DWORD))g_pfnVirtualAlloc)(
                NULL, (SIZE_T)cch * sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (pwszText != NULL)
            {
                DWORD cbWritten = 0;

                ((int (WINAPI*)(UINT, DWORD, PCSTR, int, PWSTR, int))g_pfnMultiByteToWideChar)(
                    CP_UTF8, 0, pData, (int)cbData, pwszText, cch);
                ((BOOL (WINAPI*)(HANDLE, const VOID*, DWORD, PDWORD, PVOID))g_pfnWriteConsoleW)(
                    g_hStdout, pwszText, (DWORD)cch, &cbWritten, NULL);
                ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pwszText, 0, MEM_RELEASE);
                return;
            }
        }
    }

    NativeWriteStdout(pData, cbData);
}

VOID NativeWriteStderr(PCSTR pData, DWORD cbData)
{
    NativeWrite(g_hStderr, pData, cbData);
}

static DWORD NativeStrLen(PCSTR szText)
{
    DWORD cch = 0;
    while (szText[cch] != 0) cch++;
    return cch;
}

VOID NativePrint(PCSTR szText)
{
    if (szText == NULL) return;
    NativeWriteStdout(szText, NativeStrLen(szText));
}

VOID NativePrintChar(char ch)
{
    NativeWriteStdout(&ch, 1);
}

VOID NativePrintHex(ULONG_PTR ulValue)
{
    CHAR szBuffer[19];
    int  i = 18;

    szBuffer[18] = 0;
    szBuffer[0] = '0';
    szBuffer[1] = 'x';
    for (i = 17; i >= 2; i--)
    {
        DWORD dwDigit = (DWORD)(ulValue & 0xF);
        szBuffer[i] = (CHAR)(dwDigit < 10 ? '0' + dwDigit : 'a' + (dwDigit - 10));
        ulValue >>= 4;
    }
    NativeWriteStdout(szBuffer, 18);
}

VOID NativePrintDec(DWORD dwValue)
{
    CHAR szBuffer[12];
    int  i = 11;

    szBuffer[11] = 0;
    if (dwValue == 0)
    {
        NativeWriteStdout("0", 1);
        return;
    }
    while (dwValue != 0 && i > 0)
    {
        szBuffer[--i] = (CHAR)('0' + (dwValue % 10));
        dwValue /= 10;
    }
    NativeWriteStdout(&szBuffer[i], (DWORD)(11 - i));
}

/* ------------------------------------------------------------------ */
/* Files                                                               */
/* ------------------------------------------------------------------ */

BOOL NativeReadFile(PCSTR szPath, PVOID* ppData, PDWORD pcbData)
{
    HANDLE        hFile;
    LARGE_INTEGER liSize;
    PVOID         pBuffer;
    DWORD         cbRead = 0;

    if (ppData == NULL || pcbData == NULL) return FALSE;
    *ppData = NULL;
    *pcbData = 0;

    hFile = ((HANDLE (WINAPI*)(PCSTR, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE))g_pfnCreateFileA)(
        szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    if (!((BOOL (WINAPI*)(HANDLE, PLARGE_INTEGER))g_pfnGetFileSizeEx)(hFile, &liSize) ||
        liSize.QuadPart <= 0 || liSize.QuadPart > (LONGLONG)(64u * 1024u * 1024u))
    {
        ((BOOL (WINAPI*)(HANDLE))g_pfnCloseHandle)(hFile);
        return FALSE;
    }

    pBuffer = ((PVOID (WINAPI*)(PVOID, SIZE_T, DWORD, DWORD))g_pfnVirtualAlloc)(
        NULL, (SIZE_T)liSize.QuadPart + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pBuffer == NULL)
    {
        ((BOOL (WINAPI*)(HANDLE))g_pfnCloseHandle)(hFile);
        return FALSE;
    }

    if (!((BOOL (WINAPI*)(HANDLE, PVOID, DWORD, PDWORD, PVOID))g_pfnReadFile)(
            hFile, pBuffer, (DWORD)liSize.QuadPart, &cbRead, NULL))
    {
        ((BOOL (WINAPI*)(HANDLE))g_pfnCloseHandle)(hFile);
        ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pBuffer, 0, MEM_RELEASE);
        return FALSE;
    }

    ((BOOL (WINAPI*)(HANDLE))g_pfnCloseHandle)(hFile);
    ((PBYTE)pBuffer)[cbRead] = 0;
    *ppData = pBuffer;
    *pcbData = cbRead;
    return TRUE;
}

BOOL NativeWriteFile(PCSTR szPath, const VOID* pData, DWORD cbData)
{
    HANDLE hFile;
    DWORD  cbWritten = 0;
    BOOL   bOk = TRUE;

    hFile = ((HANDLE (WINAPI*)(PCSTR, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE))g_pfnCreateFileA)(
        szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    if (cbData != 0)
    {
        bOk = ((BOOL (WINAPI*)(HANDLE, LPCVOID, DWORD, PDWORD, PVOID))g_pfnWriteFile)(
            hFile, pData, cbData, &cbWritten, NULL);
    }

    ((BOOL (WINAPI*)(HANDLE))g_pfnCloseHandle)(hFile);
    return bOk;
}

BOOL NativeFileExists(PCSTR szPath)
{
    HANDLE hFile;

    hFile = ((HANDLE (WINAPI*)(PCSTR, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE))g_pfnCreateFileA)(
        szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    ((BOOL (WINAPI*)(HANDLE))g_pfnCloseHandle)(hFile);
    return TRUE;
}

BOOL NativeTempPath(PCHAR szPath, DWORD cchPath)
{
    DWORD cch = ((DWORD (WINAPI*)(DWORD, PCHAR))g_pfnGetTempPathA)(cchPath, szPath);
    return cch != 0 && cch < cchPath;
}
