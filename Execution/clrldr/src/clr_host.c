#include "clr_host.h"

#include <intrin.h>
#include <oleauto.h>

#include "base64.h"
#include "pex_native.h"

#include "runner_blob.h"

#ifndef PEX_NATIVE
#include <stdarg.h>
#include <stdio.h>
#endif

/* Casting a resolved data pointer to a COM method pointer is the documented
 * MSVC extension used for hand-written vtables; C4152 is expected here. */
#pragma warning(disable: 4152)

/*
 * CLR v4 hosting sequence (the layout follows the mscoree/CLR v4 interface order):
 *
 *   CLRCreateInstance(CLSID_CLRMetaHost)
 *     -> ICLRMetaHost::GetRuntime("v4.0.30319")
 *     -> ICLRRuntimeInfo::GetInterface(CLSID_CorRuntimeHost)
 *     -> ICorRuntimeHost::Start
 *     -> ICorRuntimeHost::CreateDomain
 *     -> QI(IID_AppDomain)
 *     -> AppDomain.Load_3(runner bytes)
 *     -> Assembly.GetType_2("AppRuntime.Executor")
 *     -> Type.InvokeMember_3("ExecuteAssembly", base64, args)
 *
 * The domain and the runner stay resident for the life of the process: a
 * one-shot CLI has nothing to gain from tearing the runtime down.
 */

/* ------------------------------------------------------------------ */
/* Encoded names (XOR 0x41; decoded into stack buffers at runtime)     */
/* ------------------------------------------------------------------ */

static const BYTE s_obfMscoree[] = {
    0x2C, 0x32, 0x22, 0x2E, 0x33, 0x24, 0x24, 0x6F, 0x25, 0x2D, 0x2D
}; /* "mscoree.dll" */

static const BYTE s_obfOleaut[] = {
    0x2E, 0x2D, 0x24, 0x20, 0x34, 0x35, 0x72, 0x73, 0x6F, 0x25, 0x2D, 0x2D
}; /* "oleaut32.dll" */

static const BYTE s_obfVersion[] = {
    0x37, 0x75, 0x6F, 0x71, 0x6F, 0x72, 0x71, 0x72, 0x70, 0x78
}; /* "v4.0.30319" */

static const BYTE s_obfType[] = {
    0x00, 0x31, 0x31, 0x13, 0x34, 0x2F, 0x35, 0x28, 0x2C, 0x24,
    0x6F, 0x04, 0x39, 0x24, 0x22, 0x34, 0x35, 0x2E, 0x33
}; /* "AppRuntime.Executor" */

static const BYTE s_obfMethod[] = {
    0x04, 0x39, 0x24, 0x22, 0x34, 0x35, 0x24, 0x00,
    0x32, 0x32, 0x24, 0x2C, 0x23, 0x2D, 0x38
}; /* "ExecuteAssembly" */

static const BYTE s_obfPsMethod[] = {
    0x04, 0x39, 0x24, 0x22, 0x34, 0x35, 0x24, 0x11, 0x2E, 0x36,
    0x24, 0x33, 0x12, 0x29, 0x24, 0x2D, 0x2D
}; /* "ExecutePowerShell" */

/* ------------------------------------------------------------------ */
/* GUIDs                                                              */
/* ------------------------------------------------------------------ */

static const GUID G_CLSID_MetaHost  = { 0x9280188d, 0x0e8e, 0x4867, { 0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } };
static const GUID G_IID_MetaHost    = { 0xd332db9e, 0xb9b3, 0x4125, { 0x82, 0x07, 0xa1, 0x48, 0x84, 0xf5, 0x32, 0x16 } };
static const GUID G_IID_RuntimeInfo = { 0xbd39d1d2, 0xba2f, 0x486a, { 0x89, 0xb0, 0xb4, 0xb0, 0xcb, 0x46, 0x68, 0x91 } };
static const GUID G_CLSID_CorHost   = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };
static const GUID G_IID_CorHost     = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };
static const GUID G_IID_AppDomain   = { 0x05f696dc, 0x2b29, 0x3663, { 0xad, 0x8b, 0xc4, 0x38, 0x9c, 0xf2, 0xa7, 0x13 } };

/* Vtable slots on the mscoree/CLR interfaces. */
#define CLR_SLOT_META_GETRUNTIME       3
#define CLR_SLOT_INFO_GETINTERFACE     9
#define CLR_SLOT_CORHOST_START         10
#define CLR_SLOT_CORHOST_CREATEDOMAIN  12
#define CLR_SLOT_AD_LOAD3              45
#define CLR_SLOT_ASM_GETTYPE2          17
#define CLR_SLOT_TYPE_INVOKEMEMBER3    57

#define CLR_BIND_STATIC_PUBLIC_METHOD  (8 | 16 | 256)

/* ------------------------------------------------------------------ */
/* COM and oleaut32 helpers                                            */
/* ------------------------------------------------------------------ */

typedef struct _CLR_OBJ { void** v; } CLR_OBJ;

typedef HRESULT (STDMETHODCALLTYPE* PFN_QI)(CLR_OBJ*, const GUID*, PVOID*);
typedef ULONG   (STDMETHODCALLTYPE* PFN_REL)(CLR_OBJ*);
typedef HRESULT (STDMETHODCALLTYPE* PFN_CLR_CREATE)(const GUID*, const GUID*, PVOID*);
typedef HRESULT (STDMETHODCALLTYPE* PFN_META_GETRUNTIME)(CLR_OBJ*, LPCWSTR, const GUID*, PVOID*);
typedef HRESULT (STDMETHODCALLTYPE* PFN_INFO_GETINTERFACE)(CLR_OBJ*, const GUID*, const GUID*, PVOID*);
typedef HRESULT (STDMETHODCALLTYPE* PFN_CORHOST_START)(CLR_OBJ*);
typedef HRESULT (STDMETHODCALLTYPE* PFN_CORHOST_CREATEDOMAIN)(CLR_OBJ*, LPCWSTR, PVOID, PVOID*);
typedef HRESULT (STDMETHODCALLTYPE* PFN_AD_LOAD3)(CLR_OBJ*, SAFEARRAY*, PVOID*);
typedef HRESULT (STDMETHODCALLTYPE* PFN_ASM_GETTYPE)(CLR_OBJ*, BSTR, PVOID*);
typedef HRESULT (STDMETHODCALLTYPE* PFN_TYPE_INVOKEMEMBER)(CLR_OBJ*, BSTR, INT, PVOID, VARIANT, SAFEARRAY*, VARIANT*);

typedef struct _CLR_OA
{
    BSTR       (WINAPI* pSysAllocString)(const OLECHAR*);
    BSTR       (WINAPI* pSysAllocStringLen)(const OLECHAR*, UINT);
    void       (WINAPI* pSysFreeString)(BSTR);
    SAFEARRAY* (WINAPI* pSafeArrayCreate)(VARTYPE, UINT, SAFEARRAYBOUND*);
    SAFEARRAY* (WINAPI* pSafeArrayCreateVector)(VARTYPE, LONG, ULONG);
    void       (WINAPI* pSafeArrayDestroy)(SAFEARRAY*);
    HRESULT    (WINAPI* pSafeArrayAccessData)(SAFEARRAY*, void**);
    HRESULT    (WINAPI* pSafeArrayUnaccessData)(SAFEARRAY*);
    HRESULT    (WINAPI* pSafeArrayPutElement)(SAFEARRAY*, LONG*, void*);
    void       (WINAPI* pVariantClear)(VARIANTARG*);
} CLR_OA;

static CLR_OA g_Oa;

static CLR_OBJ* g_pCorHost;
static CLR_OBJ* g_pDomain;
static CLR_OBJ* g_pRunnerAsm;
static CLR_OBJ* g_pRunnerType;
static BOOL     g_bClrStarted;

/* ------------------------------------------------------------------ */
/* Error reporting                                                     */
/* ------------------------------------------------------------------ */

#ifdef PEX_NATIVE
static BOOL ClrFailSilent(PCHAR szError, DWORD cchError)
{
    if (szError != NULL && cchError != 0) szError[0] = 0;
    return FALSE;
}
#define ClrFail(szError, cchError, ...) ClrFailSilent(szError, cchError)
#else
static BOOL ClrFail(PCHAR szError, DWORD cchError, PCSTR szFormat, ...)
{
    va_list pArgList;

    if (szError != NULL && cchError != 0)
    {
        va_start(pArgList, szFormat);
        _vsnprintf_s(szError, cchError, _TRUNCATE, szFormat, pArgList);
        va_end(pArgList);
    }
    return FALSE;
}
#endif

static PVOID ClrAlloc(SIZE_T cbSize)
{
    return ((PVOID (WINAPI*)(PVOID, SIZE_T, DWORD, DWORD))g_pfnVirtualAlloc)(
        NULL, cbSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static VOID ClrFree(PVOID pMemory)
{
    if (pMemory != NULL)
    {
        ((BOOL (WINAPI*)(PVOID, SIZE_T, DWORD))g_pfnVirtualFree)(pMemory, 0, MEM_RELEASE);
    }
}

/* ------------------------------------------------------------------ */
/* String helpers                                                      */
/* ------------------------------------------------------------------ */

static VOID ClrDecodeAscii(const BYTE* pSrc, DWORD cbSrc, PCHAR szDst)
{
    DWORD i;

    for (i = 0; i < cbSrc; i++) szDst[i] = (CHAR)(pSrc[i] ^ 0x41);
    szDst[cbSrc] = 0;
}

static VOID ClrDecodeWide(const BYTE* pSrc, DWORD cbSrc, PWSTR wszDst)
{
    DWORD i;

    for (i = 0; i < cbSrc; i++) wszDst[i] = (WCHAR)(pSrc[i] ^ 0x41);
    wszDst[cbSrc] = 0;
}

static PVOID ClrLoadModule(const BYTE* pObf, DWORD cbObf)
{
    CHAR  szName[64];
    PVOID pModule;

    ClrDecodeAscii(pObf, cbObf, szName);
    pModule = NativeGetModuleByHash(NativeHash(szName));
    if (pModule == NULL && g_pfnLoadLibraryA != NULL)
    {
        pModule = ((HMODULE (WINAPI*)(PCSTR))g_pfnLoadLibraryA)(szName);
    }
    return pModule;
}

static BSTR ClrUtf8ToBstr(PCSTR szText)
{
    int  cch;
    BSTR bsText;

    if (szText == NULL) szText = "";
    cch = ((int (WINAPI*)(UINT, DWORD, PCSTR, int, PWSTR, int))g_pfnMultiByteToWideChar)(
        CP_UTF8, 0, szText, -1, NULL, 0);
    if (cch <= 1) return g_Oa.pSysAllocStringLen(NULL, 0);

    bsText = g_Oa.pSysAllocStringLen(NULL, (UINT)(cch - 1));
    if (bsText != NULL)
    {
        ((int (WINAPI*)(UINT, DWORD, PCSTR, int, PWSTR, int))g_pfnMultiByteToWideChar)(
            CP_UTF8, 0, szText, -1, bsText, cch);
    }
    return bsText;
}

static BOOL ClrBstrToUtf8(BSTR bsText, PCHAR* ppszOutput, PDWORD pcbOutput,
                          PCHAR szError, DWORD cchError)
{
    int   cbUtf8;
    PCHAR pszOutput;

    *ppszOutput = NULL;
    *pcbOutput = 0;

    cbUtf8 = ((int (WINAPI*)(UINT, DWORD, const WCHAR*, int, PCHAR, int, const CHAR*, int*))g_pfnWideCharToMultiByte)(
        CP_UTF8, 0, bsText, -1, NULL, 0, NULL, NULL);
    if (cbUtf8 <= 0) return ClrFail(szError, cchError, "cannot convert the runner output");

    pszOutput = (PCHAR)ClrAlloc((SIZE_T)cbUtf8);
    if (pszOutput == NULL) return ClrFail(szError, cchError, "out of memory");

    ((int (WINAPI*)(UINT, DWORD, const WCHAR*, int, PCHAR, int, const CHAR*, int*))g_pfnWideCharToMultiByte)(
        CP_UTF8, 0, bsText, -1, pszOutput, cbUtf8, NULL, NULL);

    *ppszOutput = pszOutput;
    *pcbOutput = (DWORD)(cbUtf8 - 1);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* oleaut32                                                            */
/* ------------------------------------------------------------------ */

static BOOL ClrOaResolve(PCHAR szError, DWORD cchError)
{
    static BOOL s_bResolved = FALSE;
    PVOID pOleaut;

    if (s_bResolved) return TRUE;

    pOleaut = ClrLoadModule(s_obfOleaut, sizeof(s_obfOleaut));
    if (pOleaut == NULL) return ClrFail(szError, cchError, "cannot load oleaut32.dll");

#define CLR_OA_RESOLVE(field, hash) \
    g_Oa.field = (PVOID)NativeGetProcFromModule(pOleaut, hash); \
    if (g_Oa.field == NULL) return ClrFail(szError, cchError, "oleaut32 export missing")

    CLR_OA_RESOLVE(pSysAllocString,       HASH_SYSALLOCSTRING);
    CLR_OA_RESOLVE(pSysAllocStringLen,    HASH_SYSALLOCSTRINGLEN);
    CLR_OA_RESOLVE(pSysFreeString,        HASH_SYSFREESTRING);
    CLR_OA_RESOLVE(pSafeArrayCreate,      HASH_SAFEARRAYCREATE);
    CLR_OA_RESOLVE(pSafeArrayCreateVector, HASH_SAFEARRAYCREATEVECTOR);
    CLR_OA_RESOLVE(pSafeArrayDestroy,     HASH_SAFEARRAYDESTROY);
    CLR_OA_RESOLVE(pSafeArrayAccessData,  HASH_SAFEARRAYACCESSDATA);
    CLR_OA_RESOLVE(pSafeArrayUnaccessData, HASH_SAFEARRAYUNACCESSDATA);
    CLR_OA_RESOLVE(pSafeArrayPutElement,  HASH_SAFEARRAYPUTELEMENT);
    CLR_OA_RESOLVE(pVariantClear,         HASH_VARIANTCLEAR);

#undef CLR_OA_RESOLVE

    s_bResolved = TRUE;
    return TRUE;
}

static HRESULT ClrQi(CLR_OBJ* pObject, const GUID* pIid, PVOID* ppOut)
{
    return ((PFN_QI)pObject->v[0])(pObject, pIid, ppOut);
}

static VOID ClrRel(CLR_OBJ* pObject)
{
    if (pObject != NULL) ((PFN_REL)pObject->v[2])(pObject);
}

static SAFEARRAY* ClrMakeByteArray(const BYTE* pbData, DWORD cbData)
{
    SAFEARRAYBOUND bound;
    SAFEARRAY*     psa;
    void*          pvData = NULL;

    bound.cElements = cbData;
    bound.lLbound = 0;

    psa = g_Oa.pSafeArrayCreate(VT_UI1, 1, &bound);
    if (psa == NULL) return NULL;

    if (g_Oa.pSafeArrayAccessData(psa, &pvData) != S_OK)
    {
        g_Oa.pSafeArrayDestroy(psa);
        return NULL;
    }
    CopyMemory(pvData, pbData, cbData);
    g_Oa.pSafeArrayUnaccessData(psa);
    return psa;
}

/* ------------------------------------------------------------------ */
/* CLR startup                                                         */
/* ------------------------------------------------------------------ */

static BOOL ClrEnsure(PCHAR szError, DWORD cchError)
{
    PVOID  pMscoree;
    PFN_CLR_CREATE pfnCreate;
    CLR_OBJ* pMeta = NULL;
    CLR_OBJ* pInfo = NULL;
    CLR_OBJ* pThunk = NULL;
    WCHAR  wszVersion[32];
    HRESULT hr;

    if (g_bClrStarted) return TRUE;

    pMscoree = ClrLoadModule(s_obfMscoree, sizeof(s_obfMscoree));
    if (pMscoree == NULL) return ClrFail(szError, cchError, "cannot load mscoree.dll");

    pfnCreate = (PFN_CLR_CREATE)NativeGetProcFromModule(pMscoree, HASH_CLRCREATEINSTANCE);
    if (pfnCreate == NULL) return ClrFail(szError, cchError, "CLRCreateInstance missing");

    ClrDecodeWide(s_obfVersion, sizeof(s_obfVersion), wszVersion);

    hr = pfnCreate(&G_CLSID_MetaHost, &G_IID_MetaHost, (PVOID*)&pMeta);
    if (FAILED(hr) || pMeta == NULL) return ClrFail(szError, cchError, "CLRCreateInstance failed (0x%08x)", hr);

    hr = ((PFN_META_GETRUNTIME)pMeta->v[CLR_SLOT_META_GETRUNTIME])(
        pMeta, wszVersion, &G_IID_RuntimeInfo, (PVOID*)&pInfo);
    ClrRel(pMeta);
    if (FAILED(hr) || pInfo == NULL) return ClrFail(szError, cchError, "GetRuntime failed (0x%08x)", hr);

    hr = ((PFN_INFO_GETINTERFACE)pInfo->v[CLR_SLOT_INFO_GETINTERFACE])(
        pInfo, &G_CLSID_CorHost, &G_IID_CorHost, (PVOID*)&g_pCorHost);
    ClrRel(pInfo);
    if (FAILED(hr) || g_pCorHost == NULL)
    {
        g_pCorHost = NULL;
        return ClrFail(szError, cchError, "GetInterface(ICorRuntimeHost) failed (0x%08x)", hr);
    }

    hr = ((PFN_CORHOST_START)g_pCorHost->v[CLR_SLOT_CORHOST_START])(g_pCorHost);
    if (FAILED(hr))
    {
        ClrRel(g_pCorHost);
        g_pCorHost = NULL;
        return ClrFail(szError, cchError, "CLR Start failed (0x%08x)", hr);
    }

    {
        WCHAR wszDomain[17];
        DWORD dwSeed = (DWORD)__rdtsc() ^ (DWORD)(ULONG_PTR)&g_bClrStarted;
        DWORD i;

        for (i = 0; i < 8; i++)
        {
            DWORD dwDigit = (dwSeed >> (28 - i * 4)) & 0xF;
            wszDomain[i] = (WCHAR)(dwDigit < 10 ? L'0' + dwDigit : L'a' + (dwDigit - 10));
        }
        wszDomain[8] = 0;

        hr = ((PFN_CORHOST_CREATEDOMAIN)g_pCorHost->v[CLR_SLOT_CORHOST_CREATEDOMAIN])(
            g_pCorHost, wszDomain, NULL, (PVOID*)&pThunk);
        if (FAILED(hr) || pThunk == NULL) return ClrFail(szError, cchError, "CreateDomain failed (0x%08x)", hr);
    }

    hr = ClrQi(pThunk, &G_IID_AppDomain, (PVOID*)&g_pDomain);
    ClrRel(pThunk);
    if (FAILED(hr) || g_pDomain == NULL)
    {
        g_pDomain = NULL;
        return ClrFail(szError, cchError, "AppDomain QI failed (0x%08x)", hr);
    }

    g_bClrStarted = TRUE;
    return TRUE;
}

static BOOL ClrLoadRunner(PCHAR szError, DWORD cchError)
{
    PBYTE     pbPlain;
    SAFEARRAY* psa = NULL;
    BSTR      bsType = NULL;
    WCHAR     wszType[64];
    HRESULT   hr;
    DWORD     i;

    if (g_pRunnerType != NULL) return TRUE;
    if (!ClrEnsure(szError, cchError)) return FALSE;
    if (!ClrOaResolve(szError, cchError)) return FALSE;

    pbPlain = (PBYTE)ClrAlloc(G_ABCLRRUNNER_SIZE);
    if (pbPlain == NULL) return ClrFail(szError, cchError, "out of memory");

    for (i = 0; i < G_ABCLRRUNNER_SIZE; i++)
    {
        pbPlain[i] = (BYTE)(g_abClrRunner[i] ^ g_abClrRunner_Key[i & 15]);
    }

    psa = ClrMakeByteArray(pbPlain, G_ABCLRRUNNER_SIZE);
    for (i = 0; i < G_ABCLRRUNNER_SIZE; i++) pbPlain[i] = 0;
    ClrFree(pbPlain);

    if (psa == NULL) return ClrFail(szError, cchError, "cannot create the runner SAFEARRAY");

    hr = ((PFN_AD_LOAD3)g_pDomain->v[CLR_SLOT_AD_LOAD3])(g_pDomain, psa, (PVOID*)&g_pRunnerAsm);
    g_Oa.pSafeArrayDestroy(psa);
    if (FAILED(hr) || g_pRunnerAsm == NULL)
    {
        g_pRunnerAsm = NULL;
        return ClrFail(szError, cchError, "AppDomain.Load_3 failed (0x%08x)", hr);
    }

    ClrDecodeWide(s_obfType, sizeof(s_obfType), wszType);
    bsType = g_Oa.pSysAllocString(wszType);
    if (bsType == NULL) return ClrFail(szError, cchError, "out of memory");

    hr = ((PFN_ASM_GETTYPE)g_pRunnerAsm->v[CLR_SLOT_ASM_GETTYPE2])(
        g_pRunnerAsm, bsType, (PVOID*)&g_pRunnerType);
    g_Oa.pSysFreeString(bsType);
    if (FAILED(hr) || g_pRunnerType == NULL)
    {
        g_pRunnerType = NULL;
        return ClrFail(szError, cchError, "GetType(AppRuntime.Executor) failed (0x%08x)", hr);
    }

    return TRUE;
}

/* ------------------------------------------------------------------ */
/* Invocation                                                          */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Invocation                                                          */
/* ------------------------------------------------------------------ */

#define CLR_METHOD_ASSEMBLY   0
#define CLR_METHOD_POWERSHELL 1

static BOOL ClrInvokeRunner(int nMethod, PCSTR szArg0, PCSTR szArg1,
                            PCHAR szError, DWORD cchError,
                            PCHAR* ppszOutput, PDWORD pcbOutput)
{
    SAFEARRAY* psaArgs = NULL;
    VARIANT    vtRet;
    VARIANT    vtEmpty;
    VARIANT    vtArg;
    BSTR       absArgs[2] = { NULL, NULL };
    BSTR       bsMethod = NULL;
    WCHAR      wszMethod[64];
    PCSTR      apszArgs[2];
    int        cArgs;
    int        i;
    LONG       idx;
    HRESULT    hr;
    BOOL       bOk = FALSE;

    if (ppszOutput == NULL || pcbOutput == NULL) return FALSE;
    *ppszOutput = NULL;
    *pcbOutput = 0;
    if (szError != NULL && cchError != 0) szError[0] = 0;

    if (!ClrLoadRunner(szError, cchError)) return FALSE;

    apszArgs[0] = (szArg0 != NULL) ? szArg0 : "";
    apszArgs[1] = (szArg1 != NULL) ? szArg1 : "";
    cArgs = (nMethod == CLR_METHOD_POWERSHELL) ? 1 : 2;

    ZeroMemory(&vtRet, sizeof(vtRet));
    ZeroMemory(&vtEmpty, sizeof(vtEmpty));

    psaArgs = g_Oa.pSafeArrayCreateVector(VT_VARIANT, 0, cArgs);
    if (psaArgs == NULL)
    {
        return ClrFail(szError, cchError, "cannot create the argument SAFEARRAY");
    }

    for (i = 0; i < cArgs; i++)
    {
        absArgs[i] = ClrUtf8ToBstr(apszArgs[i]);
        if (absArgs[i] == NULL)
        {
            ClrFail(szError, cchError, "out of memory");
            goto cleanup;
        }

        ZeroMemory(&vtArg, sizeof(vtArg));
        vtArg.vt = VT_BSTR;
        vtArg.bstrVal = absArgs[i];
        idx = (LONG)i;
        g_Oa.pSafeArrayPutElement(psaArgs, &idx, &vtArg);
    }

    if (nMethod == CLR_METHOD_POWERSHELL)
    {
        ClrDecodeWide(s_obfPsMethod, sizeof(s_obfPsMethod), wszMethod);
    }
    else
    {
        ClrDecodeWide(s_obfMethod, sizeof(s_obfMethod), wszMethod);
    }

    bsMethod = g_Oa.pSysAllocString(wszMethod);
    if (bsMethod == NULL)
    {
        ClrFail(szError, cchError, "out of memory");
        goto cleanup;
    }

    hr = ((PFN_TYPE_INVOKEMEMBER)g_pRunnerType->v[CLR_SLOT_TYPE_INVOKEMEMBER3])(
        g_pRunnerType, bsMethod, CLR_BIND_STATIC_PUBLIC_METHOD,
        NULL, vtEmpty, psaArgs, &vtRet);

    if (FAILED(hr))
    {
        ClrFail(szError, cchError, "runner call failed (0x%08x)", hr);
        goto cleanup;
    }

    if (vtRet.vt == VT_BSTR && vtRet.bstrVal != NULL)
    {
        bOk = ClrBstrToUtf8(vtRet.bstrVal, ppszOutput, pcbOutput, szError, cchError);
    }
    else
    {
        PCHAR pszEmpty = (PCHAR)ClrAlloc(1);

        if (pszEmpty != NULL)
        {
            pszEmpty[0] = 0;
            *ppszOutput = pszEmpty;
            *pcbOutput = 0;
            bOk = TRUE;
        }
        else
        {
            ClrFail(szError, cchError, "out of memory");
        }
    }

cleanup:
    if (vtRet.vt != VT_EMPTY) g_Oa.pVariantClear(&vtRet);
    if (psaArgs != NULL) g_Oa.pSafeArrayDestroy(psaArgs);
    if (bsMethod != NULL) g_Oa.pSysFreeString(bsMethod);
    for (i = 0; i < cArgs; i++)
    {
        if (absArgs[i] != NULL) g_Oa.pSysFreeString(absArgs[i]);
    }
    return bOk;
}

BOOL ClrRunAssembly(const BYTE* pbAssembly, DWORD cbAssembly, PCSTR szArguments,
                    PCHAR szError, DWORD cchError,
                    PCHAR* ppszOutput, PDWORD pcbOutput)
{
    SIZE_T cbB64;
    PCHAR  szB64;
    BOOL   bOk;

    if (ppszOutput == NULL || pcbOutput == NULL) return FALSE;
    *ppszOutput = NULL;
    *pcbOutput = 0;
    if (szError != NULL && cchError != 0) szError[0] = 0;

    if (pbAssembly == NULL || cbAssembly == 0)
    {
        return ClrFail(szError, cchError, "empty assembly");
    }
    if (cbAssembly > 64u * 1024u * 1024u)
    {
        return ClrFail(szError, cchError, "assembly is too large");
    }

    cbB64 = (((SIZE_T)cbAssembly + 2) / 3) * 4 + 1;
    szB64 = (PCHAR)ClrAlloc(cbB64);
    if (szB64 == NULL) return ClrFail(szError, cchError, "out of memory");

    if (PexBase64Encode(pbAssembly, cbAssembly, szB64, (DWORD)cbB64) == 0)
    {
        ClrFree(szB64);
        return ClrFail(szError, cchError, "base64 encoding failed");
    }

    bOk = ClrInvokeRunner(CLR_METHOD_ASSEMBLY, szB64, szArguments,
                          szError, cchError, ppszOutput, pcbOutput);
    ClrFree(szB64);
    return bOk;
}

BOOL ClrRunPowerShell(PCSTR szScript, PCHAR szError, DWORD cchError,
                      PCHAR* ppszOutput, PDWORD pcbOutput)
{
    return ClrInvokeRunner(CLR_METHOD_POWERSHELL, szScript, NULL,
                           szError, cchError, ppszOutput, pcbOutput);
}

VOID ClrFreeOutput(PCHAR pszOutput)
{
    ClrFree(pszOutput);
}