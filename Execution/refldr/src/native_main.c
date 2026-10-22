#include "pex_native.h"

#include "loader.h"

/*
 * Native entry for refldr.
 *
 * Same core as the development build, with every host service coming from the
 * runtime: no CRT and no imports. Output is numeric so the binary carries no
 * display strings.
 */

void NativeEntry(void)
{
    REFL_IMAGE image;
    ULONG_PTR  ulValue = 0;
    CHAR       szError[1];
    PCSTR      szPath;
    PCSTR      szExport;
    BOOL       bKeep;
    DWORD      dwFlags;

    if (!NativeInit()) NativeExit(1);
    if (NativeArgc() < 3) NativeExit(1);
    if (NativeHash(NativeArgv(1)) != HASH_RUN) NativeExit(1);

    szPath = NativeArgv(2);
    szExport = NativeOptionValue(HASH___EXPORT);
    bKeep = NativeHasFlag(HASH___KEEP);

    if (!ReflLoad(szPath, FALSE, &image, szError, sizeof(szError)))
    {
        NativeExit(2);
    }

    NativePrintHex((ULONG_PTR)image.pBase);
    NativePrintChar('\n');
    NativePrintHex(image.dwSizeOfImage);
    NativePrintChar('\n');

    dwFlags = (image.bPrivate ? 1u : 0u) | (image.bInLoaderList ? 2u : 0u);
    NativePrintHex(dwFlags);
    NativePrintChar('\n');

    if (szExport != NULL)
    {
        if (!ReflInvoke(&image, szExport, &ulValue))
        {
            ReflUnload(&image);
            NativeExit(3);
        }
        NativePrintHex(ulValue);
        NativePrintChar('\n');
    }

    if (!bKeep) ReflUnload(&image);

    NativeExit(0);
}
