#include <windows.h>
#include <intrin.h>

/* CRT replacements, linked only into the /NODEFAULTLIB targets. Keeping them
 * in a separate translation unit lets the development builds use the real
 * CRT without duplicate symbols. */

void* __cdecl memset(void* pDestination, int nValue, size_t cbSize)
{
    PUCHAR pBytes = (PUCHAR)pDestination;
    size_t i;

    if (nValue == 0)
    {
        __stosb(pBytes, 0, cbSize);
    }
    else
    {
        for (i = 0; i < cbSize; i++) pBytes[i] = (UCHAR)nValue;
    }
    return pDestination;
}

void* __cdecl memcpy(void* pDestination, const void* pSource, size_t cbSize)
{
    __movsb((PUCHAR)pDestination, (const UCHAR*)pSource, cbSize);
    return pDestination;
}