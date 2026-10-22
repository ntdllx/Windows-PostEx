#pragma once

#include <windows.h>

/*
 * Indirect syscall layer for the host-side mapper.
 *
 * Same technique as the payload-side stub: resolve SSNs from ntdll stubs
 * (Halo's Gate for hooked entries), collect syscall;ret gadgets from ntdll's
 * executable sections, and jump through a generic trampoline. The difference
 * is that this module lives in a normal image, so the SSN/gadget table can be
 * held in globals instead of being rebuilt on the stack.
 */

#define PEX_CURRENT_PROCESS ((HANDLE)(LONG_PTR)-1)
#define PEX_MAX_GADGETS 64
#define PEX_SSN_SCAN    8

typedef struct _PEX_SYSCALL
{
    DWORD dwSsnProtect;
    DWORD dwSsnCreateSection;
    DWORD dwSsnMapView;
    DWORD dwSsnUnmapView;
    PVOID aGadgets[PEX_MAX_GADGETS];
    DWORD cGadgets;
} PEX_SYSCALL, *PPEX_SYSCALL;

BOOL PexSysInit(PPEX_SYSCALL pCtx);

NTSTATUS PexSysProtect(PPEX_SYSCALL pCtx, PVOID pAddress, SIZE_T cbSize,
                        DWORD flNewProtect, PDWORD pflOldProtect);

NTSTATUS PexSysCreateSection(PPEX_SYSCALL pCtx, PHANDLE phSection,
                              ACCESS_MASK flDesiredAccess, PVOID pObjectAttributes,
                              PLARGE_INTEGER pliMaximumSize,
                              ULONG flPageProtection, ULONG flAllocationAttributes,
                              HANDLE hFile);

NTSTATUS PexSysMapView(PPEX_SYSCALL pCtx, HANDLE hSection, HANDLE hProcess,
                        PVOID* ppBase, ULONG_PTR ulZeroBits, SIZE_T cbCommitSize,
                        PLARGE_INTEGER pliSectionOffset, PSIZE_T pcbViewSize,
                        ULONG flInheritDisposition, ULONG flAllocationType,
                        ULONG flWin32Protect);

NTSTATUS PexSysUnmapView(PPEX_SYSCALL pCtx, HANDLE hProcess, PVOID pBase);
