; syscall_stub.asm -- generic indirect syscall trampoline (MASM x64)
;
;   NTSTATUS PexIndirectSyscall(DWORD dwSsn, PVOID pGadget,
;                                ULONG_PTR a1 ... ULONG_PTR a10);
;
; Ten arguments cover NtMapViewOfSection, the widest call the mapper needs.
; The compiler places stack arguments where the native convention expects
; them; this routine shifts a5..a10 down two slots, which is where the kernel
; reads them.
;
; x64 syscall ABI: r10 = a1, rdx = a2, r8 = a3, r9 = a4,
; [rsp+28h] = a5, [rsp+30h] = a6, [rsp+38h] = a7,
; [rsp+40h] = a8, [rsp+48h] = a9, [rsp+50h] = a10, eax = SSN.

OPTION CASEMAP:NONE

.code

PUBLIC PexIndirectSyscall
PexIndirectSyscall PROC
    mov     r11, rdx                    ; gadget
    mov     eax, ecx                    ; SSN
    mov     r10, r8                     ; a1
    mov     rdx, r9                     ; a2
    mov     r8,  QWORD PTR [rsp+28h]    ; a3
    mov     r9,  QWORD PTR [rsp+30h]    ; a4

    mov     rcx, QWORD PTR [rsp+38h]    ; a5
    mov     QWORD PTR [rsp+28h], rcx
    mov     rcx, QWORD PTR [rsp+40h]    ; a6
    mov     QWORD PTR [rsp+30h], rcx
    mov     rcx, QWORD PTR [rsp+48h]    ; a7
    mov     QWORD PTR [rsp+38h], rcx
    mov     rcx, QWORD PTR [rsp+50h]    ; a8
    mov     QWORD PTR [rsp+40h], rcx
    mov     rcx, QWORD PTR [rsp+58h]    ; a9
    mov     QWORD PTR [rsp+48h], rcx
    mov     rcx, QWORD PTR [rsp+60h]    ; a10
    mov     QWORD PTR [rsp+50h], rcx

    jmp     r11                         ; gadget: syscall; ret
PexIndirectSyscall ENDP

END
