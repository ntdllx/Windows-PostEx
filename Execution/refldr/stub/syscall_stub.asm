; syscall_stub.asm -- generic indirect syscall trampoline (MASM x64)
;
; Prototype (matches the C declaration):
;   NTSTATUS StubIndirectSyscall(DWORD dwSsn, PVOID pGadget,
;                                ULONG_PTR a1, ULONG_PTR a2,
;                                ULONG_PTR a3, ULONG_PTR a4,
;                                ULONG_PTR a5, ULONG_PTR a6);
;
; On entry the compiler has already placed the stack arguments where the
; calling convention expects them, so a5/a6 only need to move down two slots
; into the positions the kernel reads (rsp+28h / rsp+30h). Nothing is written
; outside the caller's argument area.
;
; x64 syscall ABI: r10 = a1, rdx = a2, r8 = a3, r9 = a4,
; [rsp+28h] = a5, [rsp+30h] = a6, eax = SSN.

OPTION CASEMAP:NONE

.code

PUBLIC StubIndirectSyscall
StubIndirectSyscall PROC
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
    jmp     r11                         ; gadget: syscall; ret
StubIndirectSyscall ENDP

END
