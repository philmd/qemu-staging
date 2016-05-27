/*
 * safe-syscall.inc.S : host-specific assembly fragment
 * to handle signals occurring at the same time as system calls.
 * This is intended to be included by linux-user/safe-syscall.S
 *
 *  * Written by Peter Maydell <peter.maydell@linaro.org>
 *
 * Copyright (C) 2016 Linaro Limited
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

    .syntax unified
    .arm
    .align 2

    .global safe_syscall_base
    .global safe_syscall_start
    .global safe_syscall_end
    .type   safe_syscall_base, %function

    /* This is the entry point for making a system call. The calling
     * convention here is that of a C varargs function with the
     * first argument an 'int *' to the signal_pending flag, the
     * second one the system call number (as a 'long'), and all further
     * arguments being syscall arguments (also 'long').
     * We return a long which is the syscall's return value, which
     * may be negative-errno on failure. Conversion to the
     * -1-and-errno-set convention is done by the calling wrapper.
     */
safe_syscall_base:
    .cfi_startproc

    /* The syscall calling convention isn't the same as the
     * C one:
     * we enter with r0 == *signal_pending
     *           r1 == syscall number
     *           r2, r3, (stack), (stack), ... == syscall arguments
     *           and return the result in r0
     * and the syscall instruction needs
     *           r7 == syscall number
     *           r0, r1, r2, r3, r4, r5, r6 == syscall arguments
     *           and returns the result in r0
     * Shuffle everything around appropriately.
     */
    mov r12, sp
    .cfi_def_cfa r12, 0
    push {r4, r5, r6, r7, r8, r14}
    .cfi_offset r14, -4
    .cfi_offset r8, -8
    .cfi_offset r7, -12
    .cfi_offset r6, -16
    .cfi_offset r5, -20
    .cfi_offset r4, -24
    mov r8, r0 /* signal-pending pointer */
    mov r7, r1 /* syscall number */
    /* and the syscall arguments */
    mov r0, r2
    mov r1, r3
    ldmfd r12, {r2, r3, r4, r5, r6}

    /* This next sequence of code works in conjunction with the
     * rewind_if_safe_syscall_function(). If a signal is taken
     * and the interrupted PC is anywhere between 'safe_syscall_start'
     * and 'safe_syscall_end' then we rewind it to 'safe_syscall_start'.
     * The code sequence must therefore be able to cope with this, and
     * the syscall instruction must be the final one in the sequence.
     */
safe_syscall_start:
    /* if signal_pending is non-zero, don't do the call */
    ldr r14, [r8]
    cmp r14, #0
    bne return_ERESTARTSYS
    swi 0x0
safe_syscall_end:
    /* code path for having successfully executed the syscall */
    /* NB: we assume we're not trying to do old ARMv4T interworking */
    pop {r4, r5, r6, r7, r8, pc}

return_ERESTARTSYS:
    /* code path when we didn't execute the syscall */
    ldr r0, =$-TARGET_ERESTARTSYS
    pop {r4, r5, r6, r7, r8, pc}
    .cfi_endproc

    .size   safe_syscall_base, .-safe_syscall_base
