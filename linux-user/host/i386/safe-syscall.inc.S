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

    .global safe_syscall_base
    .global safe_syscall_start
    .global safe_syscall_end
    .type   safe_syscall_base, @function

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
    /* Save ebx esi edi ebp, as the calling convention requires */
    pushl %ebp
    .cfi_adjust_cfa_offset 4
    .cfi_rel_offset ebp, 0
    pushl %edi
    .cfi_adjust_cfa_offset 4
    .cfi_rel_offset edi, 0
    pushl %esi
    .cfi_adjust_cfa_offset 4
    .cfi_rel_offset esi, 0
    pushl %ebx
    .cfi_adjust_cfa_offset 4
    .cfi_rel_offset ebx, 0

    /* The syscall calling convention isn't the same as the
     * C one:
     * we enter with all arguments on the stack:
     *           *signal_pending
     *           syscall number
     *           syscall arguments
     *           and return the result in eax
     * and the syscall instruction needs
     *           eax == syscall number
     *           ebx, ecx, edx, esi, edi, ebp == syscall arguments
     *           and returns the result in eax
     * Shuffle everything around appropriately.
     *
     * At this point the stack layout is:
     * 48(%esp)     syscall arg 6
     * 44(%esp)     syscall arg 5
     * 40(%esp)     syscall arg 4
     * 36(%esp)     syscall arg 3
     * 32(%esp)     syscall arg 2
     * 28(%esp)     syscall arg 1
     * 24(%esp)     syscall number
     * 20(%esp)     *signal_pending
     * 16(%esp)     return address
     * 12(%esp)     saved EBP
     *  8(%esp)     saved EDI
     *  4(%esp)     saved ESI
     *   (%esp)     saved EBX
     */
    /* syscall arguments */
    movl 48(%esp), %ebp
    movl 44(%esp), %edi
    movl 40(%esp), %esi
    movl 36(%esp), %edx
    movl 32(%esp), %ecx
    movl 28(%esp), %ebx

    /* This next sequence of code works in conjunction with the
     * rewind_if_safe_syscall_function(). If a signal is taken
     * and the interrupted PC is anywhere between 'safe_syscall_start'
     * and 'safe_syscall_end' then we rewind it to 'safe_syscall_start'.
     * The code sequence must therefore be able to cope with this, and
     * the syscall instruction must be the final one in the sequence.
     * For i386 we have absolutely no spare registers at the point of
     * the syscall, so we must load *signal_pending and the syscall
     * number off the stack inside the start/end section.
     */
safe_syscall_start:
    /* *signal_pending */
    movl 20(%esp), %eax
    /* if signal_pending is non-zero, don't do the call */
    testl $1, (%eax)
    jnz return_ERESTARTSYS
    movl 24(%esp), %eax
    int $0x80
safe_syscall_end:
    /* code path for having successfully executed the syscall */
    .cfi_remember_state
    popl %ebx
    .cfi_adjust_cfa_offset -4
    .cfi_restore ebx
    popl %esi
    .cfi_adjust_cfa_offset -4
    .cfi_restore esi
    popl %edi
    .cfi_adjust_cfa_offset -4
    .cfi_restore edi
    popl %ebp
    .cfi_adjust_cfa_offset -4
    .cfi_restore ebp
    ret

return_ERESTARTSYS:
    /* code path when we didn't execute the syscall */
    .cfi_restore_state
    mov $-TARGET_ERESTARTSYS, %eax
    popl %ebx
    .cfi_adjust_cfa_offset -4
    .cfi_restore ebx
    popl %esi
    .cfi_adjust_cfa_offset -4
    .cfi_restore esi
    popl %edi
    .cfi_adjust_cfa_offset -4
    .cfi_restore edi
    popl %ebp
    .cfi_adjust_cfa_offset -4
    .cfi_restore ebp
    ret
    .cfi_endproc

    .size   safe_syscall_base, .-safe_syscall_base
