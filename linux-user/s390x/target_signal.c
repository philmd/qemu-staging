/*
 *  Emulation of Linux signals : s390 specific code
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/ucontext.h>
#include <sys/resource.h>

#include "qemu.h"
#include "qemu-common.h"
#include "signal-common.h"
#include "target_signal.h"


#define __NUM_GPRS 16
#define __NUM_FPRS 16
#define __NUM_ACRS 16

#define S390_SYSCALL_SIZE   2
#define __SIGNAL_FRAMESIZE      160 /* FIXME: 31-bit mode -> 96 */

#define _SIGCONTEXT_NSIG        64
#define _SIGCONTEXT_NSIG_BPW    64 /* FIXME: 31-bit mode -> 32 */
#define _SIGCONTEXT_NSIG_WORDS  (_SIGCONTEXT_NSIG / _SIGCONTEXT_NSIG_BPW)
#define _SIGMASK_COPY_SIZE    (sizeof(unsigned long)*_SIGCONTEXT_NSIG_WORDS)
#define PSW_ADDR_AMODE            0x0000000000000000UL /* 0x80000000UL for 31-bit */
#define S390_SYSCALL_OPCODE ((uint16_t)0x0a00)

typedef struct {
    target_psw_t psw;
    target_ulong gprs[__NUM_GPRS];
    unsigned int acrs[__NUM_ACRS];
} target_s390_regs_common;

typedef struct {
    unsigned int fpc;
    double   fprs[__NUM_FPRS];
} target_s390_fp_regs;

typedef struct {
    target_s390_regs_common regs;
    target_s390_fp_regs     fpregs;
} target_sigregs;

struct target_sigcontext {
    target_ulong   oldmask[_SIGCONTEXT_NSIG_WORDS];
    target_sigregs *sregs;
};

typedef struct {
    uint8_t callee_used_stack[__SIGNAL_FRAMESIZE];
    struct target_sigcontext sc;
    target_sigregs sregs;
    int signo;
    uint8_t retcode[S390_SYSCALL_SIZE];
} sigframe;

struct target_ucontext {
    target_ulong tuc_flags;
    struct target_ucontext *tuc_link;
    target_stack_t tuc_stack;
    target_sigregs tuc_mcontext;
    target_sigset_t tuc_sigmask;   /* mask last for extensibility */
};

typedef struct {
    uint8_t callee_used_stack[__SIGNAL_FRAMESIZE];
    uint8_t retcode[S390_SYSCALL_SIZE];
    struct target_siginfo info;
    struct target_ucontext uc;
} rt_sigframe;

static inline abi_ulong
get_sigframe(struct target_sigaction *ka, CPUState *env, size_t frame_size)
{
    abi_ulong sp;

    /* Default to using normal stack */
    sp = env->regs[15];

    /* This is the X/Open sanctioned signal stack switching.  */
    if (ka->sa_flags & TARGET_SA_ONSTACK) {
        if (!sas_ss_flags(sp)) {
            sp = target_sigaltstack_used.ss_sp +
                 target_sigaltstack_used.ss_size;
        }
    }

    /* This is the legacy signal stack switching. */
    else if (/* FIXME !user_mode(regs) */ 0 &&
             !(ka->sa_flags & TARGET_SA_RESTORER) &&
             ka->sa_restorer) {
        sp = (abi_ulong) ka->sa_restorer;
    }

    return (sp - frame_size) & -8ul;
}

static void save_sigregs(CPUState *env, target_sigregs *sregs)
{
    int i;
    //save_access_regs(current->thread.acrs); FIXME

    /* Copy a 'clean' PSW mask to the user to avoid leaking
       information about whether PER is currently on.  */
    __put_user(env->psw.mask, &sregs->regs.psw.mask);
    __put_user(env->psw.addr, &sregs->regs.psw.addr);
    for (i = 0; i < 16; i++) {
        __put_user(env->regs[i], &sregs->regs.gprs[i]);
    }
    for (i = 0; i < 16; i++) {
        __put_user(env->aregs[i], &sregs->regs.acrs[i]);
    }
    /*
     * We have to store the fp registers to current->thread.fp_regs
     * to merge them with the emulated registers.
     */
    //save_fp_regs(&current->thread.fp_regs); FIXME
    for (i = 0; i < 16; i++) {
        __put_user(env->fregs[i].ll, &sregs->fpregs.fprs[i]);
    }
}

void setup_frame(int sig, struct target_sigaction *ka,
                 target_sigset_t *set, CPUState *env)
{
    sigframe *frame;
    abi_ulong frame_addr;

    frame_addr = get_sigframe(ka, env, sizeof(*frame));
    qemu_log("%s: frame_addr 0x%llx\n", __FUNCTION__,
             (unsigned long long)frame_addr);
    if (!lock_user_struct(VERIFY_WRITE, frame, frame_addr, 0)) {
            goto give_sigsegv;
    }

    qemu_log("%s: 1\n", __FUNCTION__);
    if (__put_user(set->sig[0], &frame->sc.oldmask[0])) {
              goto give_sigsegv;
    }

    save_sigregs(env, &frame->sregs);

    __put_user((abi_ulong)(unsigned long)&frame->sregs,
               (abi_ulong *)&frame->sc.sregs);

    /* Set up to return from userspace.  If provided, use a stub
       already in userspace.  */
    if (ka->sa_flags & TARGET_SA_RESTORER) {
            env->regs[14] = (unsigned long)
                    ka->sa_restorer | PSW_ADDR_AMODE;
    } else {
            env->regs[14] = (unsigned long)
                    frame->retcode | PSW_ADDR_AMODE;
            if (__put_user(S390_SYSCALL_OPCODE | TARGET_NR_sigreturn,
                           (uint16_t *)(frame->retcode)))
                    goto give_sigsegv;
    }

    /* Set up backchain. */
    if (__put_user(env->regs[15], (abi_ulong *) frame)) {
            goto give_sigsegv;
    }

    /* Set up registers for signal handler */
    env->regs[15] = frame_addr;
    env->psw.addr = (target_ulong) ka->_sa_handler | PSW_ADDR_AMODE;

    env->regs[2] = sig; //map_signal(sig);
    env->regs[3] = frame_addr += offsetof(typeof(*frame), sc);

    /* We forgot to include these in the sigcontext.
       To avoid breaking binary compatibility, they are passed as args. */
    env->regs[4] = 0; // FIXME: no clue... current->thread.trap_no;
    env->regs[5] = 0; // FIXME: no clue... current->thread.prot_addr;

    /* Place signal number on stack to allow backtrace from handler.  */
    if (__put_user(env->regs[2], (int *) &frame->signo)) {
            goto give_sigsegv;
    }
    unlock_user_struct(frame, frame_addr, 1);
    return;

give_sigsegv:
    qemu_log("%s: give_sigsegv\n", __FUNCTION__);
    unlock_user_struct(frame, frame_addr, 1);
    force_sig(TARGET_SIGSEGV);
}

void setup_rt_frame(int sig, struct target_sigaction *ka,
                    target_siginfo_t *info,
                    target_sigset_t *set, CPUState *env)
{
    int i;
    rt_sigframe *frame;
    abi_ulong frame_addr;

    frame_addr = get_sigframe(ka, env, sizeof *frame);
    qemu_log("%s: frame_addr 0x%llx\n", __FUNCTION__,
             (unsigned long long)frame_addr);
    if (!lock_user_struct(VERIFY_WRITE, frame, frame_addr, 0)) {
        goto give_sigsegv;
    }

    qemu_log("%s: 1\n", __FUNCTION__);
    if (copy_siginfo_to_user(&frame->info, info)) {
        goto give_sigsegv;
    }

    /* Create the ucontext.  */
    __put_user(0, &frame->uc.tuc_flags);
    __put_user((abi_ulong)0, (abi_ulong *)&frame->uc.tuc_link);
    __put_user(target_sigaltstack_used.ss_sp, &frame->uc.tuc_stack.ss_sp);
    __put_user(sas_ss_flags(get_sp_from_cpustate(env)),
                      &frame->uc.tuc_stack.ss_flags);
    __put_user(target_sigaltstack_used.ss_size, &frame->uc.tuc_stack.ss_size);
    save_sigregs(env, &frame->uc.tuc_mcontext);
    for (i = 0; i < TARGET_NSIG_WORDS; i++) {
        __put_user((abi_ulong)set->sig[i],
        (abi_ulong *)&frame->uc.tuc_sigmask.sig[i]);
    }

    /* Set up to return from userspace.  If provided, use a stub
       already in userspace.  */
    if (ka->sa_flags & TARGET_SA_RESTORER) {
        env->regs[14] = (unsigned long) ka->sa_restorer | PSW_ADDR_AMODE;
    } else {
        env->regs[14] = (unsigned long) frame->retcode | PSW_ADDR_AMODE;
        if (__put_user(S390_SYSCALL_OPCODE | TARGET_NR_rt_sigreturn,
                       (uint16_t *)(frame->retcode))) {
            goto give_sigsegv;
        }
    }

    /* Set up backchain. */
    if (__put_user(env->regs[15], (abi_ulong *) frame)) {
        goto give_sigsegv;
    }

    /* Set up registers for signal handler */
    env->regs[15] = frame_addr;
    env->psw.addr = (target_ulong) ka->_sa_handler | PSW_ADDR_AMODE;

    env->regs[2] = sig; //map_signal(sig);
    env->regs[3] = frame_addr + offsetof(typeof(*frame), info);
    env->regs[4] = frame_addr + offsetof(typeof(*frame), uc);
    return;

give_sigsegv:
    qemu_log("%s: give_sigsegv\n", __FUNCTION__);
    unlock_user_struct(frame, frame_addr, 1);
    force_sig(TARGET_SIGSEGV);
}

static int
restore_sigregs(CPUState *env, target_sigregs *sc)
{
    int err = 0;
    int i;

    for (i = 0; i < 16; i++) {
        err |= __get_user(env->regs[i], &sc->regs.gprs[i]);
    }

    err |= __get_user(env->psw.mask, &sc->regs.psw.mask);
    qemu_log("%s: sc->regs.psw.addr 0x%llx env->psw.addr 0x%llx\n",
             __FUNCTION__, (unsigned long long)sc->regs.psw.addr,
             (unsigned long long)env->psw.addr);
    err |= __get_user(env->psw.addr, &sc->regs.psw.addr);
    /* FIXME: 31-bit -> | PSW_ADDR_AMODE */

    for (i = 0; i < 16; i++) {
        err |= __get_user(env->aregs[i], &sc->regs.acrs[i]);
    }
    for (i = 0; i < 16; i++) {
        err |= __get_user(env->fregs[i].ll, &sc->fpregs.fprs[i]);
    }

    return err;
}

long do_sigreturn(CPUState *env)
{
    sigframe *frame;
    abi_ulong frame_addr = env->regs[15];
    qemu_log("%s: frame_addr 0x%llx\n", __FUNCTION__,
             (unsigned long long)frame_addr);
    target_sigset_t target_set;
    sigset_t set;

    if (!lock_user_struct(VERIFY_READ, frame, frame_addr, 1)) {
        goto badframe;
    }
    if (__get_user(target_set.sig[0], &frame->sc.oldmask[0])) {
        goto badframe;
    }

    target_to_host_sigset_internal(&set, &target_set);
    sigprocmask(SIG_SETMASK, &set, NULL); /* ~_BLOCKABLE? */

    if (restore_sigregs(env, &frame->sregs)) {
        goto badframe;
    }

    unlock_user_struct(frame, frame_addr, 0);
    return env->regs[2];

badframe:
    unlock_user_struct(frame, frame_addr, 0);
    force_sig(TARGET_SIGSEGV);
    return 0;
}

long do_rt_sigreturn(CPUState *env)
{
    rt_sigframe *frame;
    abi_ulong frame_addr = env->regs[15];
    qemu_log("%s: frame_addr 0x%llx\n", __FUNCTION__,
             (unsigned long long)frame_addr);
    sigset_t set;

    if (!lock_user_struct(VERIFY_READ, frame, frame_addr, 1)) {
        goto badframe;
    }
    target_to_host_sigset(&set, &frame->uc.tuc_sigmask);

    sigprocmask(SIG_SETMASK, &set, NULL); /* ~_BLOCKABLE? */

    if (restore_sigregs(env, &frame->uc.tuc_mcontext)) {
        goto badframe;
    }

    if (do_sigaltstack(frame_addr + offsetof(rt_sigframe, uc.tuc_stack), 0,
                       get_sp_from_cpustate(env)) == -EFAULT) {
        goto badframe;
    }
    unlock_user_struct(frame, frame_addr, 0);
    return env->regs[2];

badframe:
    unlock_user_struct(frame, frame_addr, 0);
    force_sig(TARGET_SIGSEGV);
    return 0;
}

