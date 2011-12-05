/*
 *  Emulation of Linux signals : m68k specific code
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

struct target_sigcontext {
    abi_ulong  sc_mask;
    abi_ulong  sc_usp;
    abi_ulong  sc_d0;
    abi_ulong  sc_d1;
    abi_ulong  sc_a0;
    abi_ulong  sc_a1;
    unsigned short sc_sr;
    abi_ulong  sc_pc;
};

struct target_sigframe
{
    abi_ulong pretcode;
    int sig;
    int code;
    abi_ulong psc;
    char retcode[8];
    abi_ulong extramask[TARGET_NSIG_WORDS-1];
    struct target_sigcontext sc;
};
 
typedef int target_greg_t;
#define TARGET_NGREG 18
typedef target_greg_t target_gregset_t[TARGET_NGREG];

typedef struct target_fpregset {
    int f_fpcntl[3];
    int f_fpregs[8*3];
} target_fpregset_t;

struct target_mcontext {
    int version;
    target_gregset_t gregs;
    target_fpregset_t fpregs;
};

#define TARGET_MCONTEXT_VERSION 2

struct target_ucontext {
    abi_ulong tuc_flags;
    abi_ulong tuc_link;
    target_stack_t tuc_stack;
    struct target_mcontext tuc_mcontext;
    abi_long tuc_filler[80];
    target_sigset_t tuc_sigmask;
};

struct target_rt_sigframe
{
    abi_ulong pretcode;
    int sig;
    abi_ulong pinfo;
    abi_ulong puc;
    char retcode[8];
    struct target_siginfo info;
    struct target_ucontext uc;
};

static int
setup_sigcontext(struct target_sigcontext *sc, CPUState *env, abi_ulong mask)
{
    int err = 0;

    err |= __put_user(mask, &sc->sc_mask);
    err |= __put_user(env->aregs[7], &sc->sc_usp);
    err |= __put_user(env->dregs[0], &sc->sc_d0);
    err |= __put_user(env->dregs[1], &sc->sc_d1);
    err |= __put_user(env->aregs[0], &sc->sc_a0);
    err |= __put_user(env->aregs[1], &sc->sc_a1);
    err |= __put_user(env->sr, &sc->sc_sr);
    err |= __put_user(env->pc, &sc->sc_pc);

    return err;
}

static int
restore_sigcontext(CPUState *env, struct target_sigcontext *sc, int *pd0)
{
    int err = 0;
    int temp;

    err |= __get_user(env->aregs[7], &sc->sc_usp);
    err |= __get_user(env->dregs[1], &sc->sc_d1);
    err |= __get_user(env->aregs[0], &sc->sc_a0);
    err |= __get_user(env->aregs[1], &sc->sc_a1);
    err |= __get_user(env->pc, &sc->sc_pc);
    err |= __get_user(temp, &sc->sc_sr);
    env->sr = (env->sr & 0xff00) | (temp & 0xff);

    *pd0 = tswapl(sc->sc_d0);

    return err;
}

/*
 * Determine which stack to use..
 */
static inline abi_ulong
get_sigframe(struct target_sigaction *ka, CPUState *regs, size_t frame_size)
{
    unsigned long sp;

    sp = regs->aregs[7];

    /* This is the X/Open sanctioned signal stack switching.  */
    if ((ka->sa_flags & TARGET_SA_ONSTACK) && (sas_ss_flags (sp) == 0)) {
        sp = target_sigaltstack_used.ss_sp + target_sigaltstack_used.ss_size;
    }

    return ((sp - frame_size) & -8UL);
}

void setup_frame(int sig, struct target_sigaction *ka,
                 target_sigset_t *set, CPUState *env)
{
    struct target_sigframe *frame;
    abi_ulong frame_addr;
    abi_ulong retcode_addr;
    abi_ulong sc_addr;
    int err = 0;
    int i;

    frame_addr = get_sigframe(ka, env, sizeof *frame);
    if (!lock_user_struct(VERIFY_WRITE, frame, frame_addr, 0))
	goto give_sigsegv;

    err |= __put_user(sig, &frame->sig);

    sc_addr = frame_addr + offsetof(struct target_sigframe, sc);
    err |= __put_user(sc_addr, &frame->psc);

    err |= setup_sigcontext(&frame->sc, env, set->sig[0]);
    if (err)
	goto give_sigsegv;

    for(i = 1; i < TARGET_NSIG_WORDS; i++) {
        if (__put_user(set->sig[i], &frame->extramask[i - 1]))
            goto give_sigsegv;
    }

    /* Set up to return from userspace.  */

    retcode_addr = frame_addr + offsetof(struct target_sigframe, retcode);
    err |= __put_user(retcode_addr, &frame->pretcode);

    /* moveq #,d0; trap #0 */

    err |= __put_user(0x70004e40 + (TARGET_NR_sigreturn << 16),
                      (long *)(frame->retcode));

    if (err)
        goto give_sigsegv;

    /* Set up to return from userspace */

    env->aregs[7] = frame_addr;
    env->pc = ka->_sa_handler;

    unlock_user_struct(frame, frame_addr, 1);
    return;

give_sigsegv:
    unlock_user_struct(frame, frame_addr, 1);
    force_sig(TARGET_SIGSEGV);
}

static inline int target_rt_setup_ucontext(struct target_ucontext *uc,
                                           CPUState *env)
{
    target_greg_t *gregs = uc->tuc_mcontext.gregs;
    int err;

    err = __put_user(TARGET_MCONTEXT_VERSION, &uc->tuc_mcontext.version);
    err |= __put_user(env->dregs[0], &gregs[0]);
    err |= __put_user(env->dregs[1], &gregs[1]);
    err |= __put_user(env->dregs[2], &gregs[2]);
    err |= __put_user(env->dregs[3], &gregs[3]);
    err |= __put_user(env->dregs[4], &gregs[4]);
    err |= __put_user(env->dregs[5], &gregs[5]);
    err |= __put_user(env->dregs[6], &gregs[6]);
    err |= __put_user(env->dregs[7], &gregs[7]);
    err |= __put_user(env->aregs[0], &gregs[8]);
    err |= __put_user(env->aregs[1], &gregs[9]);
    err |= __put_user(env->aregs[2], &gregs[10]);
    err |= __put_user(env->aregs[3], &gregs[11]);
    err |= __put_user(env->aregs[4], &gregs[12]);
    err |= __put_user(env->aregs[5], &gregs[13]);
    err |= __put_user(env->aregs[6], &gregs[14]);
    err |= __put_user(env->aregs[7], &gregs[15]);
    err |= __put_user(env->pc, &gregs[16]);
    err |= __put_user(env->sr, &gregs[17]);

    return err;
}
 
static inline int target_rt_restore_ucontext(CPUState *env,
                                             struct target_ucontext *uc,
                                             int *pd0)
{
    int temp;
    int err;
    target_greg_t *gregs = uc->tuc_mcontext.gregs;
    
    err = __get_user(temp, &uc->tuc_mcontext.version);
    if (temp != TARGET_MCONTEXT_VERSION)
        goto badframe;

    /* restore passed registers */
    err |= __get_user(env->dregs[0], &gregs[0]);
    err |= __get_user(env->dregs[1], &gregs[1]);
    err |= __get_user(env->dregs[2], &gregs[2]);
    err |= __get_user(env->dregs[3], &gregs[3]);
    err |= __get_user(env->dregs[4], &gregs[4]);
    err |= __get_user(env->dregs[5], &gregs[5]);
    err |= __get_user(env->dregs[6], &gregs[6]);
    err |= __get_user(env->dregs[7], &gregs[7]);
    err |= __get_user(env->aregs[0], &gregs[8]);
    err |= __get_user(env->aregs[1], &gregs[9]);
    err |= __get_user(env->aregs[2], &gregs[10]);
    err |= __get_user(env->aregs[3], &gregs[11]);
    err |= __get_user(env->aregs[4], &gregs[12]);
    err |= __get_user(env->aregs[5], &gregs[13]);
    err |= __get_user(env->aregs[6], &gregs[14]);
    err |= __get_user(env->aregs[7], &gregs[15]);
    err |= __get_user(env->pc, &gregs[16]);
    err |= __get_user(temp, &gregs[17]);
    env->sr = (env->sr & 0xff00) | (temp & 0xff);

    *pd0 = env->dregs[0];
    return err;

badframe:
    return 1;
}

void setup_rt_frame(int sig, struct target_sigaction *ka,
                    target_siginfo_t *info,
                    target_sigset_t *set, CPUState *env)
{
    struct target_rt_sigframe *frame;
    abi_ulong frame_addr;
    abi_ulong retcode_addr;
    abi_ulong info_addr;
    abi_ulong uc_addr;
    int err = 0;
    int i;

    frame_addr = get_sigframe(ka, env, sizeof *frame);
    if (!lock_user_struct(VERIFY_WRITE, frame, frame_addr, 0))
	goto give_sigsegv;

    err |= __put_user(sig, &frame->sig);

    info_addr = frame_addr + offsetof(struct target_rt_sigframe, info);
    err |= __put_user(info_addr, &frame->pinfo);

    uc_addr = frame_addr + offsetof(struct target_rt_sigframe, uc);
    err |= __put_user(uc_addr, &frame->puc);

    err |= copy_siginfo_to_user(&frame->info, info);

    /* Create the ucontext */

    err |= __put_user(0, &frame->uc.tuc_flags);
    err |= __put_user(0, &frame->uc.tuc_link);
    err |= __put_user(target_sigaltstack_used.ss_sp,
                      &frame->uc.tuc_stack.ss_sp);
    err |= __put_user(sas_ss_flags(env->aregs[7]),
                      &frame->uc.tuc_stack.ss_flags);
    err |= __put_user(target_sigaltstack_used.ss_size,
                      &frame->uc.tuc_stack.ss_size);
    err |= target_rt_setup_ucontext(&frame->uc, env);

    if (err)
            goto give_sigsegv;

    for(i = 0; i < TARGET_NSIG_WORDS; i++) {
        if (__put_user(set->sig[i], &frame->uc.tuc_sigmask.sig[i]))
            goto give_sigsegv;
    }

    /* Set up to return from userspace.  */

    retcode_addr = frame_addr + offsetof(struct target_sigframe, retcode);
    err |= __put_user(retcode_addr, &frame->pretcode);

    /* moveq #,d0; notb d0; trap #0 */

    err |= __put_user(0x70004600 + ((TARGET_NR_rt_sigreturn ^ 0xff) << 16),
                      (long *)(frame->retcode + 0));
    err |= __put_user(0x4e40, (short *)(frame->retcode + 4));

    if (err)
        goto give_sigsegv;

    /* Set up to return from userspace */

    env->aregs[7] = frame_addr;
    env->pc = ka->_sa_handler;

    unlock_user_struct(frame, frame_addr, 1);
    return;

give_sigsegv:
    unlock_user_struct(frame, frame_addr, 1);
    force_sig(TARGET_SIGSEGV);
}

long do_sigreturn(CPUState *env)
{
    struct target_sigframe *frame;
    abi_ulong frame_addr = env->aregs[7] - 4;
    target_sigset_t target_set;
    sigset_t set;
    int d0, i;

    if (!lock_user_struct(VERIFY_READ, frame, frame_addr, 1))
        goto badframe;

    /* set blocked signals */

    if (__get_user(target_set.sig[0], &frame->sc.sc_mask))
        goto badframe;

    for(i = 1; i < TARGET_NSIG_WORDS; i++) {
        if (__get_user(target_set.sig[i], &frame->extramask[i - 1]))
            goto badframe;
    }

    target_to_host_sigset_internal(&set, &target_set);
    sigprocmask(SIG_SETMASK, &set, NULL);

    /* restore registers */

    if (restore_sigcontext(env, &frame->sc, &d0))
        goto badframe;

    unlock_user_struct(frame, frame_addr, 0);
    return d0;

badframe:
    unlock_user_struct(frame, frame_addr, 0);
    force_sig(TARGET_SIGSEGV);
    return 0;
}

long do_rt_sigreturn(CPUState *env)
{
    struct target_rt_sigframe *frame;
    abi_ulong frame_addr = env->aregs[7] - 4;
    target_sigset_t target_set;
    sigset_t set;
    int d0;

    if (!lock_user_struct(VERIFY_READ, frame, frame_addr, 1))
        goto badframe;

    target_to_host_sigset_internal(&set, &target_set);
    sigprocmask(SIG_SETMASK, &set, NULL);

    /* restore registers */

    if (target_rt_restore_ucontext(env, &frame->uc, &d0))
        goto badframe;

    if (do_sigaltstack(frame_addr +
                       offsetof(struct target_rt_sigframe, uc.tuc_stack),
                       0, get_sp_from_cpustate(env)) == -EFAULT)
        goto badframe;

    unlock_user_struct(frame, frame_addr, 0);
    return d0;

badframe:
    unlock_user_struct(frame, frame_addr, 0);
    force_sig(TARGET_SIGSEGV);
    return 0;
}
