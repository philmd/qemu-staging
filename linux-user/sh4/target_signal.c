/*
 *  Emulation of Linux signals : sh4 specific code
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

/*
 * code and data structures from linux kernel:
 * include/asm-sh/sigcontext.h
 * arch/sh/kernel/signal.c
 */

struct target_sigcontext {
    target_ulong  oldmask;

    /* CPU registers */
    target_ulong  sc_gregs[16];
    target_ulong  sc_pc;
    target_ulong  sc_pr;
    target_ulong  sc_sr;
    target_ulong  sc_gbr;
    target_ulong  sc_mach;
    target_ulong  sc_macl;

    /* FPU registers */
    target_ulong  sc_fpregs[16];
    target_ulong  sc_xfpregs[16];
    unsigned int sc_fpscr;
    unsigned int sc_fpul;
    unsigned int sc_ownedfp;
};

struct target_sigframe
{
    struct target_sigcontext sc;
    target_ulong extramask[TARGET_NSIG_WORDS-1];
    uint16_t retcode[3];
};


struct target_ucontext {
    target_ulong tuc_flags;
    struct target_ucontext *tuc_link;
    target_stack_t tuc_stack;
    struct target_sigcontext tuc_mcontext;
    target_sigset_t tuc_sigmask;	/* mask last for extensibility */
};

struct target_rt_sigframe
{
    struct target_siginfo info;
    struct target_ucontext uc;
    uint16_t retcode[3];
};


#define MOVW(n)  (0x9300|((n)-2)) /* Move mem word at PC+n to R3 */
#define TRAP_NOARG 0xc310         /* Syscall w/no args (NR in R3) SH3/4 */

static abi_ulong get_sigframe(struct target_sigaction *ka,
                         unsigned long sp, size_t frame_size)
{
    if ((ka->sa_flags & TARGET_SA_ONSTACK) && (sas_ss_flags(sp) == 0)) {
        sp = target_sigaltstack_used.ss_sp + target_sigaltstack_used.ss_size;
    }

    return (sp - frame_size) & -8ul;
}

static int setup_sigcontext(struct target_sigcontext *sc,
			    CPUState *regs, unsigned long mask)
{
    int err = 0;
    int i;

#define COPY(x)         err |= __put_user(regs->x, &sc->sc_##x)
    COPY(gregs[0]); COPY(gregs[1]);
    COPY(gregs[2]); COPY(gregs[3]);
    COPY(gregs[4]); COPY(gregs[5]);
    COPY(gregs[6]); COPY(gregs[7]);
    COPY(gregs[8]); COPY(gregs[9]);
    COPY(gregs[10]); COPY(gregs[11]);
    COPY(gregs[12]); COPY(gregs[13]);
    COPY(gregs[14]); COPY(gregs[15]);
    COPY(gbr); COPY(mach);
    COPY(macl); COPY(pr);
    COPY(sr); COPY(pc);
#undef COPY

    for (i=0; i<16; i++) {
        err |= __put_user(regs->fregs[i], &sc->sc_fpregs[i]);
    }
    err |= __put_user(regs->fpscr, &sc->sc_fpscr);
    err |= __put_user(regs->fpul, &sc->sc_fpul);

    /* non-iBCS2 extensions.. */
    err |= __put_user(mask, &sc->oldmask);

    return err;
}

static int restore_sigcontext(CPUState *regs, struct target_sigcontext *sc,
                              target_ulong *r0_p)
{
    unsigned int err = 0;
    int i;

#define COPY(x)         err |= __get_user(regs->x, &sc->sc_##x)
    COPY(gregs[1]);
    COPY(gregs[2]); COPY(gregs[3]);
    COPY(gregs[4]); COPY(gregs[5]);
    COPY(gregs[6]); COPY(gregs[7]);
    COPY(gregs[8]); COPY(gregs[9]);
    COPY(gregs[10]); COPY(gregs[11]);
    COPY(gregs[12]); COPY(gregs[13]);
    COPY(gregs[14]); COPY(gregs[15]);
    COPY(gbr); COPY(mach);
    COPY(macl); COPY(pr);
    COPY(sr); COPY(pc);
#undef COPY

    for (i=0; i<16; i++) {
        err |= __get_user(regs->fregs[i], &sc->sc_fpregs[i]);
    }
    err |= __get_user(regs->fpscr, &sc->sc_fpscr);
    err |= __get_user(regs->fpul, &sc->sc_fpul);

    regs->tra = -1;         /* disable syscall checks */
    err |= __get_user(*r0_p, &sc->sc_gregs[0]);
    return err;
}

void setup_frame(int sig, struct target_sigaction *ka,
                 target_sigset_t *set, CPUState *regs)
{
    struct target_sigframe *frame;
    abi_ulong frame_addr;
    int i;
    int err = 0;
    int signal;

    frame_addr = get_sigframe(ka, regs->gregs[15], sizeof(*frame));
    if (!lock_user_struct(VERIFY_WRITE, frame, frame_addr, 0))
	goto give_sigsegv;

    signal = current_exec_domain_sig(sig);

    err |= setup_sigcontext(&frame->sc, regs, set->sig[0]);

    for (i = 0; i < TARGET_NSIG_WORDS - 1; i++) {
        err |= __put_user(set->sig[i + 1], &frame->extramask[i]);
    }

    /* Set up to return from userspace.  If provided, use a stub
       already in userspace.  */
    if (ka->sa_flags & TARGET_SA_RESTORER) {
        regs->pr = (unsigned long) ka->sa_restorer;
    } else {
        /* Generate return code (system call to sigreturn) */
        err |= __put_user(MOVW(2), &frame->retcode[0]);
        err |= __put_user(TRAP_NOARG, &frame->retcode[1]);
        err |= __put_user((TARGET_NR_sigreturn), &frame->retcode[2]);
        regs->pr = (unsigned long) frame->retcode;
    }

    if (err)
        goto give_sigsegv;

    /* Set up registers for signal handler */
    regs->gregs[15] = frame_addr;
    regs->gregs[4] = signal; /* Arg for signal handler */
    regs->gregs[5] = 0;
    regs->gregs[6] = frame_addr += offsetof(typeof(*frame), sc);
    regs->pc = (unsigned long) ka->_sa_handler;

    unlock_user_struct(frame, frame_addr, 1);
    return;

give_sigsegv:
    unlock_user_struct(frame, frame_addr, 1);
    force_sig(TARGET_SIGSEGV);
}

void setup_rt_frame(int sig, struct target_sigaction *ka,
                    target_siginfo_t *info,
                    target_sigset_t *set, CPUState *regs)
{
    struct target_rt_sigframe *frame;
    abi_ulong frame_addr;
    int i;
    int err = 0;
    int signal;

    frame_addr = get_sigframe(ka, regs->gregs[15], sizeof(*frame));
    if (!lock_user_struct(VERIFY_WRITE, frame, frame_addr, 0))
	goto give_sigsegv;

    signal = current_exec_domain_sig(sig);

    err |= copy_siginfo_to_user(&frame->info, info);

    /* Create the ucontext.  */
    err |= __put_user(0, &frame->uc.tuc_flags);
    err |= __put_user(0, (unsigned long *)&frame->uc.tuc_link);
    err |= __put_user((unsigned long)target_sigaltstack_used.ss_sp,
		      &frame->uc.tuc_stack.ss_sp);
    err |= __put_user(sas_ss_flags(regs->gregs[15]),
		      &frame->uc.tuc_stack.ss_flags);
    err |= __put_user(target_sigaltstack_used.ss_size,
		      &frame->uc.tuc_stack.ss_size);
    err |= setup_sigcontext(&frame->uc.tuc_mcontext,
			    regs, set->sig[0]);
    for(i = 0; i < TARGET_NSIG_WORDS; i++) {
        err |= __put_user(set->sig[i], &frame->uc.tuc_sigmask.sig[i]);
    }

    /* Set up to return from userspace.  If provided, use a stub
       already in userspace.  */
    if (ka->sa_flags & TARGET_SA_RESTORER) {
        regs->pr = (unsigned long) ka->sa_restorer;
    } else {
        /* Generate return code (system call to sigreturn) */
        err |= __put_user(MOVW(2), &frame->retcode[0]);
        err |= __put_user(TRAP_NOARG, &frame->retcode[1]);
        err |= __put_user((TARGET_NR_rt_sigreturn), &frame->retcode[2]);
        regs->pr = (unsigned long) frame->retcode;
    }

    if (err)
        goto give_sigsegv;

    /* Set up registers for signal handler */
    regs->gregs[15] = frame_addr;
    regs->gregs[4] = signal; /* Arg for signal handler */
    regs->gregs[5] = frame_addr + offsetof(typeof(*frame), info);
    regs->gregs[6] = frame_addr + offsetof(typeof(*frame), uc);
    regs->pc = (unsigned long) ka->_sa_handler;

    unlock_user_struct(frame, frame_addr, 1);
    return;

give_sigsegv:
    unlock_user_struct(frame, frame_addr, 1);
    force_sig(TARGET_SIGSEGV);
}

long do_sigreturn(CPUState *regs)
{
    struct target_sigframe *frame;
    abi_ulong frame_addr;
    sigset_t blocked;
    target_sigset_t target_set;
    target_ulong r0;
    int i;
    int err = 0;

#if defined(DEBUG_SIGNAL)
    fprintf(stderr, "do_sigreturn\n");
#endif
    frame_addr = regs->gregs[15];
    if (!lock_user_struct(VERIFY_READ, frame, frame_addr, 1))
   	goto badframe;

    err |= __get_user(target_set.sig[0], &frame->sc.oldmask);
    for(i = 1; i < TARGET_NSIG_WORDS; i++) {
        err |= (__get_user(target_set.sig[i], &frame->extramask[i - 1]));
    }

    if (err)
        goto badframe;

    target_to_host_sigset_internal(&blocked, &target_set);
    sigprocmask(SIG_SETMASK, &blocked, NULL);

    if (restore_sigcontext(regs, &frame->sc, &r0))
        goto badframe;

    unlock_user_struct(frame, frame_addr, 0);
    return r0;

badframe:
    unlock_user_struct(frame, frame_addr, 0);
    force_sig(TARGET_SIGSEGV);
    return 0;
}

long do_rt_sigreturn(CPUState *regs)
{
    struct target_rt_sigframe *frame;
    abi_ulong frame_addr;
    sigset_t blocked;
    target_ulong r0;

#if defined(DEBUG_SIGNAL)
    fprintf(stderr, "do_rt_sigreturn\n");
#endif
    frame_addr = regs->gregs[15];
    if (!lock_user_struct(VERIFY_READ, frame, frame_addr, 1))
   	goto badframe;

    target_to_host_sigset(&blocked, &frame->uc.tuc_sigmask);
    sigprocmask(SIG_SETMASK, &blocked, NULL);

    if (restore_sigcontext(regs, &frame->uc.tuc_mcontext, &r0))
        goto badframe;

    if (do_sigaltstack(frame_addr +
		       offsetof(struct target_rt_sigframe, uc.tuc_stack),
		       0, get_sp_from_cpustate(regs)) == -EFAULT)
        goto badframe;

    unlock_user_struct(frame, frame_addr, 0);
    return r0;

badframe:
    unlock_user_struct(frame, frame_addr, 0);
    force_sig(TARGET_SIGSEGV);
    return 0;
}
