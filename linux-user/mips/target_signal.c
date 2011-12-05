/*
 *  Emulation of Linux signals : MIPS specific code
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
    uint32_t   sc_regmask;     /* Unused */
    uint32_t   sc_status;
    uint64_t   sc_pc;
    uint64_t   sc_regs[32];
    uint64_t   sc_fpregs[32];
    uint32_t   sc_ownedfp;     /* Unused */
    uint32_t   sc_fpc_csr;
    uint32_t   sc_fpc_eir;     /* Unused */
    uint32_t   sc_used_math;
    uint32_t   sc_dsp;         /* dsp status, was sc_ssflags */
    uint32_t   pad0;
    uint64_t   sc_mdhi;
    uint64_t   sc_mdlo;
    target_ulong   sc_hi1;         /* Was sc_cause */
    target_ulong   sc_lo1;         /* Was sc_badvaddr */
    target_ulong   sc_hi2;         /* Was sc_sigset[4] */
    target_ulong   sc_lo2;
    target_ulong   sc_hi3;
    target_ulong   sc_lo3;
};

struct sigframe {
    uint32_t sf_ass[4];			/* argument save space for o32 */
    uint32_t sf_code[2];			/* signal trampoline */
    struct target_sigcontext sf_sc;
    target_sigset_t sf_mask;
};

struct target_ucontext {
    target_ulong tuc_flags;
    target_ulong tuc_link;
    target_stack_t tuc_stack;
    target_ulong pad0;
    struct target_sigcontext tuc_mcontext;
    target_sigset_t tuc_sigmask;
};

struct target_rt_sigframe {
    uint32_t rs_ass[4];               /* argument save space for o32 */
    uint32_t rs_code[2];              /* signal trampoline */
    struct target_siginfo rs_info;
    struct target_ucontext rs_uc;
};

/* Install trampoline to jump back from signal handler */
static inline int install_sigtramp(unsigned int *tramp,   unsigned int syscall)
{
    int err;

    /*
    * Set up the return code ...
    *
    *         li      v0, __NR__foo_sigreturn
    *         syscall
    */

    err = __put_user(0x24020000 + syscall, tramp + 0);
    err |= __put_user(0x0000000c          , tramp + 1);
    /* flush_cache_sigtramp((unsigned long) tramp); */
    return err;
}

static inline int
setup_sigcontext(CPUState *regs, struct target_sigcontext *sc)
{
    int err = 0;

    err |= __put_user(regs->active_tc.PC, &sc->sc_pc);

#define save_gp_reg(i) do {   						\
        err |= __put_user(regs->active_tc.gpr[i], &sc->sc_regs[i]);	\
    } while(0)
    __put_user(0, &sc->sc_regs[0]); save_gp_reg(1); save_gp_reg(2);
    save_gp_reg(3); save_gp_reg(4); save_gp_reg(5); save_gp_reg(6);
    save_gp_reg(7); save_gp_reg(8); save_gp_reg(9); save_gp_reg(10);
    save_gp_reg(11); save_gp_reg(12); save_gp_reg(13); save_gp_reg(14);
    save_gp_reg(15); save_gp_reg(16); save_gp_reg(17); save_gp_reg(18);
    save_gp_reg(19); save_gp_reg(20); save_gp_reg(21); save_gp_reg(22);
    save_gp_reg(23); save_gp_reg(24); save_gp_reg(25); save_gp_reg(26);
    save_gp_reg(27); save_gp_reg(28); save_gp_reg(29); save_gp_reg(30);
    save_gp_reg(31);
#undef save_gp_reg

    err |= __put_user(regs->active_tc.HI[0], &sc->sc_mdhi);
    err |= __put_user(regs->active_tc.LO[0], &sc->sc_mdlo);

    /* Not used yet, but might be useful if we ever have DSP suppport */
#if 0
    if (cpu_has_dsp) {
	err |= __put_user(mfhi1(), &sc->sc_hi1);
	err |= __put_user(mflo1(), &sc->sc_lo1);
	err |= __put_user(mfhi2(), &sc->sc_hi2);
	err |= __put_user(mflo2(), &sc->sc_lo2);
	err |= __put_user(mfhi3(), &sc->sc_hi3);
	err |= __put_user(mflo3(), &sc->sc_lo3);
	err |= __put_user(rddsp(DSP_MASK), &sc->sc_dsp);
    }
    /* same with 64 bit */
#ifdef CONFIG_64BIT
    err |= __put_user(regs->hi, &sc->sc_hi[0]);
    err |= __put_user(regs->lo, &sc->sc_lo[0]);
    if (cpu_has_dsp) {
	err |= __put_user(mfhi1(), &sc->sc_hi[1]);
	err |= __put_user(mflo1(), &sc->sc_lo[1]);
	err |= __put_user(mfhi2(), &sc->sc_hi[2]);
	err |= __put_user(mflo2(), &sc->sc_lo[2]);
	err |= __put_user(mfhi3(), &sc->sc_hi[3]);
	err |= __put_user(mflo3(), &sc->sc_lo[3]);
	err |= __put_user(rddsp(DSP_MASK), &sc->sc_dsp);
    }
#endif
#endif

#if 0
    err |= __put_user(!!used_math(), &sc->sc_used_math);

    if (!used_math())
	goto out;

    /*
    * Save FPU state to signal context.  Signal handler will "inherit"
    * current FPU state.
    */
    preempt_disable();

    if (!is_fpu_owner()) {
	own_fpu();
	restore_fp(current);
    }
    err |= save_fp_context(sc);

    preempt_enable();
    out:
#endif
    return err;
}

static inline int
restore_sigcontext(CPUState *regs, struct target_sigcontext *sc)
{
    int err = 0;

    err |= __get_user(regs->CP0_EPC, &sc->sc_pc);

    err |= __get_user(regs->active_tc.HI[0], &sc->sc_mdhi);
    err |= __get_user(regs->active_tc.LO[0], &sc->sc_mdlo);

#define restore_gp_reg(i) do {   							\
        err |= __get_user(regs->active_tc.gpr[i], &sc->sc_regs[i]);		\
    } while(0)
    restore_gp_reg( 1); restore_gp_reg( 2); restore_gp_reg( 3);
    restore_gp_reg( 4); restore_gp_reg( 5); restore_gp_reg( 6);
    restore_gp_reg( 7); restore_gp_reg( 8); restore_gp_reg( 9);
    restore_gp_reg(10); restore_gp_reg(11); restore_gp_reg(12);
    restore_gp_reg(13); restore_gp_reg(14); restore_gp_reg(15);
    restore_gp_reg(16); restore_gp_reg(17); restore_gp_reg(18);
    restore_gp_reg(19); restore_gp_reg(20); restore_gp_reg(21);
    restore_gp_reg(22); restore_gp_reg(23); restore_gp_reg(24);
    restore_gp_reg(25); restore_gp_reg(26); restore_gp_reg(27);
    restore_gp_reg(28); restore_gp_reg(29); restore_gp_reg(30);
    restore_gp_reg(31);
#undef restore_gp_reg

#if 0
    if (cpu_has_dsp) {
	err |= __get_user(treg, &sc->sc_hi1); mthi1(treg);
	err |= __get_user(treg, &sc->sc_lo1); mtlo1(treg);
	err |= __get_user(treg, &sc->sc_hi2); mthi2(treg);
	err |= __get_user(treg, &sc->sc_lo2); mtlo2(treg);
	err |= __get_user(treg, &sc->sc_hi3); mthi3(treg);
	err |= __get_user(treg, &sc->sc_lo3); mtlo3(treg);
	err |= __get_user(treg, &sc->sc_dsp); wrdsp(treg, DSP_MASK);
    }
#ifdef CONFIG_64BIT
    err |= __get_user(regs->hi, &sc->sc_hi[0]);
    err |= __get_user(regs->lo, &sc->sc_lo[0]);
    if (cpu_has_dsp) {
	err |= __get_user(treg, &sc->sc_hi[1]); mthi1(treg);
	err |= __get_user(treg, &sc->sc_lo[1]); mthi1(treg);
	err |= __get_user(treg, &sc->sc_hi[2]); mthi2(treg);
	err |= __get_user(treg, &sc->sc_lo[2]); mthi2(treg);
	err |= __get_user(treg, &sc->sc_hi[3]); mthi3(treg);
	err |= __get_user(treg, &sc->sc_lo[3]); mthi3(treg);
	err |= __get_user(treg, &sc->sc_dsp); wrdsp(treg, DSP_MASK);
    }
#endif

    err |= __get_user(used_math, &sc->sc_used_math);
    conditional_used_math(used_math);

    preempt_disable();

    if (used_math()) {
	/* restore fpu context if we have used it before */
	own_fpu();
	err |= restore_fp_context(sc);
    } else {
	/* signal handler may have used FPU.  Give it up. */
	lose_fpu();
    }

    preempt_enable();
#endif
    return err;
}
/*
 * Determine which stack to use..
 */
static inline abi_ulong
get_sigframe(struct target_sigaction *ka, CPUState *regs, size_t frame_size)
{
    unsigned long sp;

    /* Default to using normal stack */
    sp = regs->active_tc.gpr[29];

    /*
     * FPU emulator may have it's own trampoline active just
     * above the user stack, 16-bytes before the next lowest
     * 16 byte boundary.  Try to avoid trashing it.
     */
    sp -= 32;

    /* This is the X/Open sanctioned signal stack switching.  */
    if ((ka->sa_flags & TARGET_SA_ONSTACK) && (sas_ss_flags (sp) == 0)) {
        sp = target_sigaltstack_used.ss_sp + target_sigaltstack_used.ss_size;
    }

    return (sp - frame_size) & ~7;
}

/* compare linux/arch/mips/kernel/signal.c:setup_frame() */
void setup_frame(int sig, struct target_sigaction * ka,
                 target_sigset_t *set, CPUState *regs)
{
    struct sigframe *frame;
    abi_ulong frame_addr;
    int i;

    frame_addr = get_sigframe(ka, regs, sizeof(*frame));
    if (!lock_user_struct(VERIFY_WRITE, frame, frame_addr, 0))
	goto give_sigsegv;

    install_sigtramp(frame->sf_code, TARGET_NR_sigreturn);

    if(setup_sigcontext(regs, &frame->sf_sc))
	goto give_sigsegv;

    for(i = 0; i < TARGET_NSIG_WORDS; i++) {
	if(__put_user(set->sig[i], &frame->sf_mask.sig[i]))
	    goto give_sigsegv;
    }

    /*
    * Arguments to signal handler:
    *
    *   a0 = signal number
    *   a1 = 0 (should be cause)
    *   a2 = pointer to struct sigcontext
    *
    * $25 and PC point to the signal handler, $29 points to the
    * struct sigframe.
    */
    regs->active_tc.gpr[ 4] = sig;
    regs->active_tc.gpr[ 5] = 0;
    regs->active_tc.gpr[ 6] = frame_addr + offsetof(struct sigframe, sf_sc);
    regs->active_tc.gpr[29] = frame_addr;
    regs->active_tc.gpr[31] = frame_addr + offsetof(struct sigframe, sf_code);
    /* The original kernel code sets CP0_EPC to the handler
    * since it returns to userland using eret
    * we cannot do this here, and we must set PC directly */
    regs->active_tc.PC = regs->active_tc.gpr[25] = ka->_sa_handler;
    unlock_user_struct(frame, frame_addr, 1);
    return;

give_sigsegv:
    unlock_user_struct(frame, frame_addr, 1);
    force_sig(TARGET_SIGSEGV/*, current*/);
    return;
}

long do_sigreturn(CPUState *regs)
{
    struct sigframe *frame;
    abi_ulong frame_addr;
    sigset_t blocked;
    target_sigset_t target_set;
    int i;

#if defined(DEBUG_SIGNAL)
    fprintf(stderr, "do_sigreturn\n");
#endif
    frame_addr = regs->active_tc.gpr[29];
    if (!lock_user_struct(VERIFY_READ, frame, frame_addr, 1))
   	goto badframe;

    for(i = 0; i < TARGET_NSIG_WORDS; i++) {
   	if(__get_user(target_set.sig[i], &frame->sf_mask.sig[i]))
	    goto badframe;
    }

    target_to_host_sigset_internal(&blocked, &target_set);
    sigprocmask(SIG_SETMASK, &blocked, NULL);

    if (restore_sigcontext(regs, &frame->sf_sc))
   	goto badframe;

#if 0
    /*
     * Don't let your children do this ...
     */
    __asm__ __volatile__(
   	"move\t$29, %0\n\t"
   	"j\tsyscall_exit"
   	:/* no outputs */
   	:"r" (&regs));
    /* Unreached */
#endif

    regs->active_tc.PC = regs->CP0_EPC;
    /* I am not sure this is right, but it seems to work
    * maybe a problem with nested signals ? */
    regs->CP0_EPC = 0;
    return -TARGET_QEMU_ESIGRETURN;

badframe:
    force_sig(TARGET_SIGSEGV/*, current*/);
    return 0;
}

void setup_rt_frame(int sig, struct target_sigaction *ka,
                    target_siginfo_t *info,
                    target_sigset_t *set, CPUState *env)
{
    struct target_rt_sigframe *frame;
    abi_ulong frame_addr;
    int i;

    frame_addr = get_sigframe(ka, env, sizeof(*frame));
    if (!lock_user_struct(VERIFY_WRITE, frame, frame_addr, 0))
	goto give_sigsegv;

    install_sigtramp(frame->rs_code, TARGET_NR_rt_sigreturn);

    copy_siginfo_to_user(&frame->rs_info, info);

    __put_user(0, &frame->rs_uc.tuc_flags);
    __put_user(0, &frame->rs_uc.tuc_link);
    __put_user(target_sigaltstack_used.ss_sp, &frame->rs_uc.tuc_stack.ss_sp);
    __put_user(target_sigaltstack_used.ss_size, &frame->rs_uc.tuc_stack.ss_size);
    __put_user(sas_ss_flags(get_sp_from_cpustate(env)),
               &frame->rs_uc.tuc_stack.ss_flags);

    setup_sigcontext(env, &frame->rs_uc.tuc_mcontext);

    for(i = 0; i < TARGET_NSIG_WORDS; i++) {
        __put_user(set->sig[i], &frame->rs_uc.tuc_sigmask.sig[i]);
    }

    /*
    * Arguments to signal handler:
    *
    *   a0 = signal number
    *   a1 = pointer to struct siginfo
    *   a2 = pointer to struct ucontext
    *
    * $25 and PC point to the signal handler, $29 points to the
    * struct sigframe.
    */
    env->active_tc.gpr[ 4] = sig;
    env->active_tc.gpr[ 5] = frame_addr
                             + offsetof(struct target_rt_sigframe, rs_info);
    env->active_tc.gpr[ 6] = frame_addr
                             + offsetof(struct target_rt_sigframe, rs_uc);
    env->active_tc.gpr[29] = frame_addr;
    env->active_tc.gpr[31] = frame_addr
                             + offsetof(struct target_rt_sigframe, rs_code);
    /* The original kernel code sets CP0_EPC to the handler
    * since it returns to userland using eret
    * we cannot do this here, and we must set PC directly */
    env->active_tc.PC = env->active_tc.gpr[25] = ka->_sa_handler;
    unlock_user_struct(frame, frame_addr, 1);
    return;

give_sigsegv:
    unlock_user_struct(frame, frame_addr, 1);
    force_sig(TARGET_SIGSEGV/*, current*/);
    return;
}

long do_rt_sigreturn(CPUState *env)
{
    struct target_rt_sigframe *frame;
    abi_ulong frame_addr;
    sigset_t blocked;

#if defined(DEBUG_SIGNAL)
    fprintf(stderr, "do_rt_sigreturn\n");
#endif
    frame_addr = env->active_tc.gpr[29];
    if (!lock_user_struct(VERIFY_READ, frame, frame_addr, 1))
   	goto badframe;

    target_to_host_sigset(&blocked, &frame->rs_uc.tuc_sigmask);
    sigprocmask(SIG_SETMASK, &blocked, NULL);

    if (restore_sigcontext(env, &frame->rs_uc.tuc_mcontext))
        goto badframe;

    if (do_sigaltstack(frame_addr +
		       offsetof(struct target_rt_sigframe, rs_uc.tuc_stack),
		       0, get_sp_from_cpustate(env)) == -EFAULT)
        goto badframe;

    env->active_tc.PC = env->CP0_EPC;
    /* I am not sure this is right, but it seems to work
    * maybe a problem with nested signals ? */
    env->CP0_EPC = 0;
    return -TARGET_QEMU_ESIGRETURN;

badframe:
    force_sig(TARGET_SIGSEGV/*, current*/);
    return 0;
}

