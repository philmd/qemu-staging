/*
 *  Emulation of Linux signals : SPARC specific code
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

#define __SUNOS_MAXWIN   31

/* This is what SunOS does, so shall I. */
struct target_sigcontext {
        abi_ulong sigc_onstack;      /* state to restore */

        abi_ulong sigc_mask;         /* sigmask to restore */
        abi_ulong sigc_sp;           /* stack pointer */
        abi_ulong sigc_pc;           /* program counter */
        abi_ulong sigc_npc;          /* next program counter */
        abi_ulong sigc_psr;          /* for condition codes etc */
        abi_ulong sigc_g1;           /* User uses these two registers */
        abi_ulong sigc_o0;           /* within the trampoline code. */

        /* Now comes information regarding the users window set
         * at the time of the signal.
         */
        abi_ulong sigc_oswins;       /* outstanding windows */

        /* stack ptrs for each regwin buf */
        char *sigc_spbuf[__SUNOS_MAXWIN];

        /* Windows to restore after signal */
        struct {
                abi_ulong locals[8];
                abi_ulong ins[8];
        } sigc_wbuf[__SUNOS_MAXWIN];
};
/* A Sparc stack frame */
struct sparc_stackf {
        abi_ulong locals[8];
        abi_ulong ins[8];
        /* It's simpler to treat fp and callers_pc as elements of ins[]
         * since we never need to access them ourselves.
         */
        char *structptr;
        abi_ulong xargs[6];
        abi_ulong xxargs[1];
};

typedef struct {
        struct {
                abi_ulong psr;
                abi_ulong pc;
                abi_ulong npc;
                abi_ulong y;
                abi_ulong u_regs[16]; /* globals and ins */
        }               si_regs;
        int             si_mask;
} __siginfo_t;

typedef struct {
        unsigned   long si_float_regs [32];
        unsigned   long si_fsr;
        unsigned   long si_fpqdepth;
        struct {
                unsigned long *insn_addr;
                unsigned long insn;
        } si_fpqueue [16];
} qemu_siginfo_fpu_t;


struct target_signal_frame {
	struct sparc_stackf	ss;
	__siginfo_t		info;
	abi_ulong               fpu_save;
	abi_ulong		insns[2] __attribute__ ((aligned (8)));
	abi_ulong		extramask[TARGET_NSIG_WORDS - 1];
	abi_ulong		extra_size; /* Should be 0 */
	qemu_siginfo_fpu_t	fpu_state;
};
struct target_rt_signal_frame {
	struct sparc_stackf	ss;
	siginfo_t		info;
	abi_ulong		regs[20];
	sigset_t		mask;
	abi_ulong               fpu_save;
	unsigned int		insns[2];
	stack_t			stack;
	unsigned int		extra_size; /* Should be 0 */
	qemu_siginfo_fpu_t	fpu_state;
};

#define UREG_O0        16
#define UREG_O6        22
#define UREG_I0        0
#define UREG_I1        1
#define UREG_I2        2
#define UREG_I3        3
#define UREG_I4        4
#define UREG_I5        5
#define UREG_I6        6
#define UREG_I7        7
#define UREG_L0	       8
#define UREG_FP        UREG_I6
#define UREG_SP        UREG_O6

static inline abi_ulong get_sigframe(struct target_sigaction *sa, 
                                     CPUState *env, unsigned long framesize)
{
	abi_ulong sp;

	sp = env->regwptr[UREG_FP];

	/* This is the X/Open sanctioned signal stack switching.  */
	if (sa->sa_flags & TARGET_SA_ONSTACK) {
            if (!on_sig_stack(sp)
                && !((target_sigaltstack_used.ss_sp + target_sigaltstack_used.ss_size) & 7))
                sp = target_sigaltstack_used.ss_sp + target_sigaltstack_used.ss_size;
	}
	return sp - framesize;
}

static int
setup___siginfo(__siginfo_t *si, CPUState *env, abi_ulong mask)
{
	int err = 0, i;

	err |= __put_user(env->psr, &si->si_regs.psr);
	err |= __put_user(env->pc, &si->si_regs.pc);
	err |= __put_user(env->npc, &si->si_regs.npc);
	err |= __put_user(env->y, &si->si_regs.y);
	for (i=0; i < 8; i++) {
		err |= __put_user(env->gregs[i], &si->si_regs.u_regs[i]);
	}
	for (i=0; i < 8; i++) {
		err |= __put_user(env->regwptr[UREG_I0 + i], &si->si_regs.u_regs[i+8]);
	}
	err |= __put_user(mask, &si->si_mask);
	return err;
}

#if 0
static int
setup_sigcontext(struct target_sigcontext *sc, /*struct _fpstate *fpstate,*/
		 CPUState *env, unsigned long mask)
{
	int err = 0;

	err |= __put_user(mask, &sc->sigc_mask);
	err |= __put_user(env->regwptr[UREG_SP], &sc->sigc_sp);
	err |= __put_user(env->pc, &sc->sigc_pc);
	err |= __put_user(env->npc, &sc->sigc_npc);
	err |= __put_user(env->psr, &sc->sigc_psr);
	err |= __put_user(env->gregs[1], &sc->sigc_g1);
	err |= __put_user(env->regwptr[UREG_O0], &sc->sigc_o0);

	return err;
}
#endif
#define NF_ALIGNEDSZ  (((sizeof(struct target_signal_frame) + 7) & (~7)))

void setup_frame(int sig, struct target_sigaction *ka,
                 target_sigset_t *set, CPUState *env)
{
        abi_ulong sf_addr;
	struct target_signal_frame *sf;
	int sigframe_size, err, i;

	/* 1. Make sure everything is clean */
	//synchronize_user_stack();

        sigframe_size = NF_ALIGNEDSZ;
	sf_addr = get_sigframe(ka, env, sigframe_size);

        sf = lock_user(VERIFY_WRITE, sf_addr, 
                       sizeof(struct target_signal_frame), 0);
        if (!sf)
		goto sigsegv;
                
	//fprintf(stderr, "sf: %x pc %x fp %x sp %x\n", sf, env->pc, env->regwptr[UREG_FP], env->regwptr[UREG_SP]);
#if 0
	if (invalid_frame_pointer(sf, sigframe_size))
		goto sigill_and_return;
#endif
	/* 2. Save the current process state */
	err = setup___siginfo(&sf->info, env, set->sig[0]);
	err |= __put_user(0, &sf->extra_size);

	//err |= save_fpu_state(regs, &sf->fpu_state);
	//err |= __put_user(&sf->fpu_state, &sf->fpu_save);

	err |= __put_user(set->sig[0], &sf->info.si_mask);
	for (i = 0; i < TARGET_NSIG_WORDS - 1; i++) {
		err |= __put_user(set->sig[i + 1], &sf->extramask[i]);
	}

	for (i = 0; i < 8; i++) {
	  	err |= __put_user(env->regwptr[i + UREG_L0], &sf->ss.locals[i]);
	}
	for (i = 0; i < 8; i++) {
	  	err |= __put_user(env->regwptr[i + UREG_I0], &sf->ss.ins[i]);
	}
	if (err)
		goto sigsegv;

	/* 3. signal handler back-trampoline and parameters */
	env->regwptr[UREG_FP] = sf_addr;
	env->regwptr[UREG_I0] = sig;
	env->regwptr[UREG_I1] = sf_addr + 
                offsetof(struct target_signal_frame, info);
	env->regwptr[UREG_I2] = sf_addr + 
                offsetof(struct target_signal_frame, info);

	/* 4. signal handler */
	env->pc = ka->_sa_handler;
	env->npc = (env->pc + 4);
	/* 5. return to kernel instructions */
	if (ka->sa_restorer)
		env->regwptr[UREG_I7] = ka->sa_restorer;
	else {
                uint32_t val32;

		env->regwptr[UREG_I7] = sf_addr + 
                        offsetof(struct target_signal_frame, insns) - 2 * 4;

		/* mov __NR_sigreturn, %g1 */
                val32 = 0x821020d8;
		err |= __put_user(val32, &sf->insns[0]);

		/* t 0x10 */
                val32 = 0x91d02010;
		err |= __put_user(val32, &sf->insns[1]);
		if (err)
			goto sigsegv;

		/* Flush instruction space. */
		//flush_sig_insns(current->mm, (unsigned long) &(sf->insns[0]));
                //		tb_flush(env);
	}
        unlock_user(sf, sf_addr, sizeof(struct target_signal_frame));
	return;
#if 0
sigill_and_return:
	force_sig(TARGET_SIGILL);
#endif
sigsegv:
	//fprintf(stderr, "force_sig\n");
        unlock_user(sf, sf_addr, sizeof(struct target_signal_frame));
	force_sig(TARGET_SIGSEGV);
}
static inline int
restore_fpu_state(CPUState *env, qemu_siginfo_fpu_t *fpu)
{
        int err;
#if 0
#ifdef CONFIG_SMP
        if (current->flags & PF_USEDFPU)
                regs->psr &= ~PSR_EF;
#else
        if (current == last_task_used_math) {
                last_task_used_math = 0;
                regs->psr &= ~PSR_EF;
        }
#endif
        current->used_math = 1;
        current->flags &= ~PF_USEDFPU;
#endif
#if 0
        if (verify_area (VERIFY_READ, fpu, sizeof(*fpu)))
                return -EFAULT;
#endif

#if 0
        /* XXX: incorrect */
        err = __copy_from_user(&env->fpr[0], &fpu->si_float_regs[0],
	                             (sizeof(unsigned long) * 32));
#endif
        err |= __get_user(env->fsr, &fpu->si_fsr);
#if 0
        err |= __get_user(current->thread.fpqdepth, &fpu->si_fpqdepth);
        if (current->thread.fpqdepth != 0)
                err |= __copy_from_user(&current->thread.fpqueue[0],
                                        &fpu->si_fpqueue[0],
                                        ((sizeof(unsigned long) +
                                        (sizeof(unsigned long *)))*16));
#endif
        return err;
}


void setup_rt_frame(int sig, struct target_sigaction *ka,
                    target_siginfo_t *info,
                    target_sigset_t *set, CPUState *env)
{
    fprintf(stderr, "setup_rt_frame: not implemented\n");
}

long do_sigreturn(CPUState *env)
{
        abi_ulong sf_addr;
        struct target_signal_frame *sf;
        uint32_t up_psr, pc, npc;
        target_sigset_t set;
        sigset_t host_set;
        int err, i;

        sf_addr = env->regwptr[UREG_FP];
        if (!lock_user_struct(VERIFY_READ, sf, sf_addr, 1))
                goto segv_and_exit;
#if 0
	fprintf(stderr, "sigreturn\n");
	fprintf(stderr, "sf: %x pc %x fp %x sp %x\n", sf, env->pc, env->regwptr[UREG_FP], env->regwptr[UREG_SP]);
#endif
	//cpu_dump_state(env, stderr, fprintf, 0);

        /* 1. Make sure we are not getting garbage from the user */

        if (sf_addr & 3)
                goto segv_and_exit;

        err = __get_user(pc,  &sf->info.si_regs.pc);
        err |= __get_user(npc, &sf->info.si_regs.npc);

        if ((pc | npc) & 3)
                goto segv_and_exit;

        /* 2. Restore the state */
        err |= __get_user(up_psr, &sf->info.si_regs.psr);

        /* User can only change condition codes and FPU enabling in %psr. */
        env->psr = (up_psr & (PSR_ICC /* | PSR_EF */))
                  | (env->psr & ~(PSR_ICC /* | PSR_EF */));

	env->pc = pc;
	env->npc = npc;
        err |= __get_user(env->y, &sf->info.si_regs.y);
	for (i=0; i < 8; i++) {
		err |= __get_user(env->gregs[i], &sf->info.si_regs.u_regs[i]);
	}
	for (i=0; i < 8; i++) {
		err |= __get_user(env->regwptr[i + UREG_I0], &sf->info.si_regs.u_regs[i+8]);
	}

        /* FIXME: implement FPU save/restore:
         * __get_user(fpu_save, &sf->fpu_save);
         * if (fpu_save)
         *        err |= restore_fpu_state(env, fpu_save);
         */

        /* This is pretty much atomic, no amount locking would prevent
         * the races which exist anyways.
         */
        err |= __get_user(set.sig[0], &sf->info.si_mask);
        for(i = 1; i < TARGET_NSIG_WORDS; i++) {
            err |= (__get_user(set.sig[i], &sf->extramask[i - 1]));
        }

        target_to_host_sigset_internal(&host_set, &set);
        sigprocmask(SIG_SETMASK, &host_set, NULL);

        if (err)
                goto segv_and_exit;
        unlock_user_struct(sf, sf_addr, 0);
        return env->regwptr[0];

segv_and_exit:
        unlock_user_struct(sf, sf_addr, 0);
	force_sig(TARGET_SIGSEGV);
}

long do_rt_sigreturn(CPUState *env)
{
    fprintf(stderr, "do_rt_sigreturn: not implemented\n");
    return -TARGET_ENOSYS;
}

