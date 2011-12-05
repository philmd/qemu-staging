/*
 *  Emulation of Linux signals : i386 specific code
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

/* from the Linux kernel */

struct target_fpreg {
	uint16_t significand[4];
	uint16_t exponent;
};

struct target_fpxreg {
	uint16_t significand[4];
	uint16_t exponent;
	uint16_t padding[3];
};

struct target_xmmreg {
	abi_ulong element[4];
};

struct target_fpstate {
	/* Regular FPU environment */
        abi_ulong       cw;
        abi_ulong       sw;
        abi_ulong       tag;
        abi_ulong       ipoff;
        abi_ulong       cssel;
        abi_ulong       dataoff;
        abi_ulong       datasel;
	struct target_fpreg	_st[8];
	uint16_t	status;
	uint16_t	magic;		/* 0xffff = regular FPU data only */

	/* FXSR FPU environment */
        abi_ulong       _fxsr_env[6];   /* FXSR FPU env is ignored */
        abi_ulong       mxcsr;
        abi_ulong       reserved;
	struct target_fpxreg	_fxsr_st[8];	/* FXSR FPU reg data is ignored */
	struct target_xmmreg	_xmm[8];
        abi_ulong       padding[56];
};

#define X86_FXSR_MAGIC		0x0000

struct target_sigcontext {
	uint16_t gs, __gsh;
	uint16_t fs, __fsh;
	uint16_t es, __esh;
	uint16_t ds, __dsh;
        abi_ulong edi;
        abi_ulong esi;
        abi_ulong ebp;
        abi_ulong esp;
        abi_ulong ebx;
        abi_ulong edx;
        abi_ulong ecx;
        abi_ulong eax;
        abi_ulong trapno;
        abi_ulong err;
        abi_ulong eip;
	uint16_t cs, __csh;
        abi_ulong eflags;
        abi_ulong esp_at_signal;
	uint16_t ss, __ssh;
        abi_ulong fpstate; /* pointer */
        abi_ulong oldmask;
        abi_ulong cr2;
};

struct target_ucontext {
        abi_ulong         tuc_flags;
        abi_ulong         tuc_link;
	target_stack_t	  tuc_stack;
	struct target_sigcontext tuc_mcontext;
	target_sigset_t	  tuc_sigmask;	/* mask last for extensibility */
};

struct sigframe
{
    abi_ulong pretcode;
    int sig;
    struct target_sigcontext sc;
    struct target_fpstate fpstate;
    abi_ulong extramask[TARGET_NSIG_WORDS-1];
    char retcode[8];
};

struct rt_sigframe
{
    abi_ulong pretcode;
    int sig;
    abi_ulong pinfo;
    abi_ulong puc;
    struct target_siginfo info;
    struct target_ucontext uc;
    struct target_fpstate fpstate;
    char retcode[8];
};

/*
 * Set up a signal frame.
 */

/* XXX: save x87 state */
static int
setup_sigcontext(struct target_sigcontext *sc, struct target_fpstate *fpstate,
		 CPUX86State *env, abi_ulong mask, abi_ulong fpstate_addr)
{
	int err = 0;
        uint16_t magic;

	/* already locked in setup_frame() */
	err |= __put_user(env->segs[R_GS].selector, (unsigned int *)&sc->gs);
	err |= __put_user(env->segs[R_FS].selector, (unsigned int *)&sc->fs);
	err |= __put_user(env->segs[R_ES].selector, (unsigned int *)&sc->es);
	err |= __put_user(env->segs[R_DS].selector, (unsigned int *)&sc->ds);
	err |= __put_user(env->regs[R_EDI], &sc->edi);
	err |= __put_user(env->regs[R_ESI], &sc->esi);
	err |= __put_user(env->regs[R_EBP], &sc->ebp);
	err |= __put_user(env->regs[R_ESP], &sc->esp);
	err |= __put_user(env->regs[R_EBX], &sc->ebx);
	err |= __put_user(env->regs[R_EDX], &sc->edx);
	err |= __put_user(env->regs[R_ECX], &sc->ecx);
	err |= __put_user(env->regs[R_EAX], &sc->eax);
	err |= __put_user(env->exception_index, &sc->trapno);
	err |= __put_user(env->error_code, &sc->err);
	err |= __put_user(env->eip, &sc->eip);
	err |= __put_user(env->segs[R_CS].selector, (unsigned int *)&sc->cs);
	err |= __put_user(env->eflags, &sc->eflags);
	err |= __put_user(env->regs[R_ESP], &sc->esp_at_signal);
	err |= __put_user(env->segs[R_SS].selector, (unsigned int *)&sc->ss);

        cpu_x86_fsave(env, fpstate_addr, 1);
        fpstate->status = fpstate->sw;
        magic = 0xffff;
        err |= __put_user(magic, &fpstate->magic);
        err |= __put_user(fpstate_addr, &sc->fpstate);

	/* non-iBCS2 extensions.. */
	err |= __put_user(mask, &sc->oldmask);
	err |= __put_user(env->cr[2], &sc->cr2);
	return err;
}

/*
 * Determine which stack to use..
 */

static inline abi_ulong
get_sigframe(struct target_sigaction *ka, CPUX86State *env, size_t frame_size)
{
	unsigned long esp;

	/* Default to using normal stack */
	esp = env->regs[R_ESP];
	/* This is the X/Open sanctioned signal stack switching.  */
        if (ka->sa_flags & TARGET_SA_ONSTACK) {
            if (sas_ss_flags(esp) == 0)
                esp = target_sigaltstack_used.ss_sp + target_sigaltstack_used.ss_size;
        }

	/* This is the legacy signal stack switching. */
	else
        if ((env->segs[R_SS].selector & 0xffff) != __USER_DS &&
            !(ka->sa_flags & TARGET_SA_RESTORER) &&
            ka->sa_restorer) {
            esp = (unsigned long) ka->sa_restorer;
	}
        return (esp - frame_size) & -8ul;
}

/* compare linux/arch/i386/kernel/signal.c:setup_frame() */
void setup_frame(int sig, struct target_sigaction *ka,
			target_sigset_t *set, CPUX86State *env)
{
	abi_ulong frame_addr;
	struct sigframe *frame;
	int i, err = 0;

	frame_addr = get_sigframe(ka, env, sizeof(*frame));

	if (!lock_user_struct(VERIFY_WRITE, frame, frame_addr, 0))
		goto give_sigsegv;

	err |= __put_user(current_exec_domain_sig(sig),
		          &frame->sig);
	if (err)
		goto give_sigsegv;

	setup_sigcontext(&frame->sc, &frame->fpstate, env, set->sig[0],
                         frame_addr + offsetof(struct sigframe, fpstate));
	if (err)
		goto give_sigsegv;

        for(i = 1; i < TARGET_NSIG_WORDS; i++) {
            if (__put_user(set->sig[i], &frame->extramask[i - 1]))
                goto give_sigsegv;
        }

	/* Set up to return from userspace.  If provided, use a stub
	   already in userspace.  */
	if (ka->sa_flags & TARGET_SA_RESTORER) {
		err |= __put_user(ka->sa_restorer, &frame->pretcode);
	} else {
                uint16_t val16;
                abi_ulong retcode_addr;
                retcode_addr = frame_addr + offsetof(struct sigframe, retcode);
		err |= __put_user(retcode_addr, &frame->pretcode);
		/* This is popl %eax ; movl $,%eax ; int $0x80 */
                val16 = 0xb858;
		err |= __put_user(val16, (uint16_t *)(frame->retcode+0));
		err |= __put_user(TARGET_NR_sigreturn, (int *)(frame->retcode+2));
                val16 = 0x80cd;
		err |= __put_user(val16, (uint16_t *)(frame->retcode+6));
	}

	if (err)
		goto give_sigsegv;

	/* Set up registers for signal handler */
	env->regs[R_ESP] = frame_addr;
	env->eip = ka->_sa_handler;

        cpu_x86_load_seg(env, R_DS, __USER_DS);
        cpu_x86_load_seg(env, R_ES, __USER_DS);
        cpu_x86_load_seg(env, R_SS, __USER_DS);
        cpu_x86_load_seg(env, R_CS, __USER_CS);
	env->eflags &= ~TF_MASK;

	unlock_user_struct(frame, frame_addr, 1);

	return;

give_sigsegv:
	unlock_user_struct(frame, frame_addr, 1);
	if (sig == TARGET_SIGSEGV)
		ka->_sa_handler = TARGET_SIG_DFL;
	force_sig(TARGET_SIGSEGV /* , current */);
}

/* compare linux/arch/i386/kernel/signal.c:setup_rt_frame() */
void setup_rt_frame(int sig, struct target_sigaction *ka,
                           target_siginfo_t *info,
			   target_sigset_t *set, CPUX86State *env)
{
        abi_ulong frame_addr, addr;
	struct rt_sigframe *frame;
	int i, err = 0;

	frame_addr = get_sigframe(ka, env, sizeof(*frame));

	if (!lock_user_struct(VERIFY_WRITE, frame, frame_addr, 0))
		goto give_sigsegv;

	err |= __put_user(current_exec_domain_sig(sig),
			  &frame->sig);
        addr = frame_addr + offsetof(struct rt_sigframe, info);
	err |= __put_user(addr, &frame->pinfo);
        addr = frame_addr + offsetof(struct rt_sigframe, uc);
	err |= __put_user(addr, &frame->puc);
	err |= copy_siginfo_to_user(&frame->info, info);
	if (err)
		goto give_sigsegv;

	/* Create the ucontext.  */
	err |= __put_user(0, &frame->uc.tuc_flags);
	err |= __put_user(0, &frame->uc.tuc_link);
	err |= __put_user(target_sigaltstack_used.ss_sp,
			  &frame->uc.tuc_stack.ss_sp);
	err |= __put_user(sas_ss_flags(get_sp_from_cpustate(env)),
			  &frame->uc.tuc_stack.ss_flags);
	err |= __put_user(target_sigaltstack_used.ss_size,
			  &frame->uc.tuc_stack.ss_size);
	err |= setup_sigcontext(&frame->uc.tuc_mcontext, &frame->fpstate,
			        env, set->sig[0], 
                                frame_addr + offsetof(struct rt_sigframe, fpstate));
        for(i = 0; i < TARGET_NSIG_WORDS; i++) {
            if (__put_user(set->sig[i], &frame->uc.tuc_sigmask.sig[i]))
                goto give_sigsegv;
        }

	/* Set up to return from userspace.  If provided, use a stub
	   already in userspace.  */
	if (ka->sa_flags & TARGET_SA_RESTORER) {
		err |= __put_user(ka->sa_restorer, &frame->pretcode);
	} else {
                uint16_t val16;
                addr = frame_addr + offsetof(struct rt_sigframe, retcode);
		err |= __put_user(addr, &frame->pretcode);
		/* This is movl $,%eax ; int $0x80 */
                err |= __put_user(0xb8, (char *)(frame->retcode+0));
		err |= __put_user(TARGET_NR_rt_sigreturn, (int *)(frame->retcode+1));
                val16 = 0x80cd;
                err |= __put_user(val16, (uint16_t *)(frame->retcode+5));
	}

	if (err)
		goto give_sigsegv;

	/* Set up registers for signal handler */
	env->regs[R_ESP] = frame_addr;
	env->eip = ka->_sa_handler;

        cpu_x86_load_seg(env, R_DS, __USER_DS);
        cpu_x86_load_seg(env, R_ES, __USER_DS);
        cpu_x86_load_seg(env, R_SS, __USER_DS);
        cpu_x86_load_seg(env, R_CS, __USER_CS);
	env->eflags &= ~TF_MASK;

	unlock_user_struct(frame, frame_addr, 1);

	return;

give_sigsegv:
	unlock_user_struct(frame, frame_addr, 1);
	if (sig == TARGET_SIGSEGV)
		ka->_sa_handler = TARGET_SIG_DFL;
	force_sig(TARGET_SIGSEGV /* , current */);
}

static int
restore_sigcontext(CPUX86State *env, struct target_sigcontext *sc, int *peax)
{
	unsigned int err = 0;
        abi_ulong fpstate_addr;
        unsigned int tmpflags;

        cpu_x86_load_seg(env, R_GS, tswap16(sc->gs));
        cpu_x86_load_seg(env, R_FS, tswap16(sc->fs));
        cpu_x86_load_seg(env, R_ES, tswap16(sc->es));
        cpu_x86_load_seg(env, R_DS, tswap16(sc->ds));

        env->regs[R_EDI] = tswapl(sc->edi);
        env->regs[R_ESI] = tswapl(sc->esi);
        env->regs[R_EBP] = tswapl(sc->ebp);
        env->regs[R_ESP] = tswapl(sc->esp);
        env->regs[R_EBX] = tswapl(sc->ebx);
        env->regs[R_EDX] = tswapl(sc->edx);
        env->regs[R_ECX] = tswapl(sc->ecx);
        env->eip = tswapl(sc->eip);

        cpu_x86_load_seg(env, R_CS, lduw_p(&sc->cs) | 3);
        cpu_x86_load_seg(env, R_SS, lduw_p(&sc->ss) | 3);

        tmpflags = tswapl(sc->eflags);
        env->eflags = (env->eflags & ~0x40DD5) | (tmpflags & 0x40DD5);
        //		regs->orig_eax = -1;		/* disable syscall checks */

        fpstate_addr = tswapl(sc->fpstate);
	if (fpstate_addr != 0) {
                if (!access_ok(VERIFY_READ, fpstate_addr, 
                               sizeof(struct target_fpstate)))
                        goto badframe;
                cpu_x86_frstor(env, fpstate_addr, 1);
	}

        *peax = tswapl(sc->eax);
	return err;
badframe:
	return 1;
}

long do_sigreturn(CPUX86State *env)
{
    struct sigframe *frame;
    abi_ulong frame_addr = env->regs[R_ESP] - 8;
    target_sigset_t target_set;
    sigset_t set;
    int eax, i;

#if defined(DEBUG_SIGNAL)
    fprintf(stderr, "do_sigreturn\n");
#endif
    if (!lock_user_struct(VERIFY_READ, frame, frame_addr, 1))
        goto badframe;
    /* set blocked signals */
    if (__get_user(target_set.sig[0], &frame->sc.oldmask))
        goto badframe;
    for(i = 1; i < TARGET_NSIG_WORDS; i++) {
        if (__get_user(target_set.sig[i], &frame->extramask[i - 1]))
            goto badframe;
    }

    target_to_host_sigset_internal(&set, &target_set);
    sigprocmask(SIG_SETMASK, &set, NULL);

    /* restore registers */
    if (restore_sigcontext(env, &frame->sc, &eax))
        goto badframe;
    unlock_user_struct(frame, frame_addr, 0);
    return eax;

badframe:
    unlock_user_struct(frame, frame_addr, 0);
    force_sig(TARGET_SIGSEGV);
    return 0;
}

long do_rt_sigreturn(CPUX86State *env)
{
        abi_ulong frame_addr;
	struct rt_sigframe *frame;
        sigset_t set;
	int eax;

        frame_addr = env->regs[R_ESP] - 4;
        if (!lock_user_struct(VERIFY_READ, frame, frame_addr, 1))
                goto badframe;
        target_to_host_sigset(&set, &frame->uc.tuc_sigmask);
        sigprocmask(SIG_SETMASK, &set, NULL);

	if (restore_sigcontext(env, &frame->uc.tuc_mcontext, &eax))
		goto badframe;

	if (do_sigaltstack(frame_addr + offsetof(struct rt_sigframe, uc.tuc_stack), 0, 
                           get_sp_from_cpustate(env)) == -EFAULT)
		goto badframe;

        unlock_user_struct(frame, frame_addr, 0);
	return eax;

badframe:
        unlock_user_struct(frame, frame_addr, 0);
        force_sig(TARGET_SIGSEGV);
	return 0;
}

