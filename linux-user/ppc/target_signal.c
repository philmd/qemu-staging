/*
 *  Emulation of Linux signals : PPC specific code
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



#if defined(TARGET_PPC64)
void setup_frame(int sig, struct target_sigaction *ka,
                 target_sigset_t *set, CPUState *env)
{
    fprintf(stderr, "setup_frame: not implemented\n");
}

void setup_rt_frame(int sig, struct target_sigaction *ka,
                    target_siginfo_t *info,
                    target_sigset_t *set, CPUState *env)
{
    fprintf(stderr, "setup_rt_frame: not implemented\n");
}

long do_sigreturn(CPUState *env)
{
    fprintf(stderr, "do_sigreturn: not implemented\n");
    return -TARGET_ENOSYS;
}

long do_rt_sigreturn(CPUState *env)
{
    fprintf(stderr, "do_rt_sigreturn: not implemented\n");
    return -TARGET_ENOSYS;
}
#else

/* FIXME: Many of the structures are defined for both PPC and PPC64, but
   the signal handling is different enough that we haven't implemented
   support for PPC64 yet.  Hence the restriction above.

   There are various #if'd blocks for code for TARGET_PPC64.  These
   blocks should go away so that we can successfully run 32-bit and
   64-bit binaries on a QEMU configured for PPC64.  */

/* Size of dummy stack frame allocated when calling signal handler.
   See arch/powerpc/include/asm/ptrace.h.  */
#if defined(TARGET_PPC64)
#define SIGNAL_FRAMESIZE 128
#else
#define SIGNAL_FRAMESIZE 64
#endif

/* See arch/powerpc/include/asm/sigcontext.h.  */
struct target_sigcontext {
    target_ulong _unused[4];
    int32_t signal;
#if defined(TARGET_PPC64)
    int32_t pad0;
#endif
    target_ulong handler;
    target_ulong oldmask;
    target_ulong regs;      /* struct pt_regs __user * */
    /* TODO: PPC64 includes extra bits here.  */
};

/* Indices for target_mcontext.mc_gregs, below.
   See arch/powerpc/include/asm/ptrace.h for details.  */
enum {
    TARGET_PT_R0 = 0,
    TARGET_PT_R1 = 1,
    TARGET_PT_R2 = 2,
    TARGET_PT_R3 = 3,
    TARGET_PT_R4 = 4,
    TARGET_PT_R5 = 5,
    TARGET_PT_R6 = 6,
    TARGET_PT_R7 = 7,
    TARGET_PT_R8 = 8,
    TARGET_PT_R9 = 9,
    TARGET_PT_R10 = 10,
    TARGET_PT_R11 = 11,
    TARGET_PT_R12 = 12,
    TARGET_PT_R13 = 13,
    TARGET_PT_R14 = 14,
    TARGET_PT_R15 = 15,
    TARGET_PT_R16 = 16,
    TARGET_PT_R17 = 17,
    TARGET_PT_R18 = 18,
    TARGET_PT_R19 = 19,
    TARGET_PT_R20 = 20,
    TARGET_PT_R21 = 21,
    TARGET_PT_R22 = 22,
    TARGET_PT_R23 = 23,
    TARGET_PT_R24 = 24,
    TARGET_PT_R25 = 25,
    TARGET_PT_R26 = 26,
    TARGET_PT_R27 = 27,
    TARGET_PT_R28 = 28,
    TARGET_PT_R29 = 29,
    TARGET_PT_R30 = 30,
    TARGET_PT_R31 = 31,
    TARGET_PT_NIP = 32,
    TARGET_PT_MSR = 33,
    TARGET_PT_ORIG_R3 = 34,
    TARGET_PT_CTR = 35,
    TARGET_PT_LNK = 36,
    TARGET_PT_XER = 37,
    TARGET_PT_CCR = 38,
    /* Yes, there are two registers with #39.  One is 64-bit only.  */
    TARGET_PT_MQ = 39,
    TARGET_PT_SOFTE = 39,
    TARGET_PT_TRAP = 40,
    TARGET_PT_DAR = 41,
    TARGET_PT_DSISR = 42,
    TARGET_PT_RESULT = 43,
    TARGET_PT_REGS_COUNT = 44
};

/* See arch/powerpc/include/asm/ucontext.h.  Only used for 32-bit PPC;
   on 64-bit PPC, sigcontext and mcontext are one and the same.  */
struct target_mcontext {
    target_ulong mc_gregs[48];
    /* Includes fpscr.  */
    uint64_t mc_fregs[33];
    target_ulong mc_pad[2];
    /* We need to handle Altivec and SPE at the same time, which no
       kernel needs to do.  Fortunately, the kernel defines this bit to
       be Altivec-register-large all the time, rather than trying to
       twiddle it based on the specific platform.  */
    union {
        /* SPE vector registers.  One extra for SPEFSCR.  */
        uint32_t spe[33];
        /* Altivec vector registers.  The packing of VSCR and VRSAVE
           varies depending on whether we're PPC64 or not: PPC64 splits
           them apart; PPC32 stuffs them together.  */
#if defined(TARGET_PPC64)
#define QEMU_NVRREG 34
#else
#define QEMU_NVRREG 33
#endif
        ppc_avr_t altivec[QEMU_NVRREG];
#undef QEMU_NVRREG
    } mc_vregs __attribute__((__aligned__(16)));
};

struct target_ucontext {
    target_ulong tuc_flags;
    target_ulong tuc_link;    /* struct ucontext __user * */
    struct target_sigaltstack tuc_stack;
#if !defined(TARGET_PPC64)
    int32_t tuc_pad[7];
    target_ulong tuc_regs;    /* struct mcontext __user *
                                points to uc_mcontext field */
#endif
    target_sigset_t tuc_sigmask;
#if defined(TARGET_PPC64)
    target_sigset_t unused[15]; /* Allow for uc_sigmask growth */
    struct target_sigcontext tuc_mcontext;
#else
    int32_t tuc_maskext[30];
    int32_t tuc_pad2[3];
    struct target_mcontext tuc_mcontext;
#endif
};

/* See arch/powerpc/kernel/signal_32.c.  */
struct target_sigframe {
    struct target_sigcontext sctx;
    struct target_mcontext mctx;
    int32_t abigap[56];
};

struct target_rt_sigframe {
    struct target_siginfo info;
    struct target_ucontext uc;
    int32_t abigap[56];
};

/* We use the mc_pad field for the signal return trampoline.  */
#define tramp mc_pad

/* See arch/powerpc/kernel/signal.c.  */
static target_ulong get_sigframe(struct target_sigaction *ka,
                                 CPUState *env,
                                 int frame_size)
{
    target_ulong oldsp, newsp;

    oldsp = env->gpr[1];

    if ((ka->sa_flags & TARGET_SA_ONSTACK) &&
        (sas_ss_flags(oldsp))) {
        oldsp = (target_sigaltstack_used.ss_sp
                 + target_sigaltstack_used.ss_size);
    }

    newsp = (oldsp - frame_size) & ~0xFUL;

    return newsp;
}

static int save_user_regs(CPUState *env, struct target_mcontext *frame,
                          int sigret)
{
    target_ulong msr = env->msr;
    int i;
    target_ulong ccr = 0;

    /* In general, the kernel attempts to be intelligent about what it
       needs to save for Altivec/FP/SPE registers.  We don't care that
       much, so we just go ahead and save everything.  */

    /* Save general registers.  */
    for (i = 0; i < ARRAY_SIZE(env->gpr); i++) {
        if (__put_user(env->gpr[i], &frame->mc_gregs[i])) {
            return 1;
        }
    }
    if (__put_user(env->nip, &frame->mc_gregs[TARGET_PT_NIP])
        || __put_user(env->ctr, &frame->mc_gregs[TARGET_PT_CTR])
        || __put_user(env->lr, &frame->mc_gregs[TARGET_PT_LNK])
        || __put_user(env->xer, &frame->mc_gregs[TARGET_PT_XER]))
        return 1;

    for (i = 0; i < ARRAY_SIZE(env->crf); i++) {
        ccr |= env->crf[i] << (32 - ((i + 1) * 4));
    }
    if (__put_user(ccr, &frame->mc_gregs[TARGET_PT_CCR]))
        return 1;

    /* Save Altivec registers if necessary.  */
    if (env->insns_flags & PPC_ALTIVEC) {
        for (i = 0; i < ARRAY_SIZE(env->avr); i++) {
            ppc_avr_t *avr = &env->avr[i];
            ppc_avr_t *vreg = &frame->mc_vregs.altivec[i];

            if (__put_user(avr->u64[0], &vreg->u64[0]) ||
                __put_user(avr->u64[1], &vreg->u64[1])) {
                return 1;
            }
        }
        /* Set MSR_VR in the saved MSR value to indicate that
           frame->mc_vregs contains valid data.  */
        msr |= MSR_VR;
        if (__put_user((uint32_t)env->spr[SPR_VRSAVE],
                       &frame->mc_vregs.altivec[32].u32[3]))
            return 1;
    }

    /* Save floating point registers.  */
    if (env->insns_flags & PPC_FLOAT) {
        for (i = 0; i < ARRAY_SIZE(env->fpr); i++) {
            if (__put_user(env->fpr[i], &frame->mc_fregs[i])) {
                return 1;
            }
        }
        if (__put_user((uint64_t) env->fpscr, &frame->mc_fregs[32]))
            return 1;
    }

    /* Save SPE registers.  The kernel only saves the high half.  */
    if (env->insns_flags & PPC_SPE) {
#if defined(TARGET_PPC64)
        for (i = 0; i < ARRAY_SIZE(env->gpr); i++) {
            if (__put_user(env->gpr[i] >> 32, &frame->mc_vregs.spe[i])) {
                return 1;
            }
        }
#else
        for (i = 0; i < ARRAY_SIZE(env->gprh); i++) {
            if (__put_user(env->gprh[i], &frame->mc_vregs.spe[i])) {
                return 1;
            }
        }
#endif
        /* Set MSR_SPE in the saved MSR value to indicate that
           frame->mc_vregs contains valid data.  */
        msr |= MSR_SPE;
        if (__put_user(env->spe_fscr, &frame->mc_vregs.spe[32]))
            return 1;
    }

    /* Store MSR.  */
    if (__put_user(msr, &frame->mc_gregs[TARGET_PT_MSR]))
        return 1;

    /* Set up the sigreturn trampoline: li r0,sigret; sc.  */
    if (sigret) {
        if (__put_user(0x38000000UL | sigret, &frame->tramp[0]) ||
            __put_user(0x44000002UL, &frame->tramp[1])) {
            return 1;
        }
    }

    return 0;
}

static int restore_user_regs(CPUState *env,
                             struct target_mcontext *frame, int sig)
{
    target_ulong save_r2 = 0;
    target_ulong msr;
    target_ulong ccr;

    int i;

    if (!sig) {
        save_r2 = env->gpr[2];
    }

    /* Restore general registers.  */
    for (i = 0; i < ARRAY_SIZE(env->gpr); i++) {
        if (__get_user(env->gpr[i], &frame->mc_gregs[i])) {
            return 1;
        }
    }
    if (__get_user(env->nip, &frame->mc_gregs[TARGET_PT_NIP])
        || __get_user(env->ctr, &frame->mc_gregs[TARGET_PT_CTR])
        || __get_user(env->lr, &frame->mc_gregs[TARGET_PT_LNK])
        || __get_user(env->xer, &frame->mc_gregs[TARGET_PT_XER]))
        return 1;
    if (__get_user(ccr, &frame->mc_gregs[TARGET_PT_CCR]))
        return 1;

    for (i = 0; i < ARRAY_SIZE(env->crf); i++) {
        env->crf[i] = (ccr >> (32 - ((i + 1) * 4))) & 0xf;
    }

    if (!sig) {
        env->gpr[2] = save_r2;
    }
    /* Restore MSR.  */
    if (__get_user(msr, &frame->mc_gregs[TARGET_PT_MSR]))
        return 1;

    /* If doing signal return, restore the previous little-endian mode.  */
    if (sig)
        env->msr = (env->msr & ~MSR_LE) | (msr & MSR_LE);

    /* Restore Altivec registers if necessary.  */
    if (env->insns_flags & PPC_ALTIVEC) {
        for (i = 0; i < ARRAY_SIZE(env->avr); i++) {
            ppc_avr_t *avr = &env->avr[i];
            ppc_avr_t *vreg = &frame->mc_vregs.altivec[i];

            if (__get_user(avr->u64[0], &vreg->u64[0]) ||
                __get_user(avr->u64[1], &vreg->u64[1])) {
                return 1;
            }
        }
        /* Set MSR_VEC in the saved MSR value to indicate that
           frame->mc_vregs contains valid data.  */
        if (__get_user(env->spr[SPR_VRSAVE],
                       (target_ulong *)(&frame->mc_vregs.altivec[32].u32[3])))
            return 1;
    }

    /* Restore floating point registers.  */
    if (env->insns_flags & PPC_FLOAT) {
        uint64_t fpscr;
        for (i = 0; i < ARRAY_SIZE(env->fpr); i++) {
            if (__get_user(env->fpr[i], &frame->mc_fregs[i])) {
                return 1;
            }
        }
        if (__get_user(fpscr, &frame->mc_fregs[32]))
            return 1;
        env->fpscr = (uint32_t) fpscr;
    }

    /* Save SPE registers.  The kernel only saves the high half.  */
    if (env->insns_flags & PPC_SPE) {
#if defined(TARGET_PPC64)
        for (i = 0; i < ARRAY_SIZE(env->gpr); i++) {
            uint32_t hi;

            if (__get_user(hi, &frame->mc_vregs.spe[i])) {
                return 1;
            }
            env->gpr[i] = ((uint64_t)hi << 32) | ((uint32_t) env->gpr[i]);
        }
#else
        for (i = 0; i < ARRAY_SIZE(env->gprh); i++) {
            if (__get_user(env->gprh[i], &frame->mc_vregs.spe[i])) {
                return 1;
            }
        }
#endif
        if (__get_user(env->spe_fscr, &frame->mc_vregs.spe[32]))
            return 1;
    }

    return 0;
}

void setup_frame(int sig, struct target_sigaction *ka,
                 target_sigset_t *set, CPUState *env)
{
    struct target_sigframe *frame;
    struct target_sigcontext *sc;
    target_ulong frame_addr, newsp;
    int err = 0;
    int signal;

    frame_addr = get_sigframe(ka, env, sizeof(*frame));
    if (!lock_user_struct(VERIFY_WRITE, frame, frame_addr, 1))
        goto sigsegv;
    sc = &frame->sctx;

    signal = current_exec_domain_sig(sig);

    err |= __put_user(h2g(ka->_sa_handler), &sc->handler);
    err |= __put_user(set->sig[0], &sc->oldmask);
#if defined(TARGET_PPC64)
    err |= __put_user(set->sig[0] >> 32, &sc->_unused[3]);
#else
    err |= __put_user(set->sig[1], &sc->_unused[3]);
#endif
    err |= __put_user(h2g(&frame->mctx), &sc->regs);
    err |= __put_user(sig, &sc->signal);

    /* Save user regs.  */
    err |= save_user_regs(env, &frame->mctx, TARGET_NR_sigreturn);

    /* The kernel checks for the presence of a VDSO here.  We don't
       emulate a vdso, so use a sigreturn system call.  */
    env->lr = (target_ulong) h2g(frame->mctx.tramp);

    /* Turn off all fp exceptions.  */
    env->fpscr = 0;

    /* Create a stack frame for the caller of the handler.  */
    newsp = frame_addr - SIGNAL_FRAMESIZE;
    err |= __put_user(env->gpr[1], (target_ulong *)(uintptr_t) newsp);

    if (err)
        goto sigsegv;

    /* Set up registers for signal handler.  */
    env->gpr[1] = newsp;
    env->gpr[3] = signal;
    env->gpr[4] = (target_ulong) h2g(sc);
    env->nip = (target_ulong) ka->_sa_handler;
    /* Signal handlers are entered in big-endian mode.  */
    env->msr &= ~MSR_LE;

    unlock_user_struct(frame, frame_addr, 1);
    return;

sigsegv:
    unlock_user_struct(frame, frame_addr, 1);
    if (logfile)
        fprintf (logfile, "segfaulting from setup_frame\n");
    force_sig(TARGET_SIGSEGV);
}

void setup_rt_frame(int sig, struct target_sigaction *ka,
                    target_siginfo_t *info,
                    target_sigset_t *set, CPUState *env)
{
    struct target_rt_sigframe *rt_sf;
    struct target_mcontext *frame;
    target_ulong rt_sf_addr, newsp = 0;
    int i, err = 0;
    int signal;

    rt_sf_addr = get_sigframe(ka, env, sizeof(*rt_sf));
    if (!lock_user_struct(VERIFY_WRITE, rt_sf, rt_sf_addr, 1))
        goto sigsegv;

    signal = current_exec_domain_sig(sig);

    err |= copy_siginfo_to_user(&rt_sf->info, info);

    err |= __put_user(0, &rt_sf->uc.tuc_flags);
    err |= __put_user(0, &rt_sf->uc.tuc_link);
    err |= __put_user((target_ulong)target_sigaltstack_used.ss_sp,
                      &rt_sf->uc.tuc_stack.ss_sp);
    err |= __put_user(sas_ss_flags(env->gpr[1]),
                      &rt_sf->uc.tuc_stack.ss_flags);
    err |= __put_user(target_sigaltstack_used.ss_size,
                      &rt_sf->uc.tuc_stack.ss_size);
    err |= __put_user(h2g (&rt_sf->uc.tuc_mcontext),
                      &rt_sf->uc.tuc_regs);
    for(i = 0; i < TARGET_NSIG_WORDS; i++) {
        err |= __put_user(set->sig[i], &rt_sf->uc.tuc_sigmask.sig[i]);
    }

    frame = &rt_sf->uc.tuc_mcontext;
    err |= save_user_regs(env, frame, TARGET_NR_rt_sigreturn);

    /* The kernel checks for the presence of a VDSO here.  We don't
       emulate a vdso, so use a sigreturn system call.  */
    env->lr = (target_ulong) h2g(frame->tramp);

    /* Turn off all fp exceptions.  */
    env->fpscr = 0;

    /* Create a stack frame for the caller of the handler.  */
    newsp = rt_sf_addr - (SIGNAL_FRAMESIZE + 16);
    err |= __put_user(env->gpr[1], (target_ulong *)(uintptr_t) newsp);

    if (err)
        goto sigsegv;

    /* Set up registers for signal handler.  */
    env->gpr[1] = newsp;
    env->gpr[3] = (target_ulong) signal;
    env->gpr[4] = (target_ulong) h2g(&rt_sf->info);
    env->gpr[5] = (target_ulong) h2g(&rt_sf->uc);
    env->gpr[6] = (target_ulong) h2g(rt_sf);
    env->nip = (target_ulong) ka->_sa_handler;
    /* Signal handlers are entered in big-endian mode.  */
    env->msr &= ~MSR_LE;

    unlock_user_struct(rt_sf, rt_sf_addr, 1);
    return;

sigsegv:
    unlock_user_struct(rt_sf, rt_sf_addr, 1);
    if (logfile)
        fprintf (logfile, "segfaulting from setup_rt_frame\n");
    force_sig(TARGET_SIGSEGV);

}

long do_sigreturn(CPUState *env)
{
    struct target_sigcontext *sc = NULL;
    struct target_mcontext *sr = NULL;
    target_ulong sr_addr, sc_addr;
    sigset_t blocked;
    target_sigset_t set;

    sc_addr = env->gpr[1] + SIGNAL_FRAMESIZE;
    if (!lock_user_struct(VERIFY_READ, sc, sc_addr, 1))
        goto sigsegv;

#if defined(TARGET_PPC64)
    set.sig[0] = sc->oldmask + ((long)(sc->_unused[3]) << 32);
#else
    if(__get_user(set.sig[0], &sc->oldmask) ||
       __get_user(set.sig[1], &sc->_unused[3]))
       goto sigsegv;
#endif
    target_to_host_sigset_internal(&blocked, &set);
    sigprocmask(SIG_SETMASK, &blocked, NULL);

    if (__get_user(sr_addr, &sc->regs))
        goto sigsegv;
    if (!lock_user_struct(VERIFY_READ, sr, sr_addr, 1))
        goto sigsegv;
    if (restore_user_regs(env, sr, 1))
        goto sigsegv;

    unlock_user_struct(sr, sr_addr, 1);
    unlock_user_struct(sc, sc_addr, 1);
    return -TARGET_QEMU_ESIGRETURN;

sigsegv:
    unlock_user_struct(sr, sr_addr, 1);
    unlock_user_struct(sc, sc_addr, 1);
    if (logfile)
        fprintf (logfile, "segfaulting from do_sigreturn\n");
    force_sig(TARGET_SIGSEGV);
    return 0;
}

/* See arch/powerpc/kernel/signal_32.c.  */
static int do_setcontext(struct target_ucontext *ucp, CPUState *env, int sig)
{
    struct target_mcontext *mcp;
    target_ulong mcp_addr;
    sigset_t blocked;
    target_sigset_t set;

    if (copy_from_user(&set, h2g(ucp) + offsetof(struct target_ucontext, tuc_sigmask),
                       sizeof (set)))
        return 1;

#if defined(TARGET_PPC64)
    fprintf (stderr, "do_setcontext: not implemented\n");
    return 0;
#else
    if (__get_user(mcp_addr, &ucp->tuc_regs))
        return 1;

    if (!lock_user_struct(VERIFY_READ, mcp, mcp_addr, 1))
        return 1;

    target_to_host_sigset_internal(&blocked, &set);
    sigprocmask(SIG_SETMASK, &blocked, NULL);
    if (restore_user_regs(env, mcp, sig))
        goto sigsegv;

    unlock_user_struct(mcp, mcp_addr, 1);
    return 0;

sigsegv:
    unlock_user_struct(mcp, mcp_addr, 1);
    return 1;
#endif
}

long do_rt_sigreturn(CPUState *env)
{
    struct target_rt_sigframe *rt_sf = NULL;
    target_ulong rt_sf_addr;

    rt_sf_addr = env->gpr[1] + SIGNAL_FRAMESIZE + 16;
    if (!lock_user_struct(VERIFY_READ, rt_sf, rt_sf_addr, 1))
        goto sigsegv;

    if (do_setcontext(&rt_sf->uc, env, 1))
        goto sigsegv;

    do_sigaltstack(rt_sf_addr
                   + offsetof(struct target_rt_sigframe, uc.tuc_stack),
                   0, env->gpr[1]);

    unlock_user_struct(rt_sf, rt_sf_addr, 1);
    return -TARGET_QEMU_ESIGRETURN;

sigsegv:
    unlock_user_struct(rt_sf, rt_sf_addr, 1);
    if (logfile)
        fprintf (logfile, "segfaulting from do_rt_sigreturn\n");
    force_sig(TARGET_SIGSEGV);
    return 0;
}
#endif /* !TARGET_PPC64 */
