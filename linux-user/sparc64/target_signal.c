/*
 *  Emulation of Linux signals : SPARC64 specific code
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

#if !defined(TARGET_ABI32)
#define MC_TSTATE 0
#define MC_PC 1
#define MC_NPC 2
#define MC_Y 3
#define MC_G1 4
#define MC_G2 5
#define MC_G3 6
#define MC_G4 7
#define MC_G5 8
#define MC_G6 9
#define MC_G7 10
#define MC_O0 11
#define MC_O1 12
#define MC_O2 13
#define MC_O3 14
#define MC_O4 15
#define MC_O5 16
#define MC_O6 17
#define MC_O7 18
#define MC_NGREG 19

typedef abi_ulong target_mc_greg_t;
typedef target_mc_greg_t target_mc_gregset_t[MC_NGREG];

struct target_mc_fq {
    abi_ulong *mcfq_addr;
    uint32_t mcfq_insn;
};

struct target_mc_fpu {
    union {
        uint32_t sregs[32];
        uint64_t dregs[32];
        //uint128_t qregs[16];
    } mcfpu_fregs;
    abi_ulong mcfpu_fsr;
    abi_ulong mcfpu_fprs;
    abi_ulong mcfpu_gsr;
    struct target_mc_fq *mcfpu_fq;
    unsigned char mcfpu_qcnt;
    unsigned char mcfpu_qentsz;
    unsigned char mcfpu_enab;
};
typedef struct target_mc_fpu target_mc_fpu_t;

typedef struct {
    target_mc_gregset_t mc_gregs;
    target_mc_greg_t mc_fp;
    target_mc_greg_t mc_i7;
    target_mc_fpu_t mc_fpregs;
} target_mcontext_t;

struct target_ucontext {
    struct target_ucontext *tuc_link;
    abi_ulong tuc_flags;
    target_sigset_t tuc_sigmask;
    target_mcontext_t tuc_mcontext;
};

/* A V9 register window */
struct target_reg_window {
    abi_ulong locals[8];
    abi_ulong ins[8];
};

#define TARGET_STACK_BIAS 2047

/* {set, get}context() needed for 64-bit SparcLinux userland. */
void sparc64_set_context(CPUSPARCState *env)
{
    abi_ulong ucp_addr;
    struct target_ucontext *ucp;
    target_mc_gregset_t *grp;
    abi_ulong pc, npc, tstate;
    abi_ulong fp, i7, w_addr;
    int err;
    unsigned int i;

    ucp_addr = env->regwptr[UREG_I0];
    if (!lock_user_struct(VERIFY_READ, ucp, ucp_addr, 1))
        goto do_sigsegv;
    grp  = &ucp->tuc_mcontext.mc_gregs;
    err  = __get_user(pc, &((*grp)[MC_PC]));
    err |= __get_user(npc, &((*grp)[MC_NPC]));
    if (err || ((pc | npc) & 3))
        goto do_sigsegv;
    if (env->regwptr[UREG_I1]) {
        target_sigset_t target_set;
        sigset_t set;

        if (TARGET_NSIG_WORDS == 1) {
            if (__get_user(target_set.sig[0], &ucp->tuc_sigmask.sig[0]))
                goto do_sigsegv;
        } else {
            abi_ulong *src, *dst;
            src = ucp->tuc_sigmask.sig;
            dst = target_set.sig;
            for (i = 0; i < sizeof(target_sigset_t) / sizeof(abi_ulong);
                 i++, dst++, src++)
                err |= __get_user(*dst, src);
            if (err)
                goto do_sigsegv;
        }
        target_to_host_sigset_internal(&set, &target_set);
        sigprocmask(SIG_SETMASK, &set, NULL);
    }
    env->pc = pc;
    env->npc = npc;
    err |= __get_user(env->y, &((*grp)[MC_Y]));
    err |= __get_user(tstate, &((*grp)[MC_TSTATE]));
    env->asi = (tstate >> 24) & 0xff;
    cpu_put_ccr(env, tstate >> 32);
    cpu_put_cwp64(env, tstate & 0x1f);
    err |= __get_user(env->gregs[1], (&(*grp)[MC_G1]));
    err |= __get_user(env->gregs[2], (&(*grp)[MC_G2]));
    err |= __get_user(env->gregs[3], (&(*grp)[MC_G3]));
    err |= __get_user(env->gregs[4], (&(*grp)[MC_G4]));
    err |= __get_user(env->gregs[5], (&(*grp)[MC_G5]));
    err |= __get_user(env->gregs[6], (&(*grp)[MC_G6]));
    err |= __get_user(env->gregs[7], (&(*grp)[MC_G7]));
    err |= __get_user(env->regwptr[UREG_I0], (&(*grp)[MC_O0]));
    err |= __get_user(env->regwptr[UREG_I1], (&(*grp)[MC_O1]));
    err |= __get_user(env->regwptr[UREG_I2], (&(*grp)[MC_O2]));
    err |= __get_user(env->regwptr[UREG_I3], (&(*grp)[MC_O3]));
    err |= __get_user(env->regwptr[UREG_I4], (&(*grp)[MC_O4]));
    err |= __get_user(env->regwptr[UREG_I5], (&(*grp)[MC_O5]));
    err |= __get_user(env->regwptr[UREG_I6], (&(*grp)[MC_O6]));
    err |= __get_user(env->regwptr[UREG_I7], (&(*grp)[MC_O7]));

    err |= __get_user(fp, &(ucp->tuc_mcontext.mc_fp));
    err |= __get_user(i7, &(ucp->tuc_mcontext.mc_i7));

    w_addr = TARGET_STACK_BIAS+env->regwptr[UREG_I6];
    if (put_user(fp, w_addr + offsetof(struct target_reg_window, ins[6]), 
                 abi_ulong) != 0)
        goto do_sigsegv;
    if (put_user(i7, w_addr + offsetof(struct target_reg_window, ins[7]), 
                 abi_ulong) != 0)
        goto do_sigsegv;
    /* FIXME this does not match how the kernel handles the FPU in
     * its sparc64_set_context implementation. In particular the FPU
     * is only restored if fenab is non-zero in:
     *   __get_user(fenab, &(ucp->tuc_mcontext.mc_fpregs.mcfpu_enab));
     */
    err |= __get_user(env->fprs, &(ucp->tuc_mcontext.mc_fpregs.mcfpu_fprs));
    {
        uint32_t *src = ucp->tuc_mcontext.mc_fpregs.mcfpu_fregs.sregs;
        for (i = 0; i < 64; i++, src++) {
            if (i & 1) {
                err |= __get_user(env->fpr[i/2].l.lower, src);
            } else {
                err |= __get_user(env->fpr[i/2].l.upper, src);
            }
        }
    }
    err |= __get_user(env->fsr,
                      &(ucp->tuc_mcontext.mc_fpregs.mcfpu_fsr));
    err |= __get_user(env->gsr,
                      &(ucp->tuc_mcontext.mc_fpregs.mcfpu_gsr));
    if (err)
        goto do_sigsegv;
    unlock_user_struct(ucp, ucp_addr, 0);
    return;
 do_sigsegv:
    unlock_user_struct(ucp, ucp_addr, 0);
    force_sig(TARGET_SIGSEGV);
}

void sparc64_get_context(CPUSPARCState *env)
{
    abi_ulong ucp_addr;
    struct target_ucontext *ucp;
    target_mc_gregset_t *grp;
    target_mcontext_t *mcp;
    abi_ulong fp, i7, w_addr;
    int err;
    unsigned int i;
    target_sigset_t target_set;
    sigset_t set;

    ucp_addr = env->regwptr[UREG_I0];
    if (!lock_user_struct(VERIFY_WRITE, ucp, ucp_addr, 0))
        goto do_sigsegv;
    
    mcp = &ucp->tuc_mcontext;
    grp = &mcp->mc_gregs;

    /* Skip over the trap instruction, first. */
    env->pc = env->npc;
    env->npc += 4;

    err = 0;

    sigprocmask(0, NULL, &set);
    host_to_target_sigset_internal(&target_set, &set);
    if (TARGET_NSIG_WORDS == 1) {
        err |= __put_user(target_set.sig[0],
                          (abi_ulong *)&ucp->tuc_sigmask);
    } else {
        abi_ulong *src, *dst;
        src = target_set.sig;
        dst = ucp->tuc_sigmask.sig;
        for (i = 0; i < sizeof(target_sigset_t) / sizeof(abi_ulong);
             i++, dst++, src++)
            err |= __put_user(*src, dst);
        if (err)
            goto do_sigsegv;
    }

    /* XXX: tstate must be saved properly */
    //    err |= __put_user(env->tstate, &((*grp)[MC_TSTATE]));
    err |= __put_user(env->pc, &((*grp)[MC_PC]));
    err |= __put_user(env->npc, &((*grp)[MC_NPC]));
    err |= __put_user(env->y, &((*grp)[MC_Y]));
    err |= __put_user(env->gregs[1], &((*grp)[MC_G1]));
    err |= __put_user(env->gregs[2], &((*grp)[MC_G2]));
    err |= __put_user(env->gregs[3], &((*grp)[MC_G3]));
    err |= __put_user(env->gregs[4], &((*grp)[MC_G4]));
    err |= __put_user(env->gregs[5], &((*grp)[MC_G5]));
    err |= __put_user(env->gregs[6], &((*grp)[MC_G6]));
    err |= __put_user(env->gregs[7], &((*grp)[MC_G7]));
    err |= __put_user(env->regwptr[UREG_I0], &((*grp)[MC_O0]));
    err |= __put_user(env->regwptr[UREG_I1], &((*grp)[MC_O1]));
    err |= __put_user(env->regwptr[UREG_I2], &((*grp)[MC_O2]));
    err |= __put_user(env->regwptr[UREG_I3], &((*grp)[MC_O3]));
    err |= __put_user(env->regwptr[UREG_I4], &((*grp)[MC_O4]));
    err |= __put_user(env->regwptr[UREG_I5], &((*grp)[MC_O5]));
    err |= __put_user(env->regwptr[UREG_I6], &((*grp)[MC_O6]));
    err |= __put_user(env->regwptr[UREG_I7], &((*grp)[MC_O7]));

    w_addr = TARGET_STACK_BIAS+env->regwptr[UREG_I6];
    fp = i7 = 0;
    if (get_user(fp, w_addr + offsetof(struct target_reg_window, ins[6]), 
                 abi_ulong) != 0)
        goto do_sigsegv;
    if (get_user(i7, w_addr + offsetof(struct target_reg_window, ins[7]), 
                 abi_ulong) != 0)
        goto do_sigsegv;
    err |= __put_user(fp, &(mcp->mc_fp));
    err |= __put_user(i7, &(mcp->mc_i7));

    {
        uint32_t *dst = ucp->tuc_mcontext.mc_fpregs.mcfpu_fregs.sregs;
        for (i = 0; i < 64; i++, dst++) {
            if (i & 1) {
                err |= __put_user(env->fpr[i/2].l.lower, dst);
            } else {
                err |= __put_user(env->fpr[i/2].l.upper, dst);
            }
        }
    }
    err |= __put_user(env->fsr, &(mcp->mc_fpregs.mcfpu_fsr));
    err |= __put_user(env->gsr, &(mcp->mc_fpregs.mcfpu_gsr));
    err |= __put_user(env->fprs, &(mcp->mc_fpregs.mcfpu_fprs));

    if (err)
        goto do_sigsegv;
    unlock_user_struct(ucp, ucp_addr, 1);
    return;
 do_sigsegv:
    unlock_user_struct(ucp, ucp_addr, 1);
    force_sig(TARGET_SIGSEGV);
}
#endif
