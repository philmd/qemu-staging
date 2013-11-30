/*
 *  AArch64 translation
 *
 *  Copyright (c) 2013 Alexander Graf <agraf@suse.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "cpu.h"
#include "tcg-op.h"
#include "qemu/log.h"
#include "translate.h"
#include "qemu/host-utils.h"

#include "exec/gen-icount.h"

#include "helper.h"
#define GEN_HELPER 1
#include "helper.h"

#define DEBUG_AARCH64_DISAS     // define to enable tracing
#ifdef DEBUG_AARCH64_DISAS
#define TRACE_DECODE(size, opc, opt)    \
    do {                                                                \
        fprintf(stderr, "%s: 0x%08x @ %" HWADDR_PRIx                    \
                " with size:%d, opc:%d, opt:%d\n",                      \
                __func__, insn, s->pc -4, size, opc, opt);              \
    } while (0);
#else
#define TRACE_DECODE(size, opc, opt)    do { /* nothing */ } while (0);
#endif

static TCGv_i64 cpu_X[32];
static TCGv_i64 cpu_pc;
static TCGv_i32 cpu_NF, cpu_ZF, cpu_CF, cpu_VF;

static const char *regnames[] = {
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "lr", "sp"
};

enum a64_shift_type {
    A64_SHIFT_TYPE_LSL = 0,
    A64_SHIFT_TYPE_LSR = 1,
    A64_SHIFT_TYPE_ASR = 2,
    A64_SHIFT_TYPE_ROR = 3
};

/* initialize TCG globals.  */
void a64_translate_init(void)
{
    int i;

    cpu_pc = tcg_global_mem_new_i64(TCG_AREG0,
                                    offsetof(CPUARMState, pc),
                                    "pc");
    for (i = 0; i < 32; i++) {
        cpu_X[i] = tcg_global_mem_new_i64(TCG_AREG0,
                                          offsetof(CPUARMState, xregs[i]),
                                          regnames[i]);
    }

    cpu_NF = tcg_global_mem_new_i32(TCG_AREG0, offsetof(CPUARMState, NF), "NF");
    cpu_ZF = tcg_global_mem_new_i32(TCG_AREG0, offsetof(CPUARMState, ZF), "ZF");
    cpu_CF = tcg_global_mem_new_i32(TCG_AREG0, offsetof(CPUARMState, CF), "CF");
    cpu_VF = tcg_global_mem_new_i32(TCG_AREG0, offsetof(CPUARMState, VF), "VF");
}

void aarch64_cpu_dump_state(CPUState *cs, FILE *f,
                            fprintf_function cpu_fprintf, int flags)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    uint32_t psr = pstate_read(env);
    int i;

    cpu_fprintf(f, "PC=%016"PRIx64"  SP=%016"PRIx64"\n",
            env->pc, env->xregs[31]);
    for (i = 0; i < 31; i++) {
        cpu_fprintf(f, "X%02d=%016"PRIx64, i, env->xregs[i]);
        if ((i % 4) == 3) {
            cpu_fprintf(f, "\n");
        } else {
            cpu_fprintf(f, " ");
        }
    }
    cpu_fprintf(f, "PSTATE=%08x (flags %c%c%c%c)\n",
                psr,
                psr & PSTATE_N ? 'N' : '-',
                psr & PSTATE_Z ? 'Z' : '-',
                psr & PSTATE_C ? 'C' : '-',
                psr & PSTATE_V ? 'V' : '-');
    cpu_fprintf(f, "\n");
}

void gen_a64_set_pc_im(uint64_t val)
{
    tcg_gen_movi_i64(cpu_pc, val);
}

static void gen_exception(int excp)
{
    TCGv_i32 tmp = tcg_temp_new_i32();
    tcg_gen_movi_i32(tmp, excp);
    gen_helper_exception(cpu_env, tmp);
    tcg_temp_free_i32(tmp);
}

static void gen_exception_insn(DisasContext *s, int offset, int excp)
{
    gen_a64_set_pc_im(s->pc - offset);
    gen_exception(excp);
    s->is_jmp = DISAS_JUMP;
}

static void unallocated_encoding(DisasContext *s)
{
    gen_exception_insn(s, 4, EXCP_UDEF);
}

#define unsupported_encoding(s, insn)                                     \
    do {                                                                  \
        qemu_log_mask(LOG_UNIMP,                                          \
                      "%s:%d: unsupported instruction encoding 0x%08x at pc=%lx\n", \
                      __FILE__, __LINE__, insn, s->pc - 4);               \
        unallocated_encoding(s);                                          \
    } while (0);

static void free_tmp_a64(DisasContext *s)
{
    int i;
    for (i = 0; i < s->tmp_a64_count; i++) {
        tcg_temp_free_i64(s->tmp_a64[i]);
    }
    s->tmp_a64_count = 0;
}

static TCGv_i64 new_tmp_a64_zero(DisasContext *s)
{
    assert(s->tmp_a64_count < TMP_A64_MAX);
    return s->tmp_a64[s->tmp_a64_count++] = tcg_const_i64(0);
}

/* for accessing a register in 64 bit mode (r/w) */
static TCGv_i64 cpu_reg(DisasContext *s, int reg)
{
    if (reg == 31) {
        return new_tmp_a64_zero(s);
    } else {
        return cpu_X[reg];
    }
}

/* register access for when 31 == SP */
static TCGv_i64 cpu_reg_sp(DisasContext *s, int reg)
{
    return cpu_X[reg];
}

/* read a cpu register in 32bit/64bit mode to dst */
static void read_cpu_reg(DisasContext *s, TCGv_i64 dst, int reg, int sf)
{
    if (reg == 31) {
        tcg_gen_movi_i64(dst, 0);
    } else if (sf) {
        tcg_gen_mov_i64(dst, cpu_X[reg]);
    } else { /* (!sf) */
        tcg_gen_ext32u_i64(dst, cpu_X[reg]);
    }
}

static inline bool use_goto_tb(DisasContext *s, int n, uint64_t dest)
{
    /* No direct tb linking with singlestep or deterministic io */
    if (s->singlestep_enabled || (s->tb->cflags & CF_LAST_IO)) {
        return false;
    }

    /* Only link tbs from inside the same guest page */
    if ((s->tb->pc & TARGET_PAGE_MASK) != (dest & TARGET_PAGE_MASK)) {
        return false;
    }

    return true;
}

static inline void gen_goto_tb(DisasContext *s, int n, uint64_t dest)
{
    TranslationBlock *tb;

    tb = s->tb;
    if (use_goto_tb(s, n, dest)) {
        tcg_gen_goto_tb(n);
        gen_a64_set_pc_im(dest);
        tcg_gen_exit_tb((tcg_target_long)tb + n);
        s->is_jmp = DISAS_TB_JUMP;
    } else {
        gen_a64_set_pc_im(dest);
        tcg_gen_exit_tb(0);
        s->is_jmp = DISAS_JUMP;
    }
}

/* C4.3.10 NZCV, Condition Flags
   this matches the ARM target semantic for flag variables,
   but it's not optimal for Aarch64. */
/* on !sf result must be passed clean (zero-ext) */
static inline void gen_logic_CC(int sf, TCGv_i64 result)
{
    if (sf) {
        TCGv_i64 flag = tcg_temp_new_i64();
        tcg_gen_setcondi_i64(TCG_COND_NE, flag, result, 0);
        tcg_gen_trunc_i64_i32(cpu_ZF, flag);

        tcg_gen_shri_i64(flag, result, 32);
        tcg_gen_trunc_i64_i32(cpu_NF, flag);
        tcg_temp_free_i64(flag);
    } else {
        tcg_gen_trunc_i64_i32(cpu_ZF, result);
        tcg_gen_trunc_i64_i32(cpu_NF, result);
    }
    tcg_gen_movi_i32(cpu_CF, 0);
    tcg_gen_movi_i32(cpu_VF, 0);
}

static void gen_arith_CC_64(TCGv_i64 result,
                            TCGv_i64 x, TCGv_i64 y, TCGv_i64 carry_in)
{
    TCGv_i64 tmp, carry_out;
    tmp = tcg_const_i64(0);
    carry_out = tcg_temp_new_i64();

    /* calculate [C:result] = x + y + carry_in */
    tcg_gen_add2_i64(result, carry_out, x, tmp, carry_in, tmp);
    tcg_gen_add2_i64(result, carry_out, result, carry_out, y, tmp);
    tcg_gen_trunc_i64_i32(cpu_CF, carry_out);

    /* calculate NZ */
    tcg_gen_setcondi_i64(TCG_COND_NE, tmp, result, 0);
    tcg_gen_trunc_i64_i32(cpu_ZF, tmp);
    tcg_gen_shri_i64(tmp, result, 32);
    tcg_gen_trunc_i64_i32(cpu_NF, tmp);

    /* calculate V */
    tcg_gen_xor_i64(carry_out, result, x);
    tcg_gen_xor_i64(tmp, x, y);
    tcg_gen_andc_i64(carry_out, carry_out, tmp);
    tcg_gen_shri_i64(carry_out, carry_out, 32);
    tcg_gen_trunc_i64_i32(cpu_VF, carry_out);

    tcg_temp_free_i64(carry_out);
    tcg_temp_free_i64(tmp);
}

static void gen_arith_CC_32(TCGv_i32 result,
                            TCGv_i32 x, TCGv_i32 y, TCGv_i32 carry_in)
{
    TCGv_i32 tmp, carry_out;
    tmp = tcg_const_i32(0);
    carry_out = tcg_temp_new_i32();

    /* calculate [C:result] = x + y + carry_in */
    tcg_gen_add2_i32(result, carry_out, x, tmp, carry_in, tmp);
    tcg_gen_add2_i32(result, carry_out, result, carry_out, y, tmp);
    tcg_gen_mov_i32(cpu_CF, carry_out);

    /* calculate NZ */
    tcg_gen_mov_i32(cpu_ZF, result);
    tcg_gen_mov_i32(cpu_NF, result);

    /* calculate V */
    tcg_gen_xor_i32(carry_out, result, x);
    tcg_gen_xor_i32(tmp, x, y);
    tcg_gen_andc_i32(cpu_VF, carry_out, tmp);

    tcg_temp_free_i32(carry_out);
    tcg_temp_free_i32(tmp);
}

/* see AddWithCarry, "G.3 Common library pseudocode" */
static void gen_arith_CC(int sf, TCGv_i64 result,
                         TCGv_i64 x, TCGv_i64 y, TCGv_i64 carry_in)
{
    if (sf) {
        gen_arith_CC_64(result, x, y, carry_in);
    } else {
        TCGv_i32 result32, x32, y32, carry_in32;
        result32 = tcg_temp_new_i32();
        x32 = tcg_temp_new_i32();
        y32 = tcg_temp_new_i32();
        carry_in32 = tcg_temp_new_i32();
        tcg_gen_trunc_i64_i32(result32, result);
        tcg_gen_trunc_i64_i32(x32, x);
        tcg_gen_trunc_i64_i32(y32, y);
        tcg_gen_trunc_i64_i32(carry_in32, carry_in);

        gen_arith_CC_32(result32, x32, y32, carry_in32);
        tcg_gen_extu_i32_i64(result, result32);

        tcg_temp_free_i32(result32);
        tcg_temp_free_i32(x32);
        tcg_temp_free_i32(y32);
        tcg_temp_free_i32(carry_in32);
    }
}

enum sysreg_access {
    SYSTEM_GET,
    SYSTEM_PUT
};

/* C4.3.10 - NZVC */
static int get_nzcv(TCGv_i64 tcg_rt)
{
    TCGv_i32 nzcv, tmp;
    tmp = tcg_temp_new_i32();
    nzcv = tcg_temp_new_i32();

    /* build bit 31, N */
    tcg_gen_andi_i32(nzcv, cpu_NF, (1 << 31));
    /* build bit 30, Z */
    tcg_gen_setcondi_i32(TCG_COND_EQ, tmp, cpu_ZF, 0);
    tcg_gen_deposit_i32(nzcv, nzcv, tmp, 30, 1);
    /* build bit 29, C */
    tcg_gen_deposit_i32(nzcv, nzcv, cpu_CF, 29, 1);
    /* build bit 28, V */
    tcg_gen_shri_i32(tmp, cpu_VF, 31);
    tcg_gen_deposit_i32(nzcv, nzcv, tmp, 28, 1);
    /* generate result */
    tcg_gen_extu_i32_i64(tcg_rt, nzcv);

    tcg_temp_free_i32(nzcv);
    tcg_temp_free_i32(tmp);
    return 0;
}

static int put_nzcv(TCGv_i64 tcg_rt)
{
    TCGv_i32 nzcv;
    nzcv = tcg_temp_new_i32();

    /* take NZCV from R[t] */
    tcg_gen_trunc_i64_i32(nzcv, tcg_rt);

    /* bit 31, N */
    tcg_gen_andi_i32(cpu_NF, nzcv, (1 << 31));
    /* bit 30, Z */
    tcg_gen_andi_i32(cpu_ZF, nzcv, (1 << 30));
    tcg_gen_setcondi_i32(TCG_COND_EQ, cpu_ZF, cpu_ZF, 0);
    /* bit 29, C */
    tcg_gen_andi_i32(cpu_CF, nzcv, (1 << 29));
    tcg_gen_shri_i32(cpu_CF, cpu_CF, 29);
    /* bit 28, V */
    tcg_gen_andi_i32(cpu_VF, nzcv, (1 << 28));
    tcg_gen_shli_i32(cpu_VF, cpu_VF, 3); /* shift to position 31 */

    tcg_temp_free_i32(nzcv);
    return 0;
}

/* CTR_EL0 (D8.2.21) */
static int get_ctr_el0(TCGv_i64 tcg_rt)
{
    tcg_gen_movi_i64(tcg_rt, 0x80030003);
    return 0;
}

/* DCZID_EL0 (D8.2.23) */
static int get_dczid_el0(TCGv_i64 tcg_rt)
{
    tcg_gen_movi_i64(tcg_rt, 0x10);
    return 0;
}

/* TPIDR_EL0 (D8.2.87) */
static int get_tpidr_el0(TCGv_i64 tcg_rt)
{
    tcg_gen_ld_i64(tcg_rt, cpu_env,
                   offsetof(CPUARMState, sr.tpidr_el0));
    return 0;
}

static int put_tpidr_el0(TCGv_i64 tcg_rt)
{
    tcg_gen_st_i64(tcg_rt, cpu_env,
                   offsetof(CPUARMState, sr.tpidr_el0));
    return 0;
}


/* manual: System_Get() / System_Put() */
/* returns 0 on success, 1 on unsupported, 2 on unallocated */
static int sysreg_access(enum sysreg_access access, DisasContext *s,
                         unsigned int op0, unsigned int op1, unsigned int op2,
                         unsigned int crn, unsigned int crm, unsigned int rt)
{
    if (op0 != 3) {
        return 1; /* we only support non-debug system registers for now */
    }

    if (crn == 4) {
        /* Table C4-8 Special-purpose register accesses */
        if (op1 == 3 && crm == 2 && op2 == 0) {
            /* NZVC C4.3.10 */
            return access == SYSTEM_GET ?
                get_nzcv(cpu_reg(s, rt)) : put_nzcv(cpu_reg(s, rt));
        }
    } else if (crn == 11 || crn == 15) {
        /* C4.2.7 Reserved control space for IMPLEM.-DEFINED func. */
        return 2;
    } else {
        /* Table C4-7 System insn encodings for System register access */
        if (crn == 0 && op1 == 3 && crm == 0 && op2 == 1) {
            /* CTR_EL0 (D8.2.21) */
            return access == SYSTEM_GET ? get_ctr_el0(cpu_reg(s, rt)) : 2;
        } else if (crn == 0 && op1 == 3 && crm == 0 && op2 == 7) {
            /* DCZID_EL0 (D8.2.23) */
            return access == SYSTEM_GET ? get_dczid_el0(cpu_reg(s, rt)) : 2;
        } else if (crn == 13 && op1 == 3 && crm == 0 && op2 == 2) {
            return access == SYSTEM_GET ?
                get_tpidr_el0(cpu_reg(s, rt)) : put_tpidr_el0(cpu_reg(s, rt));
        }
    }

    return 1; /* unsupported */
}

/*
 * the instruction disassembly implemented here matches
 * the instruction encoding classifications in chapter 3 (C3)
 * of the ARM Architecture Reference Manual (DDI0487A_a)
 */

/* Unconditional branch (immediate) */
static void disas_uncond_b_imm(DisasContext *s, uint32_t insn)
{
    uint64_t addr = s->pc + sextract32(insn, 0, 26) * 4 - 4;

    if (insn & (1 << 31)) {
        /* C5.6.26 BL Branch with link */
        tcg_gen_movi_i64(cpu_reg(s, 30), s->pc);
    }

    /* C5.6.20 B Branch / C5.6.26 BL Branch with link */
    gen_goto_tb(s, 0, addr);
}

/* C3.2.1 Compare & branch (immediate) */
static void disas_comp_b_imm(DisasContext *s, uint32_t insn)
{
    /*
     * 31 30 29 28 27 26 25 24 23     5 4  0
     * sf  0  1  1  0  1  0 op   imm19   Rt
     */
    unsigned int sf, op, rt;
    uint64_t addr;
    int label_nomatch;
    TCGv_i64 tcg_cmp;
    sf = insn & (1 << 31) ? 1 : 0;
    op = insn & (1 << 24) ? 1 : 0;
    rt = extract32(insn, 0, 5);
    addr = s->pc + sextract32(insn, 5, 19) * 4 - 4;

    tcg_cmp = tcg_temp_new_i64();
    read_cpu_reg(s, tcg_cmp, rt, sf);
    label_nomatch = gen_new_label();

    if (op) { /* CBNZ */
        tcg_gen_brcondi_i64(TCG_COND_EQ, tcg_cmp, 0, label_nomatch);
    } else { /* CBZ */
        tcg_gen_brcondi_i64(TCG_COND_NE, tcg_cmp, 0, label_nomatch);
    }

    tcg_temp_free_i64(tcg_cmp);

    gen_goto_tb(s, 0, addr);
    gen_set_label(label_nomatch);
    gen_goto_tb(s, 1, s->pc);
}

/* C3.2.5 Test & branch (immediate) */
static void disas_test_b_imm(DisasContext *s, uint32_t insn)
{
    /* C5.6.207 TBZ, C5.6.206 TBNZ
     * 31 30 29 28 27 26 25 24 23   19 18     5 4  0
     * b5  0  1  1  0  1  1 op   b40     imm14   Rt
     */
    unsigned int bit_pos, op, rt;
    uint64_t addr;
    int label_nomatch;
    TCGv_i64 tcg_cmp;
    bit_pos = (insn & (1 << 31)) >> 26 | extract32(insn, 19, 5);
    op = extract32(insn, 24, 1);
    addr = s->pc + sextract32(insn, 5, 14) * 4 - 4;
    rt = extract32(insn, 0, 5);

    tcg_cmp = tcg_temp_new_i64();
    tcg_gen_andi_i64(tcg_cmp, cpu_reg(s, rt), (1ULL << bit_pos));
    label_nomatch = gen_new_label();
    if (op) { /* TBNZ */
        tcg_gen_brcondi_i64(TCG_COND_EQ, tcg_cmp, 0, label_nomatch);
    } else { /* TBZ */
        tcg_gen_brcondi_i64(TCG_COND_NE, tcg_cmp, 0, label_nomatch);
    }
    tcg_temp_free_i64(tcg_cmp);
    gen_goto_tb(s, 0, addr);
    gen_set_label(label_nomatch);
    gen_goto_tb(s, 1, s->pc);
}

/* C3.2.2 / C5.6.19 Conditional branch (immediate) */
static void disas_cond_b_imm(DisasContext *s, uint32_t insn)
{
    /*
     * 31 30 29 28 27 26 25 |24| 23    5| 4|  3    0
     *  0  1  0  1  0  1  0 | 0|  imm19 | 0|   cond
     *                      |o1|        |o0|
     */
    unsigned int cond; uint64_t addr;
    if ((insn & (1 << 4)) || (insn & (1 << 24))) {
        unallocated_encoding(s);
        return;
    }
    addr = s->pc + sextract32(insn, 5, 19) * 4 - 4;
    cond = extract32(insn, 0, 4);

    if (cond < 0x0e) { /* only if condition is not "always" */
        int label_nomatch = gen_new_label();
        arm_gen_test_cc(cond ^ 1, label_nomatch);
        gen_goto_tb(s, 0, addr);
        gen_set_label(label_nomatch);
        gen_goto_tb(s, 1, s->pc);
    } else { /* generate unconditional branch */
        gen_goto_tb(s, 0, addr);
    }
}

/* C5.6.68 HINT */
static void handle_hint(DisasContext *s, uint32_t insn,
                        unsigned int op1, unsigned int op2, unsigned int crm)
{
    unsigned int selector = crm << 3 | op2;

    if (op1 != 3) {
        unallocated_encoding(s);
        return;
    }

    switch (selector) {
    case 0: /* NOP */
        return;
    case 1: /* YIELD */
    case 2: /* WFE */
    case 3: /* WFI */
    case 4: /* SEV */
    case 5: /* SEVL */
        /* we treat all as NOP at least for now */
        return;
    default:
        /* default specified as NOP equivalent */
        return;
    }
}

/* CLREX, DSB, DMB, ISB */
static void handle_sync(DisasContext *s, uint32_t insn,
                        unsigned int op1, unsigned int op2, unsigned int crm)
{
    if (op1 != 3) {
        unallocated_encoding(s);
        return;
    }

    switch (op2) {
    case 2: /* CLREX */
        unsupported_encoding(s, insn);
        return;
    case 4: /* DSB */
    case 5: /* DMB */
    case 6: /* ISB */
        /* We don't emulate caches so barriers are no-ops */
        return;
    default:
        unallocated_encoding(s);
        return;
    }
}

/* C5.6.130 MSR (immediate) - move immediate to processor state field */
static void handle_msr_i(DisasContext *s, uint32_t insn,
                         unsigned int op1, unsigned int op2, unsigned int crm)
{
    unsupported_encoding(s, insn);
}

/* C5.6.204 SYS */
static void handle_sys(DisasContext *s, uint32_t insn, unsigned int l,
                       unsigned int op1, unsigned int op2,
                       unsigned int crn, unsigned int crm, unsigned int rt)
{
    unsupported_encoding(s, insn);
}

/* C5.6.129 MRS - move from system register */
static void handle_mrs(DisasContext *s, uint32_t insn, unsigned int op0,
                       unsigned int op1, unsigned int op2,
                       unsigned int crn, unsigned int crm, unsigned int rt)
{
    int rv = sysreg_access(SYSTEM_GET, s, op0, op1, op2, crn, crm, rt);

    switch (rv) {
    case 0:
        return;
    case 1: /* unsupported */
        unsupported_encoding(s, insn);
        break;
    case 2: /* unallocated */
        unallocated_encoding(s);
        break;
    default:
        assert(FALSE);
    }

    qemu_log("MRS: [op0=%d,op1=%d,op2=%d,crn=%d,crm=%d]\n",
             op0, op1, op2, crn, crm);
}

/* C5.6.131 MSR (register) - move to system register */
static void handle_msr(DisasContext *s, uint32_t insn, unsigned int op0,
                       unsigned int op1, unsigned int op2,
                       unsigned int crn, unsigned int crm, unsigned int rt)
{
    int rv = sysreg_access(SYSTEM_PUT, s, op0, op1, op2, crn, crm, rt);

    switch (rv) {
    case 0:
        return;
    case 1: /* unsupported */
        unsupported_encoding(s, insn);
        break;
    case 2: /* unallocated */
        unallocated_encoding(s);
        break;
    default:
        assert(FALSE);
    }

    qemu_log("MSR: [op0=%d,op1=%d,op2=%d,crn=%d,crm=%d]\n",
             op0, op1, op2, crn, crm);
}

/* C3.2.4 System */
static void disas_system(DisasContext *s, uint32_t insn)
{
    /*
     * 31 30 29 28 27 26 25 24 23 22 21 20 19 18   16 15   12 11   8 7   5 4  0
     *  1  1  0  1  0  1  0  1  0  0  L  op0    op1     CRn     CRm   op2   Rt
     */
    unsigned int l, op0, op1, crn, crm, op2, rt;
    l = extract32(insn, 21, 1);
    op0 = extract32(insn, 19, 2);
    op1 = extract32(insn, 16, 3);
    crn = extract32(insn, 12, 4);
    crm = extract32(insn, 8, 4);
    op2 = extract32(insn, 5, 3);
    rt = extract32(insn, 0, 5);

    if (op0 == 0) {
        if (l || rt != 31) {
            unallocated_encoding(s);
            return;
        }
        switch (crn) {
        case 2: /* C5.6.68 HINT */
            handle_hint(s, insn, op1, op2, crm);
            break;
        case 3: /* CLREX, DSB, DMB, ISB */
            handle_sync(s, insn, op1, op2, crm);
            break;
        case 4: /* C5.6.130 MSR (immediate) */
            handle_msr_i(s, insn, op1, op2, crm);
            break;
        default:
            unallocated_encoding(s);
            break;
        }
        return;
    }

    if (op0 == 1) {
        /* C5.6.204 SYS */
        handle_sys(s, insn, l, op1, op2, crn, crm, rt);
    } else if (l) { /* op0 > 1 */
        /* C5.6.129 MRS - move from system register */
        handle_mrs(s, insn, op0, op1, op2, crn, crm, rt);
    } else {
        /* C5.6.131 MSR (register) - move to system register */
        handle_msr(s, insn, op0, op1, op2, crn, crm, rt);
    }
}

/* Exception generation */
static void disas_exc(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Unconditional branch (register) */
static void disas_uncond_b_reg(DisasContext *s, uint32_t insn)
{
    /*
     * 31 30 29 28 27 26 25 24   21 20   16 15   10 9  5 4   0
     *  1  1  0  1  0  1  1   opc     op2     op3    Rn   op4
     */
    unsigned int opc, op2, op3, rn, op4;

    opc = extract32(insn, 21, 4);
    op2 = extract32(insn, 16, 5);
    op3 = extract32(insn, 10, 6);
    rn = extract32(insn, 5, 5);
    op4 = extract32(insn, 0, 5);

    if (op4 != 0x0 || op3 != 0x0 || op2 != 0x1f) {
        unallocated_encoding(s);
        return;
    }

    switch (opc) {
    case 0: /* BR */
    case 2: /* RET */
        break;
    case 1: /* BLR */
        tcg_gen_movi_i64(cpu_reg(s, 30), s->pc);
        break;
    case 4: /* ERET */
    case 5: /* DRPS */
        if (rn != 0x1f) {
            unallocated_encoding(s);
        } else {
            unsupported_encoding(s, insn);
        }
        return;
    default:
        unallocated_encoding(s);
        return;
    }

    tcg_gen_mov_i64(cpu_pc, cpu_reg(s, rn));
    s->is_jmp = DISAS_JUMP;
}

/* C3.2 Branches, exception generating and system instructions */
static void disas_b_exc_sys(DisasContext *s, uint32_t insn)
{
    switch (extract32(insn, 25, 7)) {
    case 0x0a: case 0x0b:
    case 0x4a: case 0x4b: /* Unconditional branch (immediate) */
        disas_uncond_b_imm(s, insn);
        break;
    case 0x1a: case 0x5a: /* Compare & branch (immediate) */
        disas_comp_b_imm(s, insn);
        break;
    case 0x1b: case 0x5b: /* Test & branch (immediate) */
        disas_test_b_imm(s, insn);
        break;
    case 0x2a: /* Conditional branch (immediate) */
        disas_cond_b_imm(s, insn);
        break;
    case 0x6a: /* Exception generation / System */
        if (insn & (1 << 24)) {
            disas_system(s, insn);
        } else {
            disas_exc(s, insn);
        }
        break;
    case 0x6b: /* Unconditional branch (register) */
        disas_uncond_b_reg(s, insn);
        break;
    default:
        unallocated_encoding(s);
        break;
    }
}

/* Load/store exclusive */
static void disas_ldst_excl(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Load register (literal) */
static void disas_ld_lit(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Load/store pair (all forms) */
static void disas_ldst_pair(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Load/store register (all forms) */
static void disas_ldst_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* AdvSIMD load/store multiple structures */
static void disas_ldst_multiple_struct(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* AdvSIMD load/store single structure */
static void disas_ldst_single_struct(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C3.3 Loads and stores */
static void disas_ldst(DisasContext *s, uint32_t insn)
{
    switch (extract32(insn, 24, 6)) {
    case 0x08: /* Load/store exclusive */
        disas_ldst_excl(s, insn);
        break;
    case 0x18: case 0x1c: /* Load register (literal) */
        disas_ld_lit(s, insn);
        break;
    case 0x28: case 0x29:
    case 0x2c: case 0x2d: /* Load/store pair (all forms) */
        disas_ldst_pair(s, insn);
        break;
    case 0x38: case 0x39:
    case 0x3c: case 0x3d: /* Load/store register (all forms) */
        disas_ldst_reg(s, insn);
        break;
    case 0x0c: /* AdvSIMD load/store multiple structures */
        disas_ldst_multiple_struct(s, insn);
        break;
    case 0x0d: /* AdvSIMD load/store single structure */
        disas_ldst_single_struct(s, insn);
        break;
    default:
        unallocated_encoding(s);
        break;
    }
}

/* C3.4.6 PC-rel. addressing */

static void disas_pc_rel_adr(DisasContext *s, uint32_t insn)
{
    /*
     * 31 30 29 28 27 26 25 24 23     5 4  0
     * op immlo  1  0  0  0  0   immhi   Rd
     */
    unsigned int page, rd; /* op -> page */
    uint64_t base;
    int64_t offset; /* SignExtend(immhi:immlo) -> offset */

    page = insn & (1 << 31) ? 1 : 0;
    offset = sextract32(insn, 5, 19) << 2 | extract32(insn, 29, 2);
    rd = extract32(insn, 0, 5);
    base = s->pc - 4;

    if (page) {
        /* ADRP (page based) */
        base &= ~0xfff;
        offset <<= 12; /* apply Zeros */
    }

    tcg_gen_movi_i64(cpu_reg(s, rd), base + offset);
}

/* Add/subtract (immediate) */
static void disas_add_sub_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

static uint64_t logic_imm_replicate(uint64_t mask, unsigned int esize)
{
    int i;
    uint64_t out_mask = 0;
    for (i = 0; (i * esize) < 64; i++) {
        out_mask = out_mask | (mask << (i * esize));
    }
    return out_mask;
}

static inline uint64_t logic_imm_bitmask(unsigned int len)
{
    if (len == 64) {
        return -1;
    }
    return (1ULL << len) - 1;
}

static uint64_t logic_imm_decode_wmask(unsigned int immn,
                                       unsigned int imms, unsigned int immr)
{
    uint64_t mask;
    unsigned len, esize, levels, s, r;

    len = 31 - clz32((immn << 6) | (~imms & 0x3f));
    esize = 1 << len;
    levels = (esize - 1) & 0x3f;
    s = imms & levels;
    r = immr & levels;

    mask = logic_imm_bitmask(s + 1);
    mask = (mask >> r) | (mask << (esize - r));
    mask &= logic_imm_bitmask(esize);
    mask = logic_imm_replicate(mask, esize);
    return mask;
}

/* C3.4.4 Logical (immediate) */
static void disas_logic_imm(DisasContext *s, uint32_t insn)
{
    /*
     * 31 30 29 28 27 26 25 24 23 22 21    16 15    10 9  5 4  0
     * sf  opc   1  0  0  1  0  0  N   immr     imms    Rn   Rd
     */
    unsigned int sf, opc, is_n, immr, imms, rn, rd;
    TCGv_i64 tcg_rd, tcg_rn;
    uint64_t wmask;
    sf = insn & (1 << 31) ? 1 : 0;
    opc = extract32(insn, 29, 2);
    is_n = insn & (1 << 22) ? 1 : 0;
    immr = extract32(insn, 16, 6);
    imms = extract32(insn, 10, 6);
    rn = extract32(insn, 5, 5);
    rd = extract32(insn, 0, 5);

    if (!sf && is_n) {
        unallocated_encoding(s);
        return;
    }

    if (opc == 0x3) { /* ANDS */
        tcg_rd = cpu_reg(s, rd);
    } else {
        tcg_rd = cpu_reg_sp(s, rd);
    }
    tcg_rn = cpu_reg(s, rn);

    wmask = logic_imm_decode_wmask(is_n, imms, immr);
    if (!sf) {
        wmask &= 0xffffffff;
    }

    switch (opc) {
    case 0x3: /* ANDS */
    case 0x0: /* AND */
        tcg_gen_andi_i64(tcg_rd, tcg_rn, wmask);
        break;
    case 0x1: /* ORR */
        tcg_gen_ori_i64(tcg_rd, tcg_rn, wmask);
        break;
    case 0x2: /* EOR */
        tcg_gen_xori_i64(tcg_rd, tcg_rn, wmask);
        break;
    default:
        assert(FALSE); /* must handle all above */
        break;
    }

    if (!sf) { /* zero extend final result */
        tcg_gen_ext32u_i64(tcg_rd, tcg_rd);
    }

    if (opc == 3) { /* ANDS */
        gen_logic_CC(sf, tcg_rd);
    }
}

/* Move wide (immediate) */
static void disas_movw_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C3.4.2 Bitfield */
static void disas_bitfield(DisasContext *s, uint32_t insn)
{
    /*
     * 31 30 29 28 27 26 25 24 23 22 21    16 15    10 9  5 4  0
     * sf  opc   1  0  0  1  1  0  N   immr     imms    Rn   Rd
     */
    unsigned int sf, n, opc, ri, si, rn, rd, bitsize, pos, len;
    TCGv_i64 tcg_rd, tcg_tmp;
    sf = insn & (1 << 31) ? 1 : 0;
    opc = extract32(insn, 29, 2);
    n = insn & (1 << 22) ? 1 : 0;
    ri = extract32(insn, 16, 6);
    si = extract32(insn, 10, 6);
    rn = extract32(insn, 5, 5);
    rd = extract32(insn, 0, 5);
    bitsize = sf ? 64 : 32;

    if (sf != n || ri >= bitsize || si >= bitsize || opc > 2) {
        unallocated_encoding(s);
        return;
    }

    tcg_rd = cpu_reg(s, rd);
    tcg_tmp = tcg_temp_new_i64();
    read_cpu_reg(s, tcg_tmp, rn, sf);

    if (opc != 1) { /* SBFM or UBFM */
        tcg_gen_movi_i64(tcg_rd, 0);
    }

    /* do the bit move operation */
    if (si >= ri) {
        /* Wd<s-r:0> = Wn<s:r> */
        tcg_gen_shri_i64(tcg_tmp, tcg_tmp, ri);
        pos = 0;
        len = (si - ri) + 1;
    } else {
        /* Wd<32+s-r,32-r> = Wn<s:0> */
        pos = bitsize - ri;
        len = si + 1;
    }

    tcg_gen_deposit_i64(tcg_rd, tcg_rd, tcg_tmp, pos, len);
    tcg_temp_free_i64(tcg_tmp);

    if (opc == 0) { /* SBFM - sign extend the destination field */
        tcg_gen_shli_i64(tcg_rd, tcg_rd, 64 - (pos + len));
        tcg_gen_sari_i64(tcg_rd, tcg_rd, 64 - (pos + len));
    }

    if (!sf) { /* zero extend final result */
        tcg_gen_ext32u_i64(tcg_rd, tcg_rd);
    }
}

/* C3.4.3 Extract */
static void disas_extract(DisasContext *s, uint32_t insn)
{
    /*
     * 31 30 29 28 27 26 25 24 23 22 21 20  16 15   10 9  5 4  0
     * sf [op21] 1  0  0  1  1  1  N o0   Rm     imm    Rn   Rd
     *    [0  0]                     [0]
     */
    unsigned int sf, n, rm, imm, rn, rd, bitsize;
    sf = insn & (1 << 31) ? 1 : 0;
    n = insn & (1 << 22) ? 1 : 0;
    rm = extract32(insn, 16, 5);
    imm = extract32(insn, 10, 6);
    rn = extract32(insn, 5, 5);
    rd = extract32(insn, 0, 5);
    bitsize = sf ? 64 : 32;

    if (sf != n || (insn & (0x3 << 29)) || (insn & (1 << 21))
        || imm >= bitsize)
    {
        unallocated_encoding(s);
    } else {
        TCGv_i64 tcg_tmp, tcg_rd;
        tcg_tmp = tcg_temp_new_i64();
        tcg_rd = cpu_reg(s, rd);

        read_cpu_reg(s, tcg_tmp, rm, sf);
        tcg_gen_shri_i64(tcg_rd, tcg_tmp, imm);
        tcg_gen_shli_i64(tcg_tmp, cpu_reg(s, rn), bitsize - imm);
        tcg_gen_or_i64(tcg_rd, tcg_rd, tcg_tmp);

        tcg_temp_free_i64(tcg_tmp);
        if (!sf) {
            tcg_gen_ext32u_i64(tcg_rd, tcg_rd);
        }
    }
}

/* C3.4 Data processing - immediate */
static void disas_data_proc_imm(DisasContext *s, uint32_t insn)
{
    switch (extract32(insn, 23, 6)) {
    case 0x20: case 0x21: /* PC-rel. addressing */
        disas_pc_rel_adr(s, insn);
        break;
    case 0x22: case 0x23: /* Add/subtract (immediate) */
        disas_add_sub_imm(s, insn);
        break;
    case 0x24: /* Logical (immediate) */
        disas_logic_imm(s, insn);
        break;
    case 0x25: /* Move wide (immediate) */
        disas_movw_imm(s, insn);
        break;
    case 0x26: /* Bitfield */
        disas_bitfield(s, insn);
        break;
    case 0x27: /* Extract */
        disas_extract(s, insn);
        break;
    default:
        unallocated_encoding(s);
        break;
    }
}

/* shift a TCGv src by TCGv shift_amount, put result in dst. */
static void shift_reg(TCGv_i64 dst, TCGv_i64 src, int sf,
                      enum a64_shift_type shift_type, TCGv_i64 shift_amount)
{
    switch (shift_type) {
    case A64_SHIFT_TYPE_LSL:
        tcg_gen_shl_i64(dst, src, shift_amount);
        break;
    case A64_SHIFT_TYPE_LSR:
        tcg_gen_shr_i64(dst, src, shift_amount);
        break;
    case A64_SHIFT_TYPE_ASR:
        if (!sf) {
            tcg_gen_ext32s_i64(dst, src);
        }
        tcg_gen_sar_i64(dst, sf ? src : dst, shift_amount);
        break;
    case A64_SHIFT_TYPE_ROR:
        if (sf) {
            tcg_gen_rotr_i64(dst, src, shift_amount);
        } else {
            TCGv_i32 t0, t1;
            t0 = tcg_temp_new_i32();
            t1 = tcg_temp_new_i32();
            tcg_gen_trunc_i64_i32(t0, src);
            tcg_gen_trunc_i64_i32(t1, shift_amount);
            tcg_gen_rotr_i32(t0, t0, t1);
            tcg_gen_extu_i32_i64(dst, t0);
            tcg_temp_free_i32(t0);
            tcg_temp_free_i32(t1);
        }
        break;
    default:
        assert(FALSE); /* all shift types should be handled */
        break;
    }

    if (!sf) { /* zero extend final result */
        tcg_gen_ext32u_i64(dst, dst);
    }
}

/* shift a TCGv src by immediate, put result in dst. */
static void shift_reg_imm(TCGv_i64 dst, TCGv_i64 src, int sf,
                          enum a64_shift_type shift_type, unsigned int shift_i)
{
    shift_i = shift_i & (sf ? 63 : 31);

    if (shift_i == 0) {
        tcg_gen_mov_i64(dst, src);
    } else {
        TCGv_i64 shift_const;
        shift_const = tcg_const_i64(shift_i);
        shift_reg(dst, src, sf, shift_type, shift_const);
        tcg_temp_free_i64(shift_const);
    }
}

/* C3.5.10 Logical (shifted register) */
static void disas_logic_reg(DisasContext *s, uint32_t insn)
{
    /*
     * 31 30 29 28 27 26 25 24 23 22 21 20    16 15      10 9    5 4    0
     * sf  opc   0  1  0  1  0 shift  N    Rm       imm6      Rn     Rd
     */
    TCGv_i64 tcg_rd, tcg_rn, tcg_rm;
    unsigned int sf, opc, shift_type, invert, rm, shift_amount, rn, rd;
    sf = (insn & (1 << 31)) ? 1 : 0;
    opc = extract32(insn, 29, 2);
    shift_type = extract32(insn, 22, 2);
    invert = (insn & (1 << 21)) ? 1 : 0;
    rm = extract32(insn, 16, 5);
    shift_amount = extract32(insn, 10, 6);
    rn = extract32(insn, 5, 5);
    rd = extract32(insn, 0, 5);

    if (!sf && (shift_amount & (1 << 5))) {
        unallocated_encoding(s);
        return;
    }

    tcg_rm = tcg_temp_new_i64();
    read_cpu_reg(s, tcg_rm, rm, sf);

    if (shift_amount) {
        shift_reg_imm(tcg_rm, tcg_rm, sf,
                      shift_type, shift_amount);
    }

    if (invert) {
        tcg_gen_not_i64(tcg_rm, tcg_rm);
        /* we zero extend later on (!sf) */
    }

    tcg_rd = cpu_reg(s, rd);
    tcg_rn = cpu_reg(s, rn);

    switch (opc) {
    case 0: /* AND, BIC */
    case 3: /* ANDS, BICS */
        tcg_gen_and_i64(tcg_rd, tcg_rn, tcg_rm);
        break;
    case 1: /* ORR, ORN */
        tcg_gen_or_i64(tcg_rd, tcg_rn, tcg_rm);
        break;
    case 2: /* EOR, EON */
        tcg_gen_xor_i64(tcg_rd, tcg_rn, tcg_rm);
        break;
    default:
        assert(FALSE); /* must handle all in switch */
        break;
    }

    if (!sf) {
        tcg_gen_ext32u_i64(tcg_rd, tcg_rd);
    }

    if (opc == 3) {
        gen_logic_CC(sf, tcg_rd);
    }

    tcg_temp_free_i64(tcg_rm);
}

/* Add/subtract (extended register) */
static void disas_add_sub_ext_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Add/subtract (shifted register) */
static void disas_add_sub_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Data-processing (3 source) */
static void disas_data_proc_3src(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Add/subtract (with carry) */
static void disas_adc_sbc(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Conditional compare (immediate) */
static void disas_cc_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Conditional compare (register) */
static void disas_cc_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C3.5.6 Conditional select */
static void disas_cond_select(DisasContext *s, uint32_t insn)
{
    /*
     * 31 30 29 28 27 26 25 24 23 22 21 20  16 15  12 11 10 9  5 4  0
     * sf op  S  1  1  0  1  0  1  0  0   Rm    cond   op2   Rn   Rd
     *       [0]
     * op -> else_inv, op2 -> else_inc
     */
    unsigned int sf, else_inv, rm, cond, else_inc, rn, rd;
    TCGv_i64 tcg_rd;
    if (extract32(insn, 21, 9) != 0x0d4 || (insn & (1 << 11))) {
        unallocated_encoding(s);
        return;
    }
    sf = (insn & (1 << 31)) ? 1 : 0;
    else_inv = extract32(insn, 30, 1);
    rm = extract32(insn, 16, 5);
    cond = extract32(insn, 12, 4);
    else_inc = extract32(insn, 10, 1);
    rn = extract32(insn, 5, 5);
    rd = extract32(insn, 0, 5);
    tcg_rd = cpu_reg(s, rd);

    if (cond >= 0x0e) { /* condition "always" */
        read_cpu_reg(s, tcg_rd, rn, sf);
    } else {
        int label_nomatch, label_continue;
        label_nomatch = gen_new_label();
        label_continue = gen_new_label();

        arm_gen_test_cc(cond ^ 1, label_nomatch);
        /* match: */
        read_cpu_reg(s, tcg_rd, rn, sf);
        tcg_gen_br(label_continue);
        /* nomatch: */
        gen_set_label(label_nomatch);
        read_cpu_reg(s, tcg_rd, rm, sf);
        if (else_inv) {
            tcg_gen_not_i64(tcg_rd, tcg_rd);
        }
        if (else_inc) {
            tcg_gen_addi_i64(tcg_rd, tcg_rd, 1);
        }
        if (!sf) {
            tcg_gen_ext32u_i64(tcg_rd, tcg_rd);
        }
        /* continue: */
        gen_set_label(label_continue);
    }
}

static void handle_clz(DisasContext *s, unsigned int sf,
                       unsigned int rn, unsigned int rd)
{
    TCGv_i64 tcg_rd, tcg_rn;
    tcg_rd = cpu_reg(s, rd);
    tcg_rn = cpu_reg(s, rn);

    if (sf) {
        gen_helper_clz64(tcg_rd, tcg_rn);
    } else {
        TCGv_i32 tcg_tmp32 = tcg_temp_new_i32();
        tcg_gen_trunc_i64_i32(tcg_tmp32, tcg_rn);
        gen_helper_clz(tcg_tmp32, tcg_tmp32);
        tcg_gen_extu_i32_i64(tcg_rd, tcg_tmp32);
        tcg_temp_free_i32(tcg_tmp32);
    }
}

static void handle_cls(DisasContext *s, unsigned int sf,
                       unsigned int rn, unsigned int rd)
{
    TCGv_i64 tcg_rd, tcg_rn;
    tcg_rd = cpu_reg(s, rd);
    tcg_rn = cpu_reg(s, rn);

    if (sf) {
        gen_helper_cls64(tcg_rd, tcg_rn);
    } else {
        TCGv_i32 tcg_tmp32 = tcg_temp_new_i32();
        tcg_gen_trunc_i64_i32(tcg_tmp32, tcg_rn);
        gen_helper_cls32(tcg_tmp32, tcg_tmp32);
        tcg_gen_extu_i32_i64(tcg_rd, tcg_tmp32);
        tcg_temp_free_i32(tcg_tmp32);
    }
}

static void handle_rbit(DisasContext *s, unsigned int sf,
                        unsigned int rn, unsigned int rd)
{
    TCGv_i64 tcg_rd, tcg_rn;
    tcg_rd = cpu_reg(s, rd);
    tcg_rn = cpu_reg(s, rn);

    if (sf) {
        gen_helper_rbit64(tcg_rd, tcg_rn);
    } else {
        TCGv_i32 tcg_tmp32 = tcg_temp_new_i32();
        tcg_gen_trunc_i64_i32(tcg_tmp32, tcg_rn);
        gen_helper_rbit(tcg_tmp32, tcg_tmp32);
        tcg_gen_extu_i32_i64(tcg_rd, tcg_tmp32);
        tcg_temp_free_i32(tcg_tmp32);
    }
}

/* C5.6.149 REV with sf==1, opcode==3 ("REV64") */
static void handle_rev64(DisasContext *s, unsigned int sf,
                         unsigned int rn, unsigned int rd)
{
    if (!sf) {
        unallocated_encoding(s);
        return;
    }
    tcg_gen_bswap64_i64(cpu_reg(s, rd), cpu_reg(s, rn));
}

/* C5.6.149 REV with sf==0, opcode==2 */
/* C5.6.151 REV32 (sf==1, opcode==2) */
static void handle_rev32(DisasContext *s, unsigned int sf,
                         unsigned int rn, unsigned int rd)
{
    TCGv_i64 tcg_rd, tcg_rn;
    tcg_rd = cpu_reg(s, rd);
    tcg_rn = cpu_reg(s, rn);

    if (sf) {
        TCGv_i64 tcg_tmp = tcg_temp_new_i64();
        tcg_gen_andi_i64(tcg_tmp, tcg_rn, 0xffffffff);
        tcg_gen_bswap32_i64(tcg_rd, tcg_tmp);
        tcg_gen_shri_i64(tcg_tmp, tcg_rn, 32);
        tcg_gen_bswap32_i64(tcg_tmp, tcg_tmp);
        tcg_gen_deposit_i64(tcg_rd, tcg_rd, tcg_tmp, 32, 32);
        tcg_temp_free_i64(tcg_tmp);
    } else {
        tcg_gen_ext32u_i64(tcg_rd, tcg_rn);
        tcg_gen_bswap32_i64(tcg_rd, tcg_rd);
    }
}

/* C5.6.150 REV16 (opcode==1) */
static void handle_rev16(DisasContext *s, unsigned int sf,
                         unsigned int rn, unsigned int rd)
{
    TCGv_i64 tcg_rd, tcg_rn, tcg_tmp;
    tcg_rd = cpu_reg(s, rd);
    tcg_rn = cpu_reg(s, rn);

    tcg_tmp = tcg_temp_new_i64();
    tcg_gen_andi_i64(tcg_tmp, tcg_rn, 0xffff);
    tcg_gen_bswap16_i64(tcg_rd, tcg_tmp);

    tcg_gen_shri_i64(tcg_tmp, tcg_rn, 16);
    tcg_gen_andi_i64(tcg_tmp, tcg_tmp, 0xffff);
    tcg_gen_bswap16_i64(tcg_tmp, tcg_tmp);
    tcg_gen_deposit_i64(tcg_rd, tcg_rd, tcg_tmp, 16, 16);

    if (!sf) { /* done */
        tcg_temp_free_i64(tcg_tmp);
        return;
    }

    tcg_gen_shri_i64(tcg_tmp, tcg_rn, 32);
    tcg_gen_andi_i64(tcg_tmp, tcg_tmp, 0xffff);
    tcg_gen_bswap16_i64(tcg_tmp, tcg_tmp);
    tcg_gen_deposit_i64(tcg_rd, tcg_rd, tcg_tmp, 32, 16);

    tcg_gen_shri_i64(tcg_tmp, tcg_rn, 48);
    tcg_gen_bswap16_i64(tcg_tmp, tcg_tmp);
    tcg_gen_deposit_i64(tcg_rd, tcg_rd, tcg_tmp, 48, 16);

    tcg_temp_free_i64(tcg_tmp);
}

/* C3.5.7 Data-processing (1 source) */
static void disas_data_proc_1src(DisasContext *s, uint32_t insn)
{
    /*
     * 31 30 29 28 27 26 25 24 23 22 21 20      16 15      10 9  5 4  0
     * sf  1  S  1  1  0  1  0  1  1  0   opcode2    opcode    Rn   Rd
     *       [0]                        [0 0 0 0 0]
     */
    unsigned int sf, opcode, rn, rd;
    if (extract32(insn, 16, 15) != 0x5ac0) {
        unallocated_encoding(s);
        return;
    }
    sf = insn & (1 << 31) ? 1 : 0;
    opcode = extract32(insn, 10, 6);
    rn = extract32(insn, 5, 5);
    rd = extract32(insn, 0, 5);

    switch (opcode) {
    case 0: /* RBIT */
        handle_rbit(s, sf, rn, rd);
        break;
    case 1: /* REV16 */
        handle_rev16(s, sf, rn, rd);
        break;
    case 2: /* REV32 */
        handle_rev32(s, sf, rn, rd);
        break;
    case 3: /* REV64 */
        handle_rev64(s, sf, rn, rd);
        break;
    case 4: /* CLZ */
        handle_clz(s, sf, rn, rd);
        break;
    case 5: /* CLS */
        handle_cls(s, sf, rn, rd);
        break;
    }
}

static void handle_div(DisasContext *s, bool is_signed, unsigned int sf,
                       unsigned int rm, unsigned int rn, unsigned int rd)
{
    TCGv_i64 tcg_n, tcg_m, tcg_rd;
    tcg_n = tcg_temp_new_i64();
    tcg_m = tcg_temp_new_i64();
    tcg_rd = cpu_reg(s, rd);

    if (!sf && is_signed) {
        tcg_gen_ext32s_i64(tcg_n, cpu_reg(s, rn));
        tcg_gen_ext32s_i64(tcg_m, cpu_reg(s, rm));
    } else {
        read_cpu_reg(s, tcg_n, rn, sf);
        read_cpu_reg(s, tcg_m, rm, sf);
    }

    if (is_signed) {
        gen_helper_sdiv64(tcg_rd, tcg_n, tcg_m);
    } else {
        gen_helper_udiv64(tcg_rd, tcg_n, tcg_m);
    }

    tcg_temp_free_i64(tcg_n);
    tcg_temp_free_i64(tcg_m);

    if (!sf) { /* zero extend final result */
        tcg_gen_ext32u_i64(tcg_rd, tcg_rd);
    }
}

/* C5.6.115 LSLV, C5.6.118 LSRV, C5.6.17 ASRV, C5.6.154 RORV */
static void handle_shift_reg(DisasContext *s,
                             enum a64_shift_type shift_type, unsigned int sf,
                             unsigned int rm, unsigned int rn, unsigned int rd)
{
    TCGv_i64 tcg_shift = tcg_temp_new_i64();
    tcg_gen_andi_i64(tcg_shift, cpu_reg(s, rm), sf ? 63 : 31);
    shift_reg(cpu_reg(s, rd), cpu_reg(s, rn), sf, shift_type, tcg_shift);
    tcg_temp_free_i64(tcg_shift);
}

/* C3.5.8 Data-processing (2 source) */
static void disas_data_proc_2src(DisasContext *s, uint32_t insn)
{
    /*
     * 31 30 29 28 27 26 25 24 23 22 21 20  16 15      10 9  5 4  0
     * sf  0  S  1  1  0  1  0  1  1  0   Rm     opcode    Rn   Rd
     *       [0]
     */
    unsigned int sf, rm, opcode, rn, rd;
    sf = insn & (1 << 31) ? 1 : 0;
    rm = extract32(insn, 16, 5);
    opcode = extract32(insn, 10, 6);
    rn = extract32(insn, 5, 5);
    rd = extract32(insn, 0, 5);

    if (extract32(insn, 21, 10) != 0x0d6) {
        unallocated_encoding(s);
        return;
    }

    switch (opcode) {
    case 2: /* UDIV */
        handle_div(s, FALSE, sf, rm, rn, rd);
        break;
    case 3: /* SDIV */
        handle_div(s, TRUE, sf, rm, rn, rd);
        break;
    case 8: /* LSLV */
        handle_shift_reg(s, A64_SHIFT_TYPE_LSL, sf, rm, rn, rd);
        break;
    case 9: /* LSRV */
        handle_shift_reg(s, A64_SHIFT_TYPE_LSR, sf, rm, rn, rd);
        break;
    case 10: /* ASRV */
        handle_shift_reg(s, A64_SHIFT_TYPE_ASR, sf, rm, rn, rd);
        break;
    case 11: /* RORV */
        handle_shift_reg(s, A64_SHIFT_TYPE_ROR, sf, rm, rn, rd);
        break;
    case 16:
    case 17:
    case 18:
    case 19:
    case 20:
    case 21:
    case 22:
    case 23: /* CRC32 */
        unsupported_encoding(s, insn);
        break;
    default:
        unallocated_encoding(s);
        break;
    }
}

/* C3.5 Data processing - register */
static void disas_data_proc_reg(DisasContext *s, uint32_t insn)
{
    switch (extract32(insn, 24, 5)) {
    case 0x0a: /* Logical (shifted register) */
        disas_logic_reg(s, insn);
        break;
    case 0x0b: /* Add/subtract */
        if (insn & (1 << 21)) { /* (extended register) */
            disas_add_sub_ext_reg(s, insn);
        } else {
            disas_add_sub_reg(s, insn);
        }
        break;
    case 0x1b: /* Data-processing (3 source) */
        disas_data_proc_3src(s, insn);
        break;
    case 0x1a:
        switch (extract32(insn, 21, 3)) {
        case 0x0: /* Add/subtract (with carry) */
            disas_adc_sbc(s, insn);
            break;
        case 0x2: /* Conditional compare */
            if (insn & (1 << 11)) { /* (immediate) */
                disas_cc_imm(s, insn);
            } else {            /* (register) */
                disas_cc_reg(s, insn);
            }
            break;
        case 0x4: /* Conditional select */
            disas_cond_select(s, insn);
            break;
        case 0x6: /* Data-processing */
            if (insn & (1 << 30)) { /* (1 source) */
                disas_data_proc_1src(s, insn);
            } else {            /* (2 source) */
                disas_data_proc_2src(s, insn);
            }
            break;
        default:
            unallocated_encoding(s);
            break;
        }
    default:
        unallocated_encoding(s);
        break;
    }
}

/* C3.6 Data processing - SIMD and floating point */
static void disas_data_proc_simd_fp(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C3.1 A64 instruction index by encoding */
static void disas_a64_insn(CPUARMState *env, DisasContext *s)
{
    uint32_t insn;

    insn = arm_ldl_code(env, s->pc, s->bswap_code);
    s->insn = insn;
    s->pc += 4;

    switch (extract32(insn, 25, 4)) {
    case 0x0: case 0x1: case 0x2: case 0x3: /* UNALLOCATED */
        unallocated_encoding(s);
        break;
    case 0x8: case 0x9: /* Data processing - immediate */
        disas_data_proc_imm(s, insn);
        break;
    case 0xa: case 0xb: /* Branch, exception generation and system insns */
        disas_b_exc_sys(s, insn);
        break;
    case 0x4:
    case 0x6:
    case 0xc:
    case 0xe:      /* Loads and stores */
        disas_ldst(s, insn);
        break;
    case 0x5:
    case 0xd:      /* Data processing - register */
        disas_data_proc_reg(s, insn);
        break;
    case 0x7:
    case 0xf:      /* Data processing - SIMD and floating point */
        disas_data_proc_simd_fp(s, insn);
        break;
    default:
        assert(FALSE); /* all 15 cases should be handled above */
        break;
    }

    /* if we allocated any temporaries, free them here */
    free_tmp_a64(s);

    if (unlikely(s->singlestep_enabled) && (s->is_jmp == DISAS_TB_JUMP)) {
        /* go through the main loop for single step */
        s->is_jmp = DISAS_JUMP;
    }
}

void gen_intermediate_code_internal_a64(ARMCPU *cpu,
                                        TranslationBlock *tb,
                                        bool search_pc)
{
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;
    DisasContext dc1, *dc = &dc1;
    CPUBreakpoint *bp;
    uint16_t *gen_opc_end;
    int j, lj;
    target_ulong pc_start;
    target_ulong next_page_start;
    int num_insns;
    int max_insns;

    pc_start = tb->pc;

    dc->tb = tb;

    gen_opc_end = tcg_ctx.gen_opc_buf + OPC_MAX_SIZE;

    dc->is_jmp = DISAS_NEXT;
    dc->pc = pc_start;
    dc->singlestep_enabled = cs->singlestep_enabled;
    dc->condjmp = 0;

    dc->aarch64 = 1;
    dc->thumb = 0;
    dc->bswap_code = 0;
    dc->condexec_mask = 0;
    dc->condexec_cond = 0;
#if !defined(CONFIG_USER_ONLY)
    dc->user = 0;
#endif
    dc->vfp_enabled = 0;
    dc->vec_len = 0;
    dc->vec_stride = 0;
    dc->tmp_a64_count = 0;

    next_page_start = (pc_start & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
    lj = -1;
    num_insns = 0;
    max_insns = tb->cflags & CF_COUNT_MASK;
    if (max_insns == 0) {
        max_insns = CF_COUNT_MASK;
    }

    gen_tb_start();

    tcg_clear_temp_count();

    do {
        if (unlikely(!QTAILQ_EMPTY(&env->breakpoints))) {
            QTAILQ_FOREACH(bp, &env->breakpoints, entry) {
                if (bp->pc == dc->pc) {
                    gen_exception_insn(dc, 0, EXCP_DEBUG);
                    /* Advance PC so that clearing the breakpoint will
                       invalidate this TB.  */
                    dc->pc += 2;
                    goto done_generating;
                }
            }
        }

        if (search_pc) {
            j = tcg_ctx.gen_opc_ptr - tcg_ctx.gen_opc_buf;
            if (lj < j) {
                lj++;
                while (lj < j) {
                    tcg_ctx.gen_opc_instr_start[lj++] = 0;
                }
            }
            tcg_ctx.gen_opc_pc[lj] = dc->pc;
            tcg_ctx.gen_opc_instr_start[lj] = 1;
            tcg_ctx.gen_opc_icount[lj] = num_insns;
        }

        if (num_insns + 1 == max_insns && (tb->cflags & CF_LAST_IO)) {
            gen_io_start();
        }

        if (unlikely(qemu_loglevel_mask(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT))) {
            tcg_gen_debug_insn_start(dc->pc);
        }

        disas_a64_insn(env, dc);

        if (tcg_check_temp_count()) {
            fprintf(stderr, "TCG temporary leak before "TARGET_FMT_lx"\n",
                    dc->pc);
        }

        /* Translation stops when a conditional branch is encountered.
         * Otherwise the subsequent code could get translated several times.
         * Also stop translation when a page boundary is reached.  This
         * ensures prefetch aborts occur at the right place.
         */
        num_insns++;
    } while (!dc->is_jmp && tcg_ctx.gen_opc_ptr < gen_opc_end &&
             !cs->singlestep_enabled &&
             !singlestep &&
             dc->pc < next_page_start &&
             num_insns < max_insns);

    if (tb->cflags & CF_LAST_IO) {
        gen_io_end();
    }

    if (unlikely(cs->singlestep_enabled) && dc->is_jmp != DISAS_EXC) {
        /* Note that this means single stepping WFI doesn't halt the CPU.
         * For conditional branch insns this is harmless unreachable code as
         * gen_goto_tb() has already handled emitting the debug exception
         * (and thus a tb-jump is not possible when singlestepping).
         */
        assert(dc->is_jmp != DISAS_TB_JUMP);
        if (dc->is_jmp != DISAS_JUMP) {
            gen_a64_set_pc_im(dc->pc);
        }
        gen_exception(EXCP_DEBUG);
    } else {
        switch (dc->is_jmp) {
        case DISAS_NEXT:
            gen_goto_tb(dc, 1, dc->pc);
            break;
        default:
        case DISAS_JUMP:
        case DISAS_UPDATE:
            /* indicate that the hash table must be used to find the next TB */
            tcg_gen_exit_tb(0);
            break;
        case DISAS_TB_JUMP:
        case DISAS_EXC:
        case DISAS_SWI:
            break;
        case DISAS_WFI:
            /* This is a special case because we don't want to just halt the CPU
             * if trying to debug across a WFI.
             */
            gen_helper_wfi(cpu_env);
            break;
        }
    }

done_generating:
    gen_tb_end(tb, num_insns);
    *tcg_ctx.gen_opc_ptr = INDEX_op_end;

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)) {
        qemu_log("----------------\n");
        qemu_log("IN: %s\n", lookup_symbol(pc_start));
        log_target_disas(env, pc_start, dc->pc - pc_start,
                         dc->thumb | (dc->bswap_code << 1));
        qemu_log("\n");
    }
#endif
    if (search_pc) {
        j = tcg_ctx.gen_opc_ptr - tcg_ctx.gen_opc_buf;
        lj++;
        while (lj <= j) {
            tcg_ctx.gen_opc_instr_start[lj++] = 0;
        }
    } else {
        tb->size = dc->pc - pc_start;
        tb->icount = num_insns;
    }
}
