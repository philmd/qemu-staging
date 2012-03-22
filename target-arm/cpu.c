/*
 * QEMU ARM CPU
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <http://www.gnu.org/licenses/gpl-2.0.html>
 */

#include "cpu-qom.h"
#include "qemu-common.h"
#if !defined(CONFIG_USER_ONLY)
#include "hw/loader.h"
#endif

static void arm_cpu_reset(CPUState *c)
{
    ARMCPUClass *klass = ARM_CPU_GET_CLASS(c);
    ARMCPU *cpu = ARM_CPU(c);
    CPUARMState *env = &cpu->env;
    uint32_t id;
    uint32_t tmp;

    if (qemu_loglevel_mask(CPU_LOG_RESET)) {
        qemu_log("CPU Reset (CPU %d)\n", env->cpu_index);
        log_cpu_state(env, 0);
    }

    klass->parent_reset(c);

    id = env->cp15.c0_cpuid;
    tmp = env->cp15.c15_config_base_address;
    memset(env, 0, offsetof(CPUARMState, breakpoints));
    env->cp15.c0_cpuid = id;
    env->cp15.c15_config_base_address = tmp;

#if defined(CONFIG_USER_ONLY)
    env->uncached_cpsr = ARM_CPU_MODE_USR;
    /* For user mode we must enable access to coprocessors */
    env->vfp.xregs[ARM_VFP_FPEXC] = 1 << 30;
    if (arm_feature(env, ARM_FEATURE_IWMMXT)) {
        env->cp15.c15_cpar = 3;
    } else if (arm_feature(env, ARM_FEATURE_XSCALE)) {
        env->cp15.c15_cpar = 1;
    }
#else
    /* SVC mode with interrupts disabled.  */
    env->uncached_cpsr = ARM_CPU_MODE_SVC | CPSR_A | CPSR_F | CPSR_I;
    /* On ARMv7-M the CPSR_I is the value of the PRIMASK register, and is
       clear at reset.  Initial SP and PC are loaded from ROM.  */
    if (IS_M(env)) {
        uint32_t pc;
        uint8_t *rom;
        env->uncached_cpsr &= ~CPSR_I;
        rom = rom_ptr(0);
        if (rom) {
            /* We should really use ldl_phys here, in case the guest
               modified flash and reset itself.  However images
               loaded via -kernel have not been copied yet, so load the
               values directly from there.  */
            env->regs[13] = ldl_p(rom);
            pc = ldl_p(rom + 4);
            env->thumb = pc & 1;
            env->regs[15] = pc & ~1;
        }
    }
    env->vfp.xregs[ARM_VFP_FPEXC] = 0;
    env->cp15.c2_base_mask = 0xffffc000u;
    /* v7 performance monitor control register: same implementor
     * field as main ID register, and we implement no event counters.
     */
    env->cp15.c9_pmcr = (id & 0xff000000);
#endif
    set_flush_to_zero(1, &env->vfp.standard_fp_status);
    set_flush_inputs_to_zero(1, &env->vfp.standard_fp_status);
    set_default_nan_mode(1, &env->vfp.standard_fp_status);
    set_float_detect_tininess(float_tininess_before_rounding,
                              &env->vfp.fp_status);
    set_float_detect_tininess(float_tininess_before_rounding,
                              &env->vfp.standard_fp_status);
    tlb_flush(env, 1);
    /* Reset is a state change for some CPUState fields which we
     * bake assumptions about into translated code, so we need to
     * tb_flush().
     */
    tb_flush(env);
}

static void arm_cpu_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);

    memset(&cpu->env, 0, sizeof(CPUARMState));
    cpu_exec_init(&cpu->env);

    cpu->env.cpu_model_str = object_get_typename(obj);
}

/* CPU models */

static void arm926_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x41069265;
}

static void arm946_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x41059461;
}

static void arm1026_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x4106a262;
}

static void arm1136_r2_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x4107b362;
}

static void arm1136_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x4117b363;
}

static void arm1176_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x410fb767;
}

static void arm11mpcore_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x410fb022;
}

static void cortex_m3_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x410fc231;
}

static void cortex_a8_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x410fc080;
}

static void cortex_a9_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x410fc090;
}

static void cortex_a15_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x412fc0f1;
}

static void ti925t_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x41069265;
}

static void sa1100_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x4401A11B;
}

static void sa1110_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x6901B119;
}

static void pxa250_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x69052100;
}

static void pxa255_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x69052d00;
}

static void pxa260_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x69052903;
}

static void pxa261_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x69052d05;
}

static void pxa262_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x69052d06;
}

static void pxa270a0_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x69054110;
}

static void pxa270a1_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x69054111;
}

static void pxa270b0_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x69054112;
}

static void pxa270b1_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x69054113;
}

static void pxa270c0_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x69054114;
}

static void pxa270c5_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0x69054117;
}

static void arm_any_initfn(Object *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);
    cpu->env.cp15.c0_cpuid = 0xffffffff;
}

typedef struct ARMCPUInfo {
    const char *name;
    uint32_t id;
    void (*initfn)(Object *obj);
} ARMCPUInfo;

static const ARMCPUInfo arm_cpus[] = {
    { .name = "arm926",      .initfn = arm926_initfn },
    { .name = "arm946",      .initfn = arm946_initfn },
    { .name = "arm1026",     .initfn = arm1026_initfn },
    /* What QEMU calls "arm1136-r2" is actually the 1136 r0p2, i.e. an
     * older core than plain "arm1136". In particular this does not
     * have the v6K features.
     */
    { .name = "arm1136-r2",  .initfn = arm1136_r2_initfn },
    { .name = "arm1136",     .initfn = arm1136_initfn },
    { .name = "arm1176",     .initfn = arm1176_initfn },
    { .name = "arm11mpcore", .initfn = arm11mpcore_initfn },
    { .name = "cortex-m3",   .initfn = cortex_m3_initfn },
    { .name = "cortex-a8",   .initfn = cortex_a8_initfn },
    { .name = "cortex-a9",   .initfn = cortex_a9_initfn },
    { .name = "cortex-a15",  .initfn = cortex_a15_initfn },
    { .name = "ti925t",      .initfn = ti925t_initfn },
    { .name = "sa1100",      .initfn = sa1100_initfn },
    { .name = "sa1110",      .initfn = sa1110_initfn },
    { .name = "pxa250",      .initfn = pxa250_initfn },
    { .name = "pxa255",      .initfn = pxa255_initfn },
    { .name = "pxa260",      .initfn = pxa260_initfn },
    { .name = "pxa261",      .initfn = pxa261_initfn },
    { .name = "pxa262",      .initfn = pxa262_initfn },
    { .name = "pxa270-a0",   .initfn = pxa270a0_initfn },
    { .name = "pxa270-a1",   .initfn = pxa270a1_initfn },
    { .name = "pxa270-b0",   .initfn = pxa270b0_initfn },
    { .name = "pxa270-b1",   .initfn = pxa270b1_initfn },
    { .name = "pxa270-c0",   .initfn = pxa270c0_initfn },
    { .name = "pxa270-c5",   .initfn = pxa270c5_initfn },
    { .name = "any",         .initfn = arm_any_initfn },
};

static void arm_cpu_class_init(ObjectClass *klass, void *data)
{
    ARMCPUClass *k = ARM_CPU_CLASS(klass);
    CPUClass *cpu_class = CPU_CLASS(klass);
    k->parent_reset = cpu_class->reset;
    cpu_class->reset = arm_cpu_reset;
}

static void cpu_register(const ARMCPUInfo *info)
{
    TypeInfo type = {
        .name = info->name,
        .parent = TYPE_ARM_CPU,
        .instance_size = sizeof(ARMCPU),
        .instance_init = info->initfn,
        .class_size = sizeof(ARMCPUClass),
        .class_init = arm_cpu_class_init,
    };

    type_register_static(&type);
}

static TypeInfo arm_cpu_type_info = {
    .name = TYPE_ARM_CPU,
    .parent = TYPE_CPU,
    .instance_size = sizeof(ARMCPU),
    .instance_init = arm_cpu_initfn,
    .abstract = true,
    .class_size = sizeof(ARMCPUClass),
};

static void arm_cpu_register_types(void)
{
    int i;

    type_register_static(&arm_cpu_type_info);
    for (i = 0; i < ARRAY_SIZE(arm_cpus); i++) {
        cpu_register(&arm_cpus[i]);
    }
}

type_init(arm_cpu_register_types)
