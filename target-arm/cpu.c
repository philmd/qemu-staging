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

static void arm_cpu_reset(CPUState *c)
{
    ARMCPUClass *klass = ARM_CPU_GET_CLASS(c);

    klass->parent_reset(c);
}

/* CPU models */

typedef struct ARMCPUInfo {
    const char *name;
    uint32_t id;
} ARMCPUInfo;

static const ARMCPUInfo arm_cpus[] = {
    {
        .name = "arm926",
        .id = 0x41069265,
    },
    {
        .name = "arm946",
        .id = 0x41059461,
    },
    {
        .name = "arm1026",
        .id = 0x4106a262,
    },
    /* What QEMU calls "arm1136-r2" is actually the 1136 r0p2, i.e. an
     * older core than plain "arm1136". In particular this does not
     * have the v6K features.
     */
    {
        .name = "arm1136-r2",
        .id = 0x4107b362,
    },
    {
        .name = "arm1136",
        .id = 0x4117b363,
    },
    {
        .name = "arm1176",
        .id = 0x410fb767,
    },
    {
        .name = "arm11mpcore",
        .id = 0x410fb022,
    },
    {
        .name = "cortex-m3",
        .id = 0x410fc231,
    },
    {
        .name = "cortex-a8",
        .id = 0x410fc080,
    },
    {
        .name = "cortex-a9",
        .id = 0x410fc090,
    },
    {
        .name = "cortex-a15",
        .id = 0x412fc0f1,
    },
    {
        .name = "ti925t",
        .id = 0x54029252,
    },
    {
        .name = "sa1100",
        .id = 0x4401A11B,
    },
    {
        .name = "sa1110",
        .id = 0x6901B119,
    },
    {
        .name = "pxa250",
        .id = 0x69052100,
    },
    {
        .name = "pxa255",
        .id = 0x69052d00,
    },
    {
        .name = "pxa260",
        .id = 0x69052903,
    },
    {
        .name = "pxa261",
        .id = 0x69052d05,
    },
    {
        .name = "pxa262",
        .id = 0x69052d06,
    },
    {
        .name = "pxa270-a0",
        .id = 0x69054110,
    },
    {
        .name = "pxa270-a1",
        .id = 0x69054111,
    },
    {
        .name = "pxa270-b0",
        .id = 0x69054112,
    },
    {
        .name = "pxa270-b1",
        .id = 0x69054113,
    },
    {
        .name = "pxa270-c0",
        .id = 0x69054114,
    },
    {
        .name = "pxa270-c5",
        .id = 0x69054117,
    },
    {
        .name = "any",
        .id = 0xffffffff,
    },
};

static void arm_cpu_class_init(ObjectClass *klass, void *data)
{
    ARMCPUClass *k = ARM_CPU_CLASS(klass);
    CPUClass *cpu_class = CPU_CLASS(klass);
    const ARMCPUInfo *info = data;

    k->parent_reset = cpu_class->reset;
    cpu_class->reset = arm_cpu_reset;

    k->cp15.c0_cpuid = info->id;
}

static void cpu_register(const ARMCPUInfo *info)
{
    TypeInfo type = {
        .name = info->name,
        .parent = TYPE_ARM_CPU,
        .instance_size = sizeof(ARMCPU),
        .class_size = sizeof(ARMCPUClass),
        .class_init = arm_cpu_class_init,
        .class_data = (void *)info,
    };

    type_register_static(&type);
}

static TypeInfo arm_cpu_type_info = {
    .name = TYPE_ARM_CPU,
    .parent = TYPE_CPU,
    .instance_size = sizeof(ARMCPU),
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
