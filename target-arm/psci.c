/*
 * Copyright (C) 2014 - Linaro
 * Author: Rob Herring <rob.herring@linaro.org>
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
#include <cpu.h>
#include <cpu-qom.h>
#include <kvm-consts.h>
#include <sysemu/sysemu.h>
#include <linux/psci.h>

/*
 * This function implements emulation of ARM Power State Coordination
 * Interface (PSCI) version 0.2. Details of the PSCI functionality can be
 * found at:
 * http://infocenter.arm.com/help//topic/com.arm.doc.den0022b/index.html
 */
bool arm_handle_psci(CPUState *cs)
{
    CPUState *target_cs;
    CPUClass *cc;
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    uint64_t param[4];
    uint64_t context_id, mpidr;
    target_ulong entry;
    int32_t ret = 0;
    int i;

    for (i = 0; i < 4; i++) {
        /* Zero extending registers on 32-bit is okay for PSCI */
        param[i] = is_a64(env) ? env->xregs[i] : env->regs[i];
    }

    if ((param[0] & PSCI_0_2_64BIT) && !is_a64(env)) {
        ret = PSCI_RET_INVALID_PARAMS;
        goto err;
    }

    switch (param[0]) {
    case PSCI_0_2_FN_PSCI_VERSION:
        ret = PSCI_VERSION_MAJOR(0) | PSCI_VERSION_MINOR(2);
        break;
    case PSCI_0_2_FN_MIGRATE_INFO_TYPE:
        ret = PSCI_0_2_TOS_MP;    /* No trusted OS */
        break;
    case PSCI_0_2_FN_AFFINITY_INFO:
    case PSCI_0_2_FN64_AFFINITY_INFO:
        mpidr = param[1];

        switch (param[2]) {
        case 0:
            /* Get the target cpu */
            target_cs = qemu_get_cpu(mpidr & 0xff);
            if (!target_cs) {
                ret = PSCI_RET_INVALID_PARAMS;
                break;
            }
            cpu = ARM_CPU(target_cs);
            ret = cpu->powered_off ? 1 : 0;
            break;
        default:
            /* Everything above affinity level 0 is always on. */
            ret = 0;
        }
        break;
    case PSCI_0_2_FN_SYSTEM_RESET:
        qemu_system_reset_request();
        break;
    case PSCI_0_2_FN_SYSTEM_OFF:
        qemu_system_powerdown_request();
        break;
    case PSCI_FN_CPU_ON:
    case PSCI_0_2_FN_CPU_ON:
    case PSCI_0_2_FN64_CPU_ON:
        mpidr = param[1];
        entry = param[2];
        context_id = param[3];

        /* change to the cpu we are powering up */
        target_cs = qemu_get_cpu(mpidr & 0xff);
        if (!target_cs) {
            ret = PSCI_RET_INVALID_PARAMS;
            break;
        }
        cpu = ARM_CPU(target_cs);

        if (!cpu->powered_off) {
            ret = PSCI_RET_ALREADY_ON;
            break;
        }

        /* Initialize the cpu we are turning on */
        cpu_reset(target_cs);
        cc = CPU_GET_CLASS(target_cs);
        cc->set_pc(target_cs, entry);

        cpu->powered_off = false;
        target_cs->interrupt_request |= CPU_INTERRUPT_EXITTB;

        /* Set the context_id in r0/x0 */
        cpu->env.xregs[0] = cpu->env.regs[0] = context_id;

        ret = 0;
        break;
    case PSCI_FN_CPU_OFF:
    case PSCI_0_2_FN_CPU_OFF:
        cpu->powered_off = true;
        cs->exit_request = 1;
        cs->halted = 1;

        /* CPU_OFF should never return, but if it does return an error */
        ret = PSCI_RET_DENIED;
        break;
    case PSCI_FN_CPU_SUSPEND:
    case PSCI_0_2_FN_CPU_SUSPEND:
    case PSCI_0_2_FN64_CPU_SUSPEND:
        /* Affinity levels are not supported in QEMU */
        if (param[1] & 0xfffe0000) {
            ret = PSCI_RET_INVALID_PARAMS;
            break;
        }
        /* Powerdown is not supported, we always go into WFI */
        cs->halted = 1;
        cs->exit_request = 1;

        /* Return success when we wakeup */
        ret = 0;
        break;
    case PSCI_FN_MIGRATE:
    case PSCI_0_2_FN_MIGRATE:
        ret = PSCI_RET_NOT_SUPPORTED;
        break;
    default:
        return false;
    }

err:
    if (is_a64(env)) {
        env->xregs[0] = ret;
    } else {
        env->regs[0] = ret;
    }
    return true;
}
