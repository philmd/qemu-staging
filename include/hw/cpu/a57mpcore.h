/*
 * Cortex-A57MPCore internal peripheral emulation.
 *
 * Copyright (c) 2014 Linaro Limited.
 * Written by Peter Maydell.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#ifndef HW_CPU_A57MPCORE_H
#define HW_CPU_A57MPCORE_H

#include "hw/sysbus.h"
#include "hw/intc/arm_gic.h"

/* A57MP private memory region.  */

#define TYPE_A57MPCORE_PRIV "a57mpcore_priv"
#define A57MPCORE_PRIV(obj) \
    OBJECT_CHECK(A57MPPrivState, (obj), TYPE_A57MPCORE_PRIV)

typedef struct A57MPPrivState {
    /*< private >*/
    SysBusDevice parent_obj;
    /*< public >*/

    uint32_t num_cpu;
    uint32_t num_irq;
    MemoryRegion container;

    GICState gic;
} A57MPPrivState;

#endif
