/*
 * Gumstix Overo board emulation.
 * 
 * Copyright (c) 2009 Nokia Corporation
 * Copyright (c) 2011 Linaro Limited
 * Written by Peter Maydell (based on the Beagle board emulation code)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu-common.h"
#include "sysemu.h"
#include "omap.h"
#include "arm-misc.h"
#include "boards.h"
#include "i2c.h"
#include "net.h"
#include "devices.h"
#include "flash.h"
#include "sysbus.h"
#include "blockdev.h"

#define OVERO_NAND_CS       0
#define OVERO_NET_CS        5

struct overo_s {
    struct omap_mpu_state_s *cpu;

    DeviceState *nand;
    void *twl4030;
    DeviceState *eth;
};

static void overo_init(ram_addr_t ram_size,
                       const char *boot_device,
                       const char *kernel_filename,
                       const char *kernel_cmdline,
                       const char *initrd_filename,
                       const char *cpu_model)
{
    struct overo_s *s = (struct overo_s *) qemu_mallocz(sizeof(*s));
    DriveInfo *dmtd = drive_get(IF_MTD, 0, 0);
    DriveInfo *dsd  = drive_get(IF_SD, 0, 0);

    /* FIXME maybe a bit conservative? */
    if (ram_size > 256 * 1024 * 1024) {
        fprintf(stderr, "overo: maximum permitted RAM size 256MB\n");
        exit(1);
    }
    
    if (!dmtd && !dsd) {
        hw_error("%s: SD or NAND image required", __FUNCTION__);
    }
    s->cpu = omap3_mpu_init(omap3430, 1, ram_size,
                            NULL, NULL, serial_hds[0], NULL);

    s->nand = nand_init(NAND_MFR_MICRON, 0xba, dmtd ? dmtd->bdrv : NULL);
    nand_setpins(s->nand, 0, 0, 0, 1, 0); /* no write-protect */
    omap_gpmc_attach(s->cpu->gpmc, OVERO_NAND_CS, s->nand, 0, 2);

    if (dsd) {
        omap3_mmc_attach(s->cpu->omap3_mmc[0], dsd->bdrv, 0, 0);
    }

    /* FAB revs >= 2516: 4030 interrupt is GPIO 0 (earlier ones were 112) */
    s->twl4030 = twl4030_init(omap_i2c_bus(s->cpu->i2c, 0),
                              qdev_get_gpio_in(s->cpu->gpio, 0),
                              NULL, NULL);

    omap_lcd_panel_attach(s->cpu->dss);

    /* Strictly this should be a LAN9221 */
    if (nd_table[0].vlan) {
        /* The ethernet chip hangs off the GPMC */
        NICInfo *nd = &nd_table[0];
        qemu_check_nic_model(nd, "lan9118");
        s->eth = qdev_create(NULL, "lan9118");
        qdev_set_nic_properties(s->eth, nd);
        qdev_init_nofail(s->eth);
        omap_gpmc_attach(s->cpu->gpmc, OVERO_NET_CS, s->eth, 0, 0);
        sysbus_connect_irq(sysbus_from_qdev(s->eth), 0, 
                           qdev_get_gpio_in(s->cpu->gpio, 176));
    }
}

QEMUMachine overo_machine = {
    .name =        "overo",
    .desc =        "Gumstix Overo board (OMAP3530)",
    .init =        overo_init,
};

static void overo_machine_init(void)
{
    qemu_register_machine(&overo_machine);
}

machine_init(overo_machine_init);
