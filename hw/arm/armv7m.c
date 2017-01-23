/*
 * ARMV7M System emulation.
 *
 * Copyright (c) 2006-2007 CodeSourcery.
 * Written by Paul Brook
 *
 * This code is licensed under the GPL.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include "hw/sysbus.h"
#include "hw/arm/arm.h"
#include "hw/loader.h"
#include "elf.h"
#include "sysemu/qtest.h"
#include "qemu/error-report.h"

/* Bitbanded IO.  Each word corresponds to a single bit.  */

/* Get the byte address of the real memory for a bitband access.  */
static inline uint32_t bitband_addr(void * opaque, uint32_t addr)
{
    uint32_t res;

    res = *(uint32_t *)opaque;
    res |= (addr & 0x1ffffff) >> 5;
    return res;

}

static uint32_t bitband_readb(void *opaque, hwaddr offset)
{
    uint8_t v;
    cpu_physical_memory_read(bitband_addr(opaque, offset), &v, 1);
    return (v & (1 << ((offset >> 2) & 7))) != 0;
}

static void bitband_writeb(void *opaque, hwaddr offset,
                           uint32_t value)
{
    uint32_t addr;
    uint8_t mask;
    uint8_t v;
    addr = bitband_addr(opaque, offset);
    mask = (1 << ((offset >> 2) & 7));
    cpu_physical_memory_read(addr, &v, 1);
    if (value & 1)
        v |= mask;
    else
        v &= ~mask;
    cpu_physical_memory_write(addr, &v, 1);
}

static uint32_t bitband_readw(void *opaque, hwaddr offset)
{
    uint32_t addr;
    uint16_t mask;
    uint16_t v;
    addr = bitband_addr(opaque, offset) & ~1;
    mask = (1 << ((offset >> 2) & 15));
    mask = tswap16(mask);
    cpu_physical_memory_read(addr, &v, 2);
    return (v & mask) != 0;
}

static void bitband_writew(void *opaque, hwaddr offset,
                           uint32_t value)
{
    uint32_t addr;
    uint16_t mask;
    uint16_t v;
    addr = bitband_addr(opaque, offset) & ~1;
    mask = (1 << ((offset >> 2) & 15));
    mask = tswap16(mask);
    cpu_physical_memory_read(addr, &v, 2);
    if (value & 1)
        v |= mask;
    else
        v &= ~mask;
    cpu_physical_memory_write(addr, &v, 2);
}

static uint32_t bitband_readl(void *opaque, hwaddr offset)
{
    uint32_t addr;
    uint32_t mask;
    uint32_t v;
    addr = bitband_addr(opaque, offset) & ~3;
    mask = (1 << ((offset >> 2) & 31));
    mask = tswap32(mask);
    cpu_physical_memory_read(addr, &v, 4);
    return (v & mask) != 0;
}

static void bitband_writel(void *opaque, hwaddr offset,
                           uint32_t value)
{
    uint32_t addr;
    uint32_t mask;
    uint32_t v;
    addr = bitband_addr(opaque, offset) & ~3;
    mask = (1 << ((offset >> 2) & 31));
    mask = tswap32(mask);
    cpu_physical_memory_read(addr, &v, 4);
    if (value & 1)
        v |= mask;
    else
        v &= ~mask;
    cpu_physical_memory_write(addr, &v, 4);
}

static const MemoryRegionOps bitband_ops = {
    .old_mmio = {
        .read = { bitband_readb, bitband_readw, bitband_readl, },
        .write = { bitband_writeb, bitband_writew, bitband_writel, },
    },
    .endianness = DEVICE_NATIVE_ENDIAN,
};

#define TYPE_BITBAND "ARM,bitband-memory"
#define BITBAND(obj) OBJECT_CHECK(BitBandState, (obj), TYPE_BITBAND)

typedef struct {
    /*< private >*/
    SysBusDevice parent_obj;
    /*< public >*/

    MemoryRegion iomem;
    uint32_t base;
} BitBandState;

static void bitband_init(Object *obj)
{
    BitBandState *s = BITBAND(obj);
    SysBusDevice *dev = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->iomem, obj, &bitband_ops, &s->base,
                          "bitband", 0x02000000);
    sysbus_init_mmio(dev, &s->iomem);
}

static void armv7m_bitband_init(void)
{
    DeviceState *dev;

    dev = qdev_create(NULL, TYPE_BITBAND);
    qdev_prop_set_uint32(dev, "base", 0x20000000);
    object_property_add_child(qdev_get_machine(), "bitband22",
                              &dev->parent_obj, &error_fatal);
    qdev_init_nofail(dev);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, 0x22000000);

    dev = qdev_create(NULL, TYPE_BITBAND);
    qdev_prop_set_uint32(dev, "base", 0x40000000);
    object_property_add_child(qdev_get_machine(), "bitband42",
                              &dev->parent_obj, &error_fatal);
    qdev_init_nofail(dev);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, 0x42000000);
}

/* Board init.  */

void armv7m_init(const char *cpu_model)
{
    ARMCPU *cpu;
    CPUARMState *env;
    DeviceState *nvic;

    if (cpu_model == NULL) {
        cpu_model = "cortex-m3";
    }
    cpu = ARM_CPU(cpu_generic_init_unrealized(TYPE_ARM_CPU, cpu_model));
    if (cpu == NULL) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }
    env = &cpu->env;

    object_property_add_child(qdev_get_machine(), "cpu[*]", OBJECT(cpu),
                              &error_fatal);

    armv7m_bitband_init();

    nvic = qdev_create(NULL, "armv7m_nvic");
    object_property_add_child(qdev_get_machine(), "nvic", &nvic->parent_obj,
                              &error_fatal);
    env->nvic = nvic;

    sysbus_connect_irq(SYS_BUS_DEVICE(nvic), 0,
                       qdev_get_gpio_in(DEVICE(cpu), ARM_CPU_IRQ));
}


void armv7m_realize(int mem_size, const char *kernel_filename)
{
    ARMCPU *cpu = ARM_CPU(first_cpu);
    DeviceState *nvic = DEVICE(object_resolve_path("/machine/nvic", NULL));
    int image_size;
    uint64_t entry;
    uint64_t lowaddr;
    int big_endian;

#ifdef TARGET_WORDS_BIGENDIAN
    big_endian = 1;
#else
    big_endian = 0;
#endif

    if (!kernel_filename && !qtest_enabled()) {
        fprintf(stderr, "Guest image must be specified (using -kernel)\n");
        exit(1);
    }

    if (kernel_filename) {
        image_size = load_elf(kernel_filename, NULL, NULL, &entry, &lowaddr,
                              NULL, big_endian, EM_ARM, 1, 0);
        if (image_size < 0) {
            image_size = load_image_targphys(kernel_filename, 0, mem_size);
            lowaddr = 0;
        }
        if (image_size < 0) {
            error_report("Could not load kernel '%s'", kernel_filename);
            exit(1);
        }
    }

    /* Realizing cpu calls cpu_reset(), which must have rom image
     * already mapped to find the correct entry point.
     */
    qdev_init_nofail(DEVICE(cpu));
    qdev_init_nofail(nvic);
}

static Property bitband_properties[] = {
    DEFINE_PROP_UINT32("base", BitBandState, base, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void bitband_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->props = bitband_properties;
}

static const TypeInfo bitband_info = {
    .name          = TYPE_BITBAND,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(BitBandState),
    .instance_init = bitband_init,
    .class_init    = bitband_class_init,
};

static void armv7m_register_types(void)
{
    type_register_static(&bitband_info);
}

type_init(armv7m_register_types)
