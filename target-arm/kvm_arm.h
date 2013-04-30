/*
 * QEMU KVM support -- ARM specific functions.
 *
 * Copyright (c) 2012 Linaro Limited
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_KVM_ARM_H
#define QEMU_KVM_ARM_H

#include "sysemu/kvm.h"
#include "exec/memory.h"

/**
 * kvm_arm_register_device:
 * @mr: memory region for this device
 * @devid: the KVM device ID
 *
 * Remember the memory region @mr, and when it is mapped by the
 * machine model, tell the kernel that base address using the
 * KVM_SET_DEVICE_ADDRESS ioctl. @devid should be the ID of
 * the device as defined by KVM_SET_DEVICE_ADDRESS.
 * The machine model may map and unmap the device multiple times;
 * the kernel will only be told the final address at the point
 * where machine init is complete.
 */
void kvm_arm_register_device(MemoryRegion *mr, uint64_t devid);

/**
 * write_kvmstate_to_list:
 * @cpu: ARMCPU
 * @fail_on_error: true to fail on any error/mismatch, false
 *    to continue regardless
 *
 * Write the kernel's idea of the state of the coprocessor
 * registers for this CPU to the cpreg_tuples[] list. If
 * fail_on_error is set then we will stop (and return false)
 * if the kernel doesn't recognise any of the register indexes
 * in the tuples list. Otherwise we continue on regardless
 * and always return true.
 *
 * Returns true on success, false on failure
 */
bool write_kvmstate_to_list(ARMCPU *cpu, bool fail_on_error);

/**
 * write_list_to_kvmstate:
 * @cpu: ARMCPU
 * @fail_on_error: true to fail on any error/mismatch, false
 *    to continue regardless
 *
 * Write the coprocessor register state from the cprog_tuples[]
 * list to the kernel. If fail_on_error is set then we will stop
 * (and return false) if the kernel doesn't recognise any of the
 * register indexes in the tuples list, or if the value can't
 * be written (eg attempt to change value of read-only constant
 * register or to set unsettable bits in a partially RO register).
 * Otherwise we continue on regardless and always return true.
 *
 * Returns true on success, false on failure
 */
bool write_list_to_kvmstate(ARMCPU *cpu, bool fail_on_error);

#endif
