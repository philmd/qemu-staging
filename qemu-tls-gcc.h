/*
 * TLS with __thread
 *
 * Copyright Red Hat, Inc. 2011
 *
 * Authors:
 *  Paolo Bonzini   <pbonzini@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_TLS_GCC_H
#define QEMU_TLS_GCC_H

#define DECLARE_TLS(type, x) extern DEFINE_TLS(type, x)
#define DEFINE_TLS(type, x)  __thread __typeof__(type) tls__##x
#define get_tls(x)           tls__##x

static inline size_t tls_init(size_t size, size_t alignment) { return 0; }
static inline void tls_init_thread(void) {}

#endif
