/*
 * TLS with Win32 .tls sections
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

#ifndef QEMU_TLS_WIN32_H
#define QEMU_TLS_WIN32_H

#include <windows.h>
#include <winnt.h>

typedef struct _TEB {
  NT_TIB NtTib;
  void *EnvironmentPointer;
  void *x[3];
  char **ThreadLocalStoragePointer;
} TEB, *PTEB;

/* 1) The initial contents TLS variables is placed in the .tls section.  */

#define DECLARE_TLS(type, x)  extern DEFINE_TLS(type, x)
#define DEFINE_TLS(type, x)   __typeof__(type) tls__##x __attribute__((section(".tls$AAA")))

/* 2) _tls_index holds the number of our module.  The executable should be
   zero, DLLs are numbered 1 and up.  The loader fills it in for us.  */

extern int _tls_index;
extern int _tls_start;
static inline void tls_init_thread(void) {}

/* 3) Thus, Teb->ThreadLocalStoragePointer[_tls_index] is the base of
   the TLS segment for this (thread, module) pair.  Each segment has
   the same layout as this module's .tls segment and is initialized
   with the content of the .tls segment; 0 is the _tls_start variable.
   So, get_tls passes us the offset of the passed variable relative to
   _tls_start, and we return that same offset plus the base of segment.  */

static inline __attribute__((__const__)) void *_get_tls(size_t offset)
{
    PTEB Teb = NtCurrentTeb();
    return (char *)(Teb->ThreadLocalStoragePointer[_tls_index]) + offset;
}

/* 4) get_tls, in addition to computing the offset, returns an lvalue.
      "I got it.  Magic."  */

#define get_tls(x)                                                 \
  (*(__typeof__(tls__##x) *)                                       \
    _get_tls((ULONG_PTR)&(tls__##x) - (ULONG_PTR)&_tls_start))

#endif
