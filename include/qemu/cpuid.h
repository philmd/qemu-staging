/*
 * Wrapper for the gcc cpuid.h header.
 *
 * Copyright (c) 2013 Linaro Limited
 *
 * Authors:
 *  Peter Maydell <peter.maydell@linaro.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* This header serves two purposes:
 * (1) some versions of gcc's cpuid.h have no multiple inclusion
 * guards; this header is guaranteed to have them.
 * (2) it saves the including file having to wrap its #include
 * in the CONFIG_CPUID_H ifdef.
 */

#ifndef QEMU_CPUID_H
#define QEMU_CPUID_H

#ifdef CONFIG_CPUID_H
#include <cpuid.h>
#endif

#endif
