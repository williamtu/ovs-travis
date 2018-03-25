/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMPILER_H
#define COMPILER_H 1

#include "openvswitch/compiler.h"

#if __GNUC__ && !__CHECKER__
#define STRFTIME_FORMAT(FMT) __attribute__((__format__(__strftime__, FMT, 0)))
#define MALLOC_LIKE __attribute__((__malloc__))
#define ALWAYS_INLINE __attribute__((always_inline))
#define SENTINEL(N) __attribute__((sentinel(N)))
#define __rcu
#else
#define STRFTIME_FORMAT(FMT)
#define MALLOC_LIKE
#define ALWAYS_INLINE
#define SENTINEL(N)
//#define __rcu __attribute__((noderef, address_space(4)))
#define __rcu __attribute__((address_space(4)))
#define rcu_dereference_sparse(p, space) \
        ((void)(((typeof(*p) space *)p) == p))
//#define RCU_INITIALIZER(v) (typeof(*(v)) __force __rcu *)(v)
// see how kernel handle it include/linux/rcupdate.h
// see rcu_assign_pointer(p, v)                                              \
//
#endif

/* Output a message (not an error) while compiling without failing the
 * compilation process */
#if HAVE_PRAGMA_MESSAGE
#define DO_PRAGMA(x) _Pragma(#x)
#define BUILD_MESSAGE(x) \
    DO_PRAGMA(message(x))
#else
#define BUILD_MESSAGE(x)
#endif

#endif /* compiler.h */
