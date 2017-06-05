#ifndef _ATOMIC_H
#define _ATOMIC_H

#include <stdint.h>

#define DCACHE1_LINESIZE	64
#define ____cacheline_aligned   __attribute__((aligned(DCACHE1_LINESIZE)))

#ifdef ALIGN_REFCOUNT
#define __refcount_aligned	____cacheline_aligned
#else
#define __refcount_aligned
#endif

typedef int32_t atomic_t;
typedef int64_t atomic64_t;

#define atomic_inc(val) (__sync_add_and_fetch((val), 1))
#define atomic_dec(val) (__sync_sub_and_fetch((val), 1))

#endif
