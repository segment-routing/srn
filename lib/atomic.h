#ifndef _ATOMIC_H
#define _ATOMIC_H

#define DCACHE1_LINESIZE	64
#define ____cacheline_aligned   __attribute__((aligned(DCACHE1_LINESIZE)))

#ifdef ALIGN_REFCOUNT
#define __refcount_aligned	____cacheline_aligned
#else
#define __refcount_aligned
#endif

typedef int atomic_t;

static inline atomic_t atomic_inc(atomic_t *val)
{
	return __sync_fetch_and_add(val, 1);
}

static inline atomic_t atomic_dec(atomic_t *val)
{
	return __sync_fetch_and_sub(val, 1);
}

#endif
