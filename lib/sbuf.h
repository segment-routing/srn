#ifndef _SBUF_H
#define _SBUF_H

#include <pthread.h>
#include <semaphore.h>

struct sbuf {
	pthread_mutex_t lock;
	sem_t empty;
	sem_t full;
	void **data;
	unsigned long capacity;
	unsigned long read;
	unsigned long write;
};

#define __sbuf_mask(q, v)	((v) & ((q)->capacity - 1))
#define __sbuf_push(q, v)	((q)->data[__sbuf_mask(q, (q)->write++)] = (v))
#define __sbuf_pop(q)		((q)->data[__sbuf_mask(q, (q)->read++)])
#define __sbuf_empty(q)		((q)->read == (q)->write)
#define __sbuf_full(q)		(__sbuf_size(q) == (q)->capacity)
#define __sbuf_size(q)		((q)->write - (q)->read)

struct sbuf *sbuf_new(unsigned long bufsize);
void sbuf_destroy(struct sbuf *sbuf);
void sbuf_push(struct sbuf *sbuf, void *elem);
void *sbuf_pop(struct sbuf *sbuf);

#endif
