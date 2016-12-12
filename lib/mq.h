#ifndef _MQ_H
#define _MQ_H

#include <pthread.h>
#include <semaphore.h>

struct mqueue {
	pthread_mutex_t mutex;
	sem_t empty;
	sem_t full;
	void *buf;
	int size;
	int msize;
	int widx;
	int ridx;
};

struct mqueue *mq_init(int, int);
void mq_push(struct mqueue *, void *);
void mq_pop(struct mqueue *, void *);
void mq_destroy(struct mqueue *);

#endif
