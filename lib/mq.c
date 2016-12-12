#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <string.h>

#include "mq.h"

struct mqueue *mq_init(int size, int msize)
{
	struct mqueue *mq;

	mq = malloc(sizeof(*mq));
	if (!mq)
		return NULL;

	mq->buf = malloc(size*msize);
	if (!mq->buf) {
		free(mq);
		return NULL;
	}
	mq->size = size;
	mq->msize = msize;
	pthread_mutex_init(&mq->mutex, NULL);
	sem_init(&mq->empty, 0, size);
	sem_init(&mq->full, 0, 0);
	mq->widx = 0;
	mq->ridx = 0;

	return mq;
}

void mq_push(struct mqueue *mq, void *elem)
{
	sem_wait(&mq->empty);
	pthread_mutex_lock(&mq->mutex);

	memcpy(mq->buf + mq->widx*mq->msize, elem, mq->msize);
	mq->widx = (mq->widx + 1) % mq->size;

	pthread_mutex_unlock(&mq->mutex);
	sem_post(&mq->full);
}

void mq_pop(struct mqueue *mq, void *elem)
{
	sem_wait(&mq->full);
	pthread_mutex_lock(&mq->mutex);

	memcpy(elem, mq->buf + mq->ridx*mq->msize, mq->msize);
	mq->ridx = (mq->ridx + 1) % mq->size;

	pthread_mutex_unlock(&mq->mutex);
	sem_post(&mq->empty);
}

void mq_destroy(struct mqueue *mq)
{
	sem_destroy(&mq->empty);
	sem_destroy(&mq->full);
	pthread_mutex_destroy(&mq->mutex);
	free(mq->buf);
	free(mq);
}
