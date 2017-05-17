#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>

#include "sbuf.h"

struct sbuf *sbuf_new(unsigned long bufsize)
{
	struct sbuf *sbuf;

	sbuf = calloc(1, sizeof(*sbuf));
	if (!sbuf)
		return NULL;

	pthread_mutex_init(&sbuf->lock, NULL);

	sem_init(&sbuf->empty, 0, bufsize);
	sem_init(&sbuf->full, 0, 0);

	sbuf->capacity = bufsize;
	sbuf->data = malloc(bufsize * sizeof(void *));

	return sbuf;
}

void sbuf_destroy(struct sbuf *sbuf)
{
	free(sbuf->data);
	free(sbuf);
}

void sbuf_push(struct sbuf *sbuf, void *elem)
{
	sem_wait(&sbuf->empty);
	pthread_mutex_lock(&sbuf->lock);
	__sbuf_push(sbuf, elem);
	pthread_mutex_unlock(&sbuf->lock);
	sem_post(&sbuf->full);
}

int sbuf_trypush(struct sbuf *sbuf, void *elem)
{
	if (sem_trywait(&sbuf->empty))
		return -1;

	pthread_mutex_lock(&sbuf->lock);
	__sbuf_push(sbuf, elem);
	pthread_mutex_unlock(&sbuf->lock);
	sem_post(&sbuf->full);

	return 0;
}

void *sbuf_pop(struct sbuf *sbuf)
{
	void *elem;

	sem_wait(&sbuf->full);
	pthread_mutex_lock(&sbuf->lock);
	elem = __sbuf_pop(sbuf);
	pthread_mutex_unlock(&sbuf->lock);
	sem_post(&sbuf->empty);

	return elem;
}

int sbuf_trypop(struct sbuf *sbuf, void **elem)
{
	if (sem_trywait(&sbuf->full))
		return -1;

	pthread_mutex_lock(&sbuf->lock);
	*elem = __sbuf_pop(sbuf);
	pthread_mutex_unlock(&sbuf->lock);
	sem_post(&sbuf->empty);

	return 0;
}
