#include <stdlib.h>
#include <stdio.h>

#include "linked_list.h"


void queue_init(struct queue *queue) {
  queue->length = 0;
  queue->node.next = (struct node *) queue;
  queue->node.prev = (struct node *) queue;
}

void mqueue_init(struct queue_thread *queue, size_t max_size) {
  queue_init(&queue->queue);
  pthread_mutex_init(&queue->mutex, NULL);
	sem_init(&queue->empty, 0, max_size);
	sem_init(&queue->full, 0, 0);
}

int queue_append(struct queue *queue, struct node *elem) {

  struct node *tmp = NULL;

  tmp = queue->node.prev;
  elem->next = (struct node *) queue;
  elem->prev = queue->node.prev;
  tmp->next = elem;
  queue->node.prev = elem;
  queue->length += 1;

  return 0;
}

int mqueue_append(struct queue_thread *queue, struct node *elem) {

  int err = 0;

	if ((err = sem_wait(&queue->empty))) {
    perror("Cannot wait for the semaphore 'empty'");
    goto out_err;
  }
  if (queue->closed) {
    /* Cannot use the queue anymore */
    err = -1;
    goto out_free_sem;
  }
	if ((err = pthread_mutex_lock(&queue->mutex))) {
    perror("Cannot lock the mutex to append");
    goto out_free_sem;
  }

  queue_append(&queue->queue, elem);

	pthread_mutex_unlock(&queue->mutex);
	sem_post(&queue->full);

  return 0;
out_free_sem:
  sem_post(&queue->empty);
out_err:
  return err;
}

struct node *queue_dequeue(struct queue *queue) {
  struct node *tmp = queue->node.next;
  queue->node.next = tmp->next;
  queue->node.next->prev = (struct node *) queue;
  queue->length -= 1;
  return tmp;
}

struct node *mqueue_dequeue(struct queue_thread *queue) {

  struct node *tmp = NULL;

  if (sem_wait(&queue->full)) {
    perror("Cannot wait for the semaphore 'full'");
    goto out_err;
  }
  if (queue->closed) {
    /* Cannot use the queue anymore */
    goto out_free_sem;
  }
	if (pthread_mutex_lock(&queue->mutex)) {
    perror("Cannot lock the mute to dequeue");
    goto out_free_sem;
  }

  tmp = queue_dequeue(&queue->queue);

	pthread_mutex_unlock(&queue->mutex);
	sem_post(&queue->empty);

  return tmp;
out_free_sem:
  sem_post(&queue->full);
out_err:
  return (struct node *) queue;
}

int queue_remove(struct queue *queue, struct node *elem) {

  elem->prev->next = elem->next;
  elem->next->prev = elem->prev;
  elem->next = NULL;
  elem->prev = NULL;
  queue->length -= 1;
  return 0;
}

int mqueue_remove(struct queue_thread *queue, struct node *elem) {

  int err = 0;

  if (sem_wait(&queue->full)) {
    perror("Cannot wait for the semaphore 'full'");
    goto out_err;
  }
  if (queue->closed) {
    /* Cannot use the queue anymore */
    goto out_free_sem;
  }
	if (pthread_mutex_lock(&queue->mutex)) {
    perror("Cannot lock the mute to dequeue");
    goto out_free_sem;
  }

  err = queue_remove(&queue->queue, elem);

	pthread_mutex_unlock(&queue->mutex);
	sem_post(&queue->empty);

  return err;
out_free_sem:
  sem_post(&queue->full);
out_err:
  return -1;
}

void mqueue_close(struct queue_thread *queue, int consumer_threads, int producer_threads) {

  int i = 0;
  queue->closed = 1;
  /* Do a post on empty and on full to unblock these threads */
  for (i = 0; i < consumer_threads; i++) {
    sem_post(&queue->full);
  }
  for (i = 0; i < producer_threads; i++) {
    sem_post(&queue->empty);
  }
}

void queue_destroy(struct queue *queue) {
  struct node *elem = NULL;
  for (elem = queue_dequeue(queue);
       elem != (struct node *) queue;
       elem = queue_dequeue(queue)) {
    free(elem);
  }
}

void mqueue_destroy(struct queue_thread *queue) {
  queue_destroy(&queue->queue);
  sem_destroy(&queue->empty);
	sem_destroy(&queue->full);
	pthread_mutex_destroy(&queue->mutex);
}
