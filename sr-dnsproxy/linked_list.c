#include <stdlib.h>
#include <stdio.h>

#include "linked_list.h"


int queue_is_empty(struct queue_thread *queue) {
  return queue->node.next == (struct node *) queue;
}

void queue_init(struct queue_thread *queue, size_t max_size) {
  queue->max_size = max_size;
  queue->node.next = (struct node *) queue;
  queue->node.prev = (struct node *) queue;
  pthread_mutex_init(&queue->mutex, NULL);
	sem_init(&queue->empty, 0, max_size);
	sem_init(&queue->full, 0, 0);
}

void queue_append(struct queue_thread *queue, struct node *elem) {

  struct node *tmp = NULL;
	sem_wait(&queue->empty);
	pthread_mutex_lock(&queue->mutex);

  tmp = queue->node.prev;
  elem->next = (struct node *) queue;
  elem->prev = queue->node.prev;
  tmp->next = elem;
  queue->node.prev = elem;

	pthread_mutex_unlock(&queue->mutex);
	sem_post(&queue->full);
}

static struct node *queue_dequeue_unsafe(struct queue_thread *queue) {
  struct node *tmp = queue->node.next;
  queue->node.next = tmp->next;
  queue->node.next->prev = (struct node *) queue;
  return tmp;
}

struct node *queue_dequeue(struct queue_thread *queue) {
  struct node *tmp = NULL;
  if (queue_is_empty(queue)) {
    return (struct node *) queue;
  }
  sem_wait(&queue->full);
	pthread_mutex_lock(&queue->mutex);
  tmp = queue_dequeue_unsafe(queue);
	pthread_mutex_unlock(&queue->mutex);
	sem_post(&queue->empty);
  return tmp;
}

void queue_destroy(struct queue_thread *queue) {
  struct node *elem = NULL;
  for (elem = queue_dequeue_unsafe(queue);
       elem != (struct node *) queue;
       elem = queue_dequeue_unsafe(queue)) {
    free(elem);
  }
  sem_destroy(&queue->empty);
	sem_destroy(&queue->full);
	pthread_mutex_destroy(&queue->mutex);
}
