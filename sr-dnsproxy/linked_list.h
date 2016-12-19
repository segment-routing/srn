#ifndef LINKED_LIST__H
#define LINKED_LIST__H

#include <pthread.h>
#include <semaphore.h>

/* Thread-safe linked-list */

struct node {
  struct node *next;
  struct node *prev;
};

struct queue_thread {
  struct node node;
  size_t max_size;
	pthread_mutex_t mutex;
	sem_t empty;
	sem_t full;
};

int queue_is_empty(struct queue_thread *queue);
void queue_init(struct queue_thread *queue, size_t max_size);
void queue_append(struct queue_thread *queue, struct node *elem);
struct node *queue_dequeue(struct queue_thread *queue);
void queue_destroy(struct queue_thread *queue);

#define queue_walk_dequeue(queue, elem, type)           \
  for (elem = (type) (queue_dequeue(queue));	          \
       (struct node *) elem != (struct node *) (queue); \
       elem = (type) (queue_dequeue(queue)))

#endif /* LINKED_LIST__H */
