#ifndef LINKED_LIST__H
#define LINKED_LIST__H

#include <pthread.h>
#include <semaphore.h>

#define queue_walk_dequeue(queue, elem, type)           \
  for (elem = (type) (queue_dequeue(queue));	          \
       (struct node *) elem != (struct node *) (queue); \
       elem = (type) (queue_dequeue(queue)))

#define mqueue_walk_dequeue(queue, elem, type)           \
  for (elem = (type) (mqueue_dequeue(queue));	           \
       (struct node *) elem != (struct node *) (queue);  \
       elem = (type) (mqueue_dequeue(queue)))

#define mqueue_walk_safe(queue, elem, tmp, type)                                               \
  for (elem = (type) ((struct node *) queue)->next, tmp = (type) ((struct node *) elem)->next; \
       (struct node *) elem != (struct node *) (queue);                                        \
       elem = tmp, tmp = (type) ((struct node *) tmp)->next)

struct node {
  struct node *next;
  struct node *prev;
};

struct queue {
  struct node node;
  size_t length;
};

void queue_init(struct queue *queue);
int queue_append(struct queue *queue, struct node *elem);
struct node *queue_dequeue(struct queue *queue);
int queue_remove(struct queue *queue, struct node *elem);
void queue_destroy(struct queue *queue);

/* Thread-safe linked-list */

struct queue_thread {
  struct queue queue;
  int closed;
	pthread_mutex_t mutex;
	sem_t empty;
	sem_t full;
};

/* These 2 functions are thread-safe */
int mqueue_append(struct queue_thread *queue, struct node *elem);
struct node *mqueue_dequeue(struct queue_thread *queue);
int mqueue_remove(struct queue_thread *queue, struct node *elem);

/* It can be called to unblock threads that are calling inside queue_append and queue_dequeue.
 * Moreover, all subsequent calls to these function will fail.
 */
void mqueue_close(struct queue_thread *queue, int consumer_threads, int producer_threads);

/* These two last functions are not thread-safe */
void mqueue_init(struct queue_thread *queue, size_t max_size);
void mqueue_destroy(struct queue_thread *queue);

#endif /* LINKED_LIST__H */
