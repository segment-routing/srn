#ifndef LINKED_LIST__H
#define LINKED_LIST__H

struct node {
  struct node *next;
  struct node *prev;
};

#define queue_walk_safe(queue, elem, tmp, type)                         \
	for (elem = (type) ((struct node *) queue)->next, tmp = (type) ((struct node *) elem)->next;	\
	  elem != (queue);                                              \
	  elem = tmp, tmp = (type) ((struct node *) elem)->next)

int queue_is_empty(struct node *queue);
void queue_init(struct node *queue);
void queue_append(struct node *queue, struct node *elem);
struct node *queue_dequeue(struct node *queue);
void queue_remove(struct node *queue, struct node *elem);

#define QUEUE_INIT(queue) queue_init((struct node *)(queue))
#define QUEUE_IS_EMPTY(queue) queue_is_empty((struct node *)(queue))
#define QUEUE_APPEND(queue, elem) queue_append((struct node *)(queue), (struct node *)(elem))
#define QUEUE_DEQUEUE(queue) queue_dequeue((struct node *)(queue))
#define QUEUE_REMOVE(queue, elem) queue_remove((struct node *)(queue), (struct node *)(elem))

#endif /* LINKED_LIST__H */
