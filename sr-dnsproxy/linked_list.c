#include <stdlib.h>

#include "linked_list.h"


int queue_is_empty(struct node *queue) {
  return queue->next == queue;
}

void queue_init(struct node *queue) {
  queue->next = queue;
  queue->prev = queue;
}

void queue_append(struct node *queue, struct node *elem) {
  struct node *tmp = queue->prev;
  elem->next = (queue);
  elem->prev = (queue)->prev;
  tmp->next = elem;
  (queue)->next = elem;
}

struct node *queue_dequeue(struct node *queue) {
  struct node *tmp = queue->next;
  queue->next = tmp->next;
  queue->next->prev = queue;
  return tmp;
}

void queue_remove(struct node *queue, struct node *elem) {

  struct node *next = NULL;
  struct node *current = NULL;

  queue_walk_safe(queue, current, next, struct node *) {
    if (current == elem) {
      current->prev->next = current->next;
      current->next->prev = current->prev;
      current->next = NULL;
      current->prev = NULL;
    }
  }
}
