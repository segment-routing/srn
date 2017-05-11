#ifndef _LLIST_H
#define _LLIST_H

#include <stddef.h>

struct llist_head {
	struct llist_head *prev;
	struct llist_head *next;
};

struct llist_node {
	struct llist_head head;
	void *data;
};

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type, member) ); })

#define llist_init(head)	\
{				\
	(head)->next = head;	\
	(head)->prev = head;	\
}

#define llist_insert_tail(head, elem)	\
{					\
	(elem)->next = (head);		\
	(elem)->prev = (head)->prev;	\
	(head)->prev->next = (elem);	\
	(head)->prev = (elem);		\
}

#define llist_insert_head(head, elem)	\
{					\
	(elem)->next = (head)->next;	\
	(elem)->prev = (head);		\
	(head)->next->prev = (elem);	\
	(head)->next = (elem);		\
}

#define llist_remove(elem)			\
{						\
	(elem)->next->prev = (elem)->prev;	\
	(elem)->prev->next = (elem)->next;	\
	(elem)->next = (elem);			\
	(elem)->prev = (elem);			\
}

#define llist_foreach(head, elem, type, member) 			\
	for ((elem) = container_of((head)->next, type, member);		\
	     &((elem)->member) != (head);				\
	     (elem) = container_of((elem)->member.next, type, member))

#define llist_foreach_safe(head, elem, tmp, type, member)		\
	for ((elem) = container_of((head)->next, type, member),		\
	     (tmp) = container_of((elem)->member.next, type, member);	\
	     &((elem)->member) != (head);				\
	     (elem) = (tmp),						\
	     (tmp) = container_of((tmp)->member.next, type, member))

struct llist_node *llist_insert_node_tail(struct llist_head *head, void *data);
struct llist_node *llist_insert_node_head(struct llist_head *head, void *data);

#endif
