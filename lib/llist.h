#ifndef _LLIST_H
#define _LLIST_H

#include <stddef.h>
#include <stdbool.h>

struct llist_head {
	struct llist_head *prev;
	struct llist_head *next;
};

struct llist_node {
	void *data;
	struct llist_head head;
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

#define llist_empty(head) ((head)->next == (head))

#define llist_entry(head, type, member)	\
	container_of(head, type, member)

#define llist_first_entry(head, type, member) \
	llist_entry((head)->next, type, member)

#define llist_next_entry(elem, member)	\
	llist_entry((elem)->member.next, typeof(*(elem)), member)

#define llist_last_entry(head, type, member) \
	llist_entry((head)->prev, type, member)

#define llist_foreach(head, elem, member) 				\
	for ((elem) = llist_first_entry(head, typeof(*(elem)), member);	\
	     &((elem)->member) != (head);				\
	     (elem) = llist_next_entry(elem, member))

#define llist_foreach_safe(head, elem, tmp, member)			\
	for ((elem) = llist_first_entry(head, typeof(*(elem)), member),	\
	     (tmp) = llist_next_entry(elem, member);			\
	     &((elem)->member) != (head);				\
	     (elem) = (tmp), (tmp) = llist_next_entry(tmp, member))

#define llist_node_foreach(nhead, elem)	\
	llist_foreach(&(nhead)->head, elem, head)

#define llist_node_foreach_safe(nhead, elem, tmp)	\
	llist_foreach_safe(&(nhead)->head, elem, tmp, head)

#define llist_node_first_entry(nhead) \
	llist_first_entry(&(nhead)->head, struct llist_node, head)

#define llist_node_last_entry(nhead) \
	llist_last_entry(&(nhead)->head, struct llist_node, head)

#define llist_node_next_entry(elem) \
	llist_next_entry(elem, head)

#define llist_node_size(nhead) \
	((size_t)(uintptr_t)(nhead)->data)

struct llist_node *llist_node_alloc(void);
struct llist_node *llist_node_insert_tail(struct llist_node *nhead, void *data);
struct llist_node *llist_node_insert_head(struct llist_node *nhead, void *data);
void llist_node_remove(struct llist_node *nhead, struct llist_node *node);
bool llist_node_exist(struct llist_node *nhead, void *data);
bool llist_node_empty(struct llist_node *nhead);
void llist_node_flush(struct llist_node *nhead);
void llist_node_destroy(struct llist_node *nhead);
struct llist_node *llist_node_copy(struct llist_node *nhead);
struct llist_node *llist_node_copy_reverse(struct llist_node *nhead);
struct llist_node *llist_node_get_iter(struct llist_node *nhead, void *data);
struct llist_node *llist_node_append(struct llist_node *dst, struct llist_node *src);

#endif
