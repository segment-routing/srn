#include <stdlib.h>

#include "llist.h"

static struct llist_node *llist_new_node(void *data)
{
	struct llist_node *node;

	node = malloc(sizeof(*node));
	if (!node)
		return NULL;

	llist_init(&node->head);
	node->data = data;

	return node;
}

struct llist_node *llist_insert_node_tail(struct llist_head *head, void *data)
{
	struct llist_node *node;

	node = llist_new_node(data);
	if (!node)
		return NULL;

	llist_insert_tail(head, &node->head);

	return node;
}

struct llist_node *llist_insert_node_head(struct llist_head *head, void *data)
{
	struct llist_node *node;

	node = llist_new_node(data);
	if (!node)
		return NULL;

	llist_insert_head(head, &node->head);

	return node;
}
