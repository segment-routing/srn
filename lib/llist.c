#include <stdlib.h>
#include <stdint.h>

#include "llist.h"

static void inc_size(struct llist_node *nhead)
{
	nhead->data = (void *)(uintptr_t)(llist_node_size(nhead) + 1);
}

static void dec_size(struct llist_node *nhead)
{
	nhead->data = (void *)(uintptr_t)(llist_node_size(nhead) - 1);
}

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

struct llist_node *llist_node_alloc(void)
{
	return llist_new_node(NULL);
}

struct llist_node *llist_node_insert_tail(struct llist_node *nhead, void *data)
{
	struct llist_node *node;

	node = llist_new_node(data);
	if (!node)
		return NULL;

	llist_insert_tail(&nhead->head, &node->head);

	inc_size(nhead);

	return node;
}

struct llist_node *llist_node_insert_head(struct llist_node *nhead, void *data)
{
	struct llist_node *node;

	node = llist_new_node(data);
	if (!node)
		return NULL;

	llist_insert_head(&nhead->head, &node->head);

	inc_size(nhead);

	return node;
}

void llist_node_remove(struct llist_node *nhead, struct llist_node *node)
{
	llist_remove(&node->head);
	free(node);

	dec_size(nhead);
}

struct llist_node *llist_node_get_iter(struct llist_node *nhead, void *data)
{
	struct llist_node *iter, *res = NULL;

	llist_node_foreach(nhead, iter) {
		if (iter->data == data) {
			res = iter;
			break;
		}
	}

	return res;
}

bool llist_node_exist(struct llist_node *nhead, void *data)
{
	return llist_node_get_iter(nhead, data) != NULL;
}

bool llist_node_empty(struct llist_node *nhead)
{
	return llist_empty(&nhead->head);
}

void llist_node_flush(struct llist_node *nhead)
{
	struct llist_node *iter;

	while (!llist_node_empty(nhead)) {
		iter = llist_first_entry(&nhead->head, struct llist_node, head);
		llist_node_remove(nhead, iter);
	}
}

void llist_node_destroy(struct llist_node *nhead)
{
	llist_node_flush(nhead);
	free(nhead);
}

static struct llist_node *__llist_node_copy(struct llist_node *nhead, bool rev)
{
	struct llist_node *new_nhead, *iter;

	new_nhead = llist_node_alloc();
	if (!new_nhead)
		return NULL;

	llist_node_foreach(nhead, iter)
		if (rev)
			llist_node_insert_head(new_nhead, iter->data);
		else
			llist_node_insert_tail(new_nhead, iter->data);

	return new_nhead;
}

struct llist_node *llist_node_copy(struct llist_node *nhead)
{
	return __llist_node_copy(nhead, false);
}

struct llist_node *llist_node_copy_reverse(struct llist_node *nhead)
{
	return __llist_node_copy(nhead, true);
}

struct llist_node *llist_node_append(struct llist_node *dst, struct llist_node *src)
{
	struct llist_node *iter;

	llist_node_foreach(src, iter)
		llist_node_insert_tail(dst, iter->data);

	return dst;
}
