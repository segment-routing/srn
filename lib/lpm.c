/* Longest Prefix Match library V2
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "lpm.h"

struct lpm_tree *lpm_new(void)
{
	struct lpm_tree *tree;

	tree = malloc(sizeof(*tree));
	if (!tree)
		return NULL;

	memset(tree, 0, sizeof(*tree));

	return tree;
}

static struct lpm_node *lpm_create_node(struct in6_addr *prefix, uint8_t plen,
					void *data)
{
	struct lpm_node *node;

	node = malloc(sizeof(*node));
	if (!node)
		return NULL;

	memset(node, 0, sizeof(*node));
	memcpy(&node->prefix, prefix, 16);
	node->plen = plen;
	node->data = data;

	return node;
}

static void addr_to_binary(struct in6_addr *addr, char *res)
{
	int i, j, k = 0;

	for (i = 0; i < 16; i++) {
		int val = addr->s6_addr[i];

		for (j = 0; j < 8; j++) {
			int bit = (val >> (7-j)) & 0x1;
			res[k++] = bit ? '1' : '0';
		}
	}

	res[k] = 0;
}

static bool match_node(struct lpm_node *node, struct in6_addr *addr,
		       uint8_t cur_plen)
{
	char prefix_bin[129], addr_bin[129];

	if (node->plen == 0)
		return true;

	addr_to_binary(&node->prefix, prefix_bin);
	addr_to_binary(addr, addr_bin);

	if (memcmp(&prefix_bin[cur_plen], &addr_bin[cur_plen],
		   node->plen - cur_plen) == 0)
		return true;

	return false;
}

static struct lpm_node *__lpm_lookup(struct lpm_tree *tree,
				     struct in6_addr *addr,
				     struct lpm_node **save_cur)
{
	struct lpm_node *cur_node = &tree->head;
	struct lpm_node *last_match = &tree->head;

	for (;;) {
		if (cur_node->data != (void *)-1)
			last_match = cur_node;

		if (cur_node->children[0]) {
			if (match_node(cur_node->children[0], addr,
				       cur_node->plen)) {
				cur_node = cur_node->children[0];
				continue;
			}
		}

		if (cur_node->children[1]) {
			if (match_node(cur_node->children[1], addr,
				       cur_node->plen)) {
				cur_node = cur_node->children[1];
				continue;
			}
		}

		/* either no children or no match */
		break;
	}

	/* save current intermediate node */
	if (save_cur)
		*save_cur = cur_node;

	/* return last valid entry */
	return last_match;
}

void *lpm_lookup(struct lpm_tree *tree, struct in6_addr *addr)
{
	struct lpm_node *node;

	node = __lpm_lookup(tree, addr, NULL);

	if (node->data == (void *)-1)
		return NULL;

	return node->data;
}

static struct lpm_node *__lpm_lookup_exact(struct lpm_tree *tree,
					   struct in6_addr *prefix,
					   uint8_t plen,
					   struct lpm_node **save_cur)
{
	struct lpm_node *cur_node = &tree->head;
	struct lpm_node *match = NULL;

	for (;;) {
		if (match_node(cur_node, prefix, 0) && cur_node->plen == plen &&
		    cur_node->data != (void *)-1) {
			match = cur_node;
			break;
		}

		if (cur_node->children[0] &&
		    cur_node->children[0]->plen <= plen) {
			if (match_node(cur_node->children[0], prefix,
				       cur_node->plen)) {
				cur_node = cur_node->children[0];
				continue;
			}
		}

		if (cur_node->children[1] &&
		    cur_node->children[1]->plen <= plen) {
			if (match_node(cur_node->children[1], prefix,
				       cur_node->plen)) {
				cur_node = cur_node->children[1];
				continue;
			}
		}

		break;
	}

	if (save_cur)
		*save_cur = cur_node;

	return match;
}

static uint8_t common_prefix_len(struct in6_addr *p1, struct in6_addr *p2,
				 uint8_t maxplen)
{
	char p1_bin[129];
	char p2_bin[129];
	uint8_t i;

	addr_to_binary(p1, p1_bin);
	addr_to_binary(p2, p2_bin);

	for (i = 0; i < maxplen; i++) {
		if (p1_bin[i] != p2_bin[i])
			break;
	}

	return i;
}

struct lpm_node *lpm_insert(struct lpm_tree *tree, struct in6_addr *prefix,
			    uint8_t plen, void *data)
{
	struct lpm_node *match, *save, *new_node, *vnode, *child_node;
	char prefix_bin[129];
	int child, cplen, child2;

	match = __lpm_lookup_exact(tree, prefix, plen, &save);

	/* replace existing entry */
	if (match) {
		match->data = data;
		return match;
	}

	/* virtual node becomes real */
	if (save->plen == plen) {
		assert(save->data == (void *)-1);
		save->data = data;
		return save;
	}

	addr_to_binary(prefix, prefix_bin);
	child = prefix_bin[save->plen] == '0' ? 0 : 1;
	child_node = save->children[child];

	new_node = lpm_create_node(prefix, plen, data);

	/* corresponding child entry is non-existent */
	if (!child_node) {
		save->children[child] = new_node;
		new_node->parent = save;
		return new_node;
	}

	cplen = common_prefix_len(&child_node->prefix, prefix, plen);
	assert(cplen > 0);

	/* get child entry for new node */
	child2 = prefix_bin[cplen] == '0' ? 0 : 1;

	/* prefix to add fully matches child prefix, insert in place */
	if (cplen == plen) {
		new_node->children[child2] = child_node;
		child_node->parent = new_node;
		save->children[child] = new_node;
		new_node->parent = save;
		return new_node;
	}

	/* virtual node creation */
	assert(cplen < plen);
	vnode = lpm_create_node(prefix, cplen, (void *)-1);

	/* set child entry in vnode for new node and original child node
	 * set parent to corresponding nodes
	 */
	vnode->children[child2] = new_node;
	vnode->children[!child2] = child_node;
	new_node->parent = vnode;
	child_node->parent = vnode;

	/* replace original child by vnode and set parent accordingly */
	save->children[child] = vnode;
	vnode->parent = save;

	return new_node;
}

static void optimize_virtual_plen(struct lpm_node *node)
{
	int minplen, cplen;

	if (!node->children[0] || !node->children[1])
		return;

	minplen = MIN(node->children[0]->plen, node->children[1]->plen);
	cplen = common_prefix_len(&node->children[0]->prefix,
				  &node->children[1]->prefix, minplen);

	assert(cplen >= node->plen);

	if (cplen == node->plen)
		return;

	memcpy(&node->prefix, &node->children[0]->prefix, 16);
	node->plen = cplen;
}

static void merge_child(struct lpm_node *node)
{
	int idx;
	struct lpm_node *child;

	if (node->children[0] && node->children[1])
		return;

	if (!node->children[0] && !node->children[1])
		return;

	idx = node->children[0] ? 0 : 1;
	child = node->children[idx];

	node->data = child->data;
	memcpy(&node->prefix, &child->prefix, 16);
	node->plen = child->plen;

	node->children[0] = child->children[0];
	node->children[1] = child->children[1];

	if (node->children[0])
		node->children[0]->parent = node;
	if (node->children[1])
		node->children[1]->parent = node;

	memset(child, 0, sizeof(struct lpm_node));
	free(child);
}

static void optimize_virtual_empty(struct lpm_node *node)
{
	int pidx;
	struct lpm_node *parent;

	if (node->children[0] || node->children[1])
		return;

	parent = node->parent;
	pidx = parent->children[0] == node ? 0 : 1;

	parent->children[pidx] = NULL;
	free(node);
}

static void optimize_virtual(struct lpm_node *node)
{
	struct lpm_node *parent;

	if (node->data != (void *)-1)
		return;

	parent = node->parent;

	if (node->children[0] && node->children[1]) {
		optimize_virtual_plen(node);
	} else if (node->children[0] || node->children[1]) {
		merge_child(node);
		optimize_virtual(node);
	} else {
		optimize_virtual_empty(node);
		optimize_virtual(parent);
	}
}

static void *lpm_delete_node(struct lpm_node *node)
{
	void *data;

	data = node->data;
	node->data = (void *)-1;

	optimize_virtual(node);

	return data;
}

void *lpm_delete(struct lpm_tree *tree, struct in6_addr *prefix, uint8_t plen)
{
	struct lpm_node *node;

	node = __lpm_lookup_exact(tree, prefix, plen, NULL);
	if (!node)
		return NULL;

	return lpm_delete_node(node);
}

static void lpm_destroy_node(struct lpm_node *node)
{
	int pidx;

	if (!node)
		return;

	lpm_destroy_node(node->children[0]);
	lpm_destroy_node(node->children[1]);

	if (!node->children[0] && !node->children[1]) {
		pidx = node->parent->children[0] == node ? 0 : 1;
		node->parent->children[pidx] = NULL;
		free(node);
		return;
	}
}

void lpm_destroy(struct lpm_tree *tree)
{
	struct lpm_node *head = &tree->head;

	while (head->children[0])
		lpm_destroy_node(head->children[0]);
	while (head->children[1])
		lpm_destroy_node(head->children[1]);

	free(tree);
}

void print_node(struct lpm_node *node)
{
	char addr[129];

	if (!node)
		return;

	if (node->data != (void *)-1) {
		inet_ntop(AF_INET6, &node->prefix, addr, 128);
		printf("%s/%d\n", addr, node->plen);
	}

	print_node(node->children[0]);
	print_node(node->children[1]);
}

void print_tree(struct lpm_tree *tree)
{
	print_node(&tree->head);
}
