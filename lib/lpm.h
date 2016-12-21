#ifndef _LPM2_H
#define _LPM2_H

#include <arpa/inet.h>
#include <stdint.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

struct lpm_node {
	void *data;

	struct in6_addr prefix;
	uint8_t plen;

	struct lpm_node *parent;
	struct lpm_node *children[2];
};

struct lpm_tree {
	struct lpm_node head;
};

struct lpm_tree *lpm_new(void);
void *lpm_lookup(struct lpm_tree *tree, struct in6_addr *addr);
struct lpm_node *lpm_insert(struct lpm_tree *tree, struct in6_addr *prefix,
			    uint8_t plen, void *data);
void *lpm_delete(struct lpm_tree *tree, struct in6_addr *prefix, uint8_t plen);
void lpm_destroy(struct lpm_tree *tree);

#endif
