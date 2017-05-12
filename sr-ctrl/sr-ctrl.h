#ifndef _SRCTRL_H
#define _SRCTRL_H

#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "graph.h"

struct prefix {
	struct in6_addr addr;
	int len;
};

static inline void pref_pton(const char *src, struct prefix *dst)
{
	char *d, *s;

	memset(dst, 0, sizeof(*dst));

	d = strdup(src);
	s = strchr(d, '/');
	if (!s) {
		free(d);
		return;
	}
	*s++ = 0;
	inet_pton(AF_INET6, d, &dst->addr);
	dst->len = atoi(s);
	free(d);
}

struct router {
	char name[SLEN + 1];
	struct in6_addr addr;
	struct prefix pbsid;
	struct llist_node *prefixes;
	struct hashmap *flows;
	struct node *node;
};

struct link {
	struct in6_addr local;
	struct in6_addr remote;
	unsigned int refcount;
	uint32_t bw;
	uint32_t ava_bw;
	uint32_t delay;
};

struct src_prefix {
	char router[SLEN + 1];
	char addr[SLEN + 1];
	char prefix_len;
	int priority;
	struct in6_addr bsid;
	struct llist_node *segs;
};

struct flow {
	char src[SLEN + 1];
	char dst[SLEN + 1];
	struct in6_addr dstaddr;
	struct src_prefix *src_prefixes;
	unsigned int nb_prefixes;
	struct router *srcrt;
	struct router *dstrt;
	uint32_t bw;
	uint32_t delay;
	uint32_t ttl;
	uint32_t idle;
	time_t timestamp;
	enum flow_status status;
	unsigned int refcount;
};

extern struct d_ops delay_below_ops;
extern struct graph_ops g_ops_srdns;

#endif
