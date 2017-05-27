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
	unsigned int node_id;
	atomic_t refcount __refcount_aligned;
};

static inline void rt_hold(struct router *rt)
{
	atomic_inc(&rt->refcount);
}

static inline void rt_release(struct router *rt)
{
	struct llist_node *iter;

	if (atomic_dec(&rt->refcount) == 0) {
		llist_node_foreach(rt->prefixes, iter)
			free(iter->data);
		llist_node_destroy(rt->prefixes);
		free(rt);
	}
}

struct linkpair {
	struct in6_addr local;
	struct in6_addr remote;
};

struct link {
	struct in6_addr local;
	struct in6_addr remote;
	uint32_t bw;
	uint32_t ava_bw;
	uint32_t delay;
	atomic_t refcount __refcount_aligned;
};

static inline void link_hold(struct link *link)
{
	atomic_inc(&link->refcount);
}

static inline void link_release(struct link *link)
{
	if (atomic_dec(&link->refcount) == 0)
		free(link);
}

struct src_prefix {
	char router[SLEN + 1];
	char addr[SLEN + 1];
	char prefix_len;
	int priority;
	struct in6_addr bsid;
	struct llist_node *segs;
	struct llist_node *epath;
};

struct flow {
	char uuid[SLEN + 1];
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
	char proxy[SLEN + 1];
	char request_id[SLEN + 1];
	atomic_t refcount __refcount_aligned;
};

static inline void flow_hold(struct flow *fl)
{
	atomic_inc(&fl->refcount);
}

static inline void flow_release(struct flow *fl)
{
	if (atomic_dec(&fl->refcount) == 0) {
		unsigned int i;

		for (i = 0; i < fl->nb_prefixes; i++)
			free_segments(fl->src_prefixes[i].segs);

		free(fl->src_prefixes);
		free(fl);
	}
}

static inline struct in6_addr *segment_addr(struct segment *s)
{
	if (s->adjacency)
		return &((struct link *)s->edge->data)->remote;
	else
		return &((struct router *)s->node->data)->addr;
}

extern struct d_ops delay_below_ops;
extern struct graph_ops g_ops_srdns;

#endif
