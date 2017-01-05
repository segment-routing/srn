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
	struct arraylist *prefixes;
	struct hashmap *flows;
	struct node *node;
};

struct link {
	struct in6_addr local;
	struct in6_addr remote;
	uint32_t bw;
	uint32_t ava_bw;
	uint32_t delay;
};

struct flow {
	struct in6_addr bsid;
	char src[SLEN + 1];
	char dst[SLEN + 1];
	struct in6_addr dstaddr;
	struct router *srcrt;
	struct router *dstrt;
	struct arraylist *segs;
	uint32_t bw;
	uint32_t delay;
	uint32_t ttl;
	uint32_t idle;
	time_t timestamp;
	enum flow_status status;
};

#endif
