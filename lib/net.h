#ifndef _NET_H
#define _NET_H

#include "redblack.h"

struct net;
struct socket;

struct socket_operations {
	int (*read)(struct net *, struct socket *);
};

#define INBUFLEN 1024

struct socket {
	int fd;
	int inlen;
	const struct socket_operations *ops;
	char inbuf[INBUFLEN];
	pthread_mutex_t lock;
	int vudp;
};

struct net {
	int epollfd;
	struct rbtree *sk_tree;
	void *udata;
};

int net_poll(struct net *);
void net_unregister(struct net *, struct socket *);
int net_register(struct net *, int, int, const struct socket_operations *);
struct net *net_new(void *);

#endif
