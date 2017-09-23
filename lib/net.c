#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#include "redblack.h"
#include "net.h"

#define __unused__ __attribute__((unused))

static int compare(const void *a, const void *b, const void *config __unused__)
{
	struct socket *sk1 = (struct socket *)a;
	struct socket *sk2 = (struct socket *)b;

	return (sk1->fd < sk2->fd) ? -1 : (sk1->fd > sk2->fd);
}

struct net *net_new(void *udata)
{
	struct net *net;

	net = malloc(sizeof(*net));
	if (!net)
		return NULL;

	net->epollfd = epoll_create1(0);
	if (net->epollfd < 0) {
		free(net);
		return NULL;
	}

	net->sk_tree = rbinit(compare, NULL);
	if (!net->sk_tree) {
		close(net->epollfd);
		free(net);
		return NULL;
	}

	net->udata = udata;

	return net;
}

int net_register(struct net *net, int fd, int flags,
		 const struct socket_operations *ops)
{
	struct socket *sk;
	struct epoll_event ev;

	sk = malloc(sizeof(*sk));
	if (!sk)
		return -1;

	sk->fd = fd;
	sk->inlen = 0;
	sk->ops = ops;
	sk->vudp = 0;
	pthread_mutex_init(&sk->lock, NULL);

	if (rbfind(sk, net->sk_tree)) {
		free(sk);
		return -1;
	}

	rbsearch(sk, net->sk_tree);

	memset(&ev, 0, sizeof(ev));
	ev.events = flags;
	ev.data.fd = fd;
	if (epoll_ctl(net->epollfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		free(sk);
		return -1;
	}

	return 0;
}

void net_unregister(struct net *net, struct socket *sk)
{
	epoll_ctl(net->epollfd, EPOLL_CTL_DEL, sk->fd, NULL);
	rbdelete(sk, net->sk_tree);
	close(sk->fd);
	free(sk);
}

#define MAX_EVENTS 1000

int net_poll(struct net *net)
{
	struct epoll_event events[MAX_EVENTS];
	struct socket *sk, _sk;
	int i, n, nfds;
	int cleanup[MAX_EVENTS];
	int cleanup_cnt;

	for (;;) {
		nfds = epoll_wait(net->epollfd, events, MAX_EVENTS, -1);
		if (nfds == -1) {
			if (errno == EINTR)
				continue;
			perror("epoll_wait");
			return -1;
		}

		cleanup_cnt = 0;

		for (n = 0; n < nfds; n++) {
			_sk.fd = events[n].data.fd;
			sk = (struct socket *)rbfind(&_sk, net->sk_tree);
			if (!sk) {
				fprintf(stderr, "%s: fd %d not in sk_tree\n", __func__, _sk.fd);
				continue;
			}

			if (events[n].events & EPOLLIN) {
				if (sk->ops->read(net, sk) < 0)
					cleanup[cleanup_cnt++] = sk->fd;
			}
		}

		for (i = 0; i < cleanup_cnt; i++) {
			_sk.fd = cleanup[i];
			sk = (struct socket *)rbfind(&_sk, net->sk_tree);
			if (!sk) {
				fprintf(stderr, "%s: fd %d not in sk_tree for cleanup\n", __func__, _sk.fd);
				continue;
			}
			net_unregister(net, sk);
		}
	}

	return 0;
}
