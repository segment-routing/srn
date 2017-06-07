#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>

#include "srdns.h"
#include "misc.h"

struct flowreq {
	const char *dst;
	const char *dns_server;
	const char *src;
	int bw;
	int delay;
};

enum {
	REQ_FLOW,
	REQ_DNS,
};

static int send_flowreq(struct flowreq *freq, struct in6_addr *res_addr,
			struct in6_addr *bsid)
{
	return make_srdns_request(freq->dst, freq->dns_server, (char *)freq->src,
				  freq->bw, freq->delay, (char *)res_addr,
				  NULL, (char *)bsid);
}

static int send_dnsreq(struct flowreq *freq, struct in6_addr *res_addr)
{
	return make_dns_request(freq->dst, freq->dns_server, (char *)res_addr);
}

static void run(struct flowreq *freq, int count, int type)
{
	struct in6_addr res_addr, bsid;
	struct timeval tv0, tv1, tres;
	int i, ret;

	for (i = 0; i < count; i++) {
		gettimeofday(&tv0, NULL);

		switch (type) {
		case REQ_FLOW:
			ret = send_flowreq(freq, &res_addr, &bsid);
			break;
		case REQ_DNS:
			ret = send_dnsreq(freq, &res_addr);
		}

		gettimeofday(&tv1, NULL);

		timersub(&tv1, &tv0, &tres);

		printf("iter %d success %d time %lf\n", i, !!ret,
			(tres.tv_sec * 1000.0 + tres.tv_usec / 1000.0));
	}
}

int main(int argc, char **argv)
{
	struct flowreq freq;
	int type = 0;

	if (argc != 5) {
		fprintf(stderr, "Usage: %s dns|sr cnt remotename dns_server\n", argv[0]);
		return -1;
	}

	freq.dst = argv[3];
	freq.dns_server = argv[4];
	freq.src = "client";
	freq.bw = 0;
	freq.delay = 0;

	if (!strcmp(argv[1], "dns"))
		type = REQ_DNS;
	else if (!strcmp(argv[1], "sr"))
		type = REQ_FLOW;
	else {
		fprintf(stderr, "Invalid type `%s'.\n", argv[1]);
		return -1;
	}

	run(&freq, atoi(argv[2]), type);
}
