#include <sys/select.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <ares.h>
#include <ares_dns.h>
#include <srdns.h>

#include "proxy.h"

int server_sfd = -1;
struct queue_thread queries;

int server_pipe_fd;

static int dns_parse_edns(struct query *query, char **name)
{
	unsigned char *aptr = ((unsigned char *) query->data);
	long len = 0;
	int status = 0, i = 0;
	uint16_t qdcount, ancount, nscount, arcount;

	/* Default values */
	query->bandwidth_req = 0;
	query->latency_req = 0;
	*query->app_name_req = '\0';

	/* Fetch the question and additional record counts from the header. */
	qdcount = DNS_HEADER_QDCOUNT(aptr);
	ancount = DNS_HEADER_ANCOUNT(aptr);
	nscount = DNS_HEADER_NSCOUNT(aptr);
	arcount = DNS_HEADER_ARCOUNT(aptr);
	if (qdcount != 1 || ancount != 0 || nscount != 0 || arcount > 1) {
		fprintf(stderr, "Unexpected number of records for a DNS query: \
			qdcount = %d - ancount = %d - nscount = %d - arcount = %d\n",
			qdcount, ancount, nscount, arcount);
		return -1;
	}

	aptr = aptr + DNS_HEADER_LENGTH;
	status = ares_expand_name(aptr, (unsigned char *) query->data, query->length, name, &len);
	if (status != ARES_SUCCESS) {
		fprintf(stderr, "ERROR Expanding name: %s\n", ares_strerror(status));
		return -1;
	}
	aptr += len + DNS_FIXED_HEADER_QUERY;

	if (arcount == 0) {
		/* No special request for the controller */
		print_debug("A DNS request without information\n");
		inet_ntop(AF_INET6, &query->addr.sin6_addr, query->app_name_req, SLEN + 1);
		return 0;
	}

	/* Examine the EDNS RR */
	aptr++;
	if (DNS_RR_TYPE(aptr) != T_OPT) {
		fprintf(stderr, "The additional record of the request is not an OPT record\n");
	}
	// TODO We could use max_udp_size //uint16_t max_udp_size = DNS_RR_CLASS(q);
	uint16_t edns_length = DNS_RR_LEN(aptr);
	aptr += (EDNSFIXEDSZ-1);

	/* EDNS options in the DNS query */
	uint16_t option_code = 0;
	uint16_t option_length = 0;
	for (i = 0; i < edns_length; i = i + 4 + option_length) {
		option_code = DNS_OPT_CODE(aptr + i);
		option_length = DNS_OPT_LEN(aptr + i);
		switch (option_code) {
		case T_OPT_OPCODE_APP_NAME:
			memcpy(query->app_name_req, aptr + i + 4, option_length);
			query->app_name_req[option_length] = '\0';
			break;
		case T_OPT_OPCODE_BANDWIDTH:
			query->bandwidth_req = DNS__32BIT(aptr + i + 4);
			break;
		case T_OPT_OPCODE_LATENCY:
			query->latency_req = DNS__32BIT(aptr + i + 4);
			break;
		default: /* Unknown values are skipped */
			print_debug("Unknown option code %d in a T_OPT RR of a DNS query\n", option_code);
			break;
		}
	}

	/* Use the IPv6 address if the application name was not given */
	if (*query->app_name_req == '\0') {
		print_debug("No application name received -> we use the IPv6 address\n");
		inet_ntop(AF_INET6, &query->addr.sin6_addr, query->app_name_req, SLEN + 1);
	}

	return 0;
}

static void server_producer_process(fd_set *read_fds)
{
	struct query *query = NULL;
	int length = 0;

	if (FD_ISSET(server_sfd, read_fds)) {
		print_debug("A server producer thread will read the server socket\n");

		/* Read request */
		query = malloc(QUERY_ALLOC);
		if (!query) {
			fprintf(stderr, "Out of memory !\n");
			return; /* Drop request */
		}

		query->addr_len = sizeof(query->addr);
		length = recvfrom(server_sfd, query->data,
				  (size_t) MAX_DNS_PACKET_SIZE, 0,
				  (struct sockaddr *) &(query->addr),
				  &(query->addr_len));
		if (length == -1) {
			perror("Error reading request"); /* Drop the request */
			FREE_POINTER(query);
		} else {
			query->length = (uint16_t) length;
#if DEBUG_PERF
			if (clock_gettime(CLOCK_MONOTONIC, &query->query_rcv_time)) {
				perror("Cannot get query_rcv time");
			}
#endif
			if (mqueue_append(&queries, (struct llnode *) query)) {
				/* Dropping request */
				FREE_POINTER(query);
				return;
			}
		}
	}
}

static void *server_producer_main(__attribute__((unused)) void *args)
{
	print_debug("A server producer thread has started\n");

	int err = 0;
	fd_set read_fds;
	struct timeval timeout;

	while (!stop) {
		FD_ZERO(&read_fds);
		FD_SET(server_sfd, &read_fds);
		timeout.tv_sec = TIMEOUT_LOOP;
		timeout.tv_usec = 0;
		err = select(server_sfd + 1, &read_fds, NULL, NULL, &timeout);
		if (err < 0) {
			perror("Select fail");
			goto out;
		}
		server_producer_process(&read_fds);
	}

out:
	print_debug("A server producer thread has finished\n");
	return NULL;
}

#if USE_DNS_CACHE
static struct reply *get_from_dns_cache(char *dns_name)
{

	hmap_read_lock(dns_cache);
	struct reply *stored_reply = hmap_get(dns_cache, dns_name);
	if (stored_reply) {
		/* TODO Delete if TTL is exceeded */
	}
	hmap_unlock(dns_cache);

	struct reply *dns_reply = NULL;
	if (stored_reply) {
		dns_reply = malloc(REPLY_ALLOC);
		if (!dns_reply) {
			fprintf(stderr, "Out of memory\n");
		}
		memcpy(dns_reply, stored_reply, sizeof(*stored_reply) + stored_reply->data_length);
	}
	return dns_reply;
}
#endif

static void *server_consumer_main(__attribute__((unused)) void *_arg)
{
	print_debug("A server consumer thread has started\n");

	int err = 0;
	struct query *query = NULL;
	struct callback_args *args = NULL;
	char *name = NULL;

	server_pipe_fd = open(cfg.client_server_fifo, O_WRONLY);
	if (server_pipe_fd < 0) {
		perror("Cannot open pipe");
		return NULL;
	}
	print_debug("Pipe opened on server side\n");

	mqueue_walk_dequeue(&queries, query, struct query *) {

		print_debug("A server consumer thread dequeues a query\n");

#if DEBUG_PERF
		if (clock_gettime(CLOCK_MONOTONIC, &query->query_forward_time)) {
			perror("Cannot get query_forward time");
		}
#endif

		/* Parse Query and EDNS0 RR */
		if (dns_parse_edns(query, &name)) {
			fprintf(stderr, "A query was not parsed correctly and hence dropped\n");
			goto free_query;
		}

		/* Look inside the DNS cache */
		struct reply *reply = NULL;
#if USE_DNS_CACHE
		reply = get_from_dns_cache(name);
#endif
		if (!reply) {
			/* Makes a new request to the controller */
			print_debug("DNS cache miss !\n");

			args = malloc(sizeof(struct callback_args));
			if (!args) {
				fprintf(stderr, "Out of memory !\n");
				goto err_free_ares_string;
			}

			args->qid = DNS_HEADER_QID((char *) query->data);
			args->addr = query->addr;
			args->addr_len = query->addr_len;
			args->bandwidth_req = query->bandwidth_req;
			args->latency_req = query->latency_req;
			strncpy(args->app_name_req, query->app_name_req, SLEN + 1);
#if DEBUG_PERF
			args->query_rcv_time = query->query_rcv_time;
			args->query_forward_time = query->query_forward_time;
#endif

			if ((err = pthread_mutex_lock(&channel_mutex))) {
				perror("Cannot lock the mutex to append");
				goto err_free_args;
			}
			ares_query(channel, name, C_IN, T_AAAA, client_callback, (void *) args);
			pthread_mutex_unlock(&channel_mutex);
			if (write(server_pipe_fd, "1", 1) != 1) {
				perror("Problem writing to pipe");
			}
#if DEBUG_PERF
			if (clock_gettime(CLOCK_MONOTONIC, &query->query_after_query_time)) {
				perror("Cannot get query_after_query time");
			}
			printf("Query %d has finished to send the query at %ld.%ld\n", args->qid,
			       query->query_after_query_time.tv_sec, query->query_after_query_time.tv_nsec);
#endif

		} else {
			/* Bypass the interactions the DNS server and the client producer */
			print_debug("DNS cache hit !\n");
			reply->addr = query->addr;
			reply->addr_len = query->addr_len;
			reply->bandwidth_req = query->bandwidth_req;
			reply->latency_req = query->latency_req;
			strncpy(reply->app_name_req, query->app_name_req, SLEN + 1);
			uint16_t qid = DNS_HEADER_QID((char *) query->data);
			DNS_HEADER_SET_QID((char *) reply->data, qid);
#if DEBUG_PERF
			reply->query_rcv_time = query->query_rcv_time;
			reply->query_forward_time = query->query_forward_time;
			if (clock_gettime(CLOCK_MONOTONIC, &reply->reply_rcv_time)) {
				perror("Cannot get reply_rcv time (cache hit)");
			}
#endif
			if (mqueue_append(&replies, (struct llnode *) reply)) {
				/* Dropping reply */
				FREE_POINTER(reply);
			}
		}

		ares_free_string(name);

free_query:
		FREE_POINTER(query);
		continue;

		/* Errors */
err_free_args:
		FREE_POINTER(args);
err_free_ares_string:
		ares_free_string(name);
		goto free_query;
	}

	print_debug("A server consumer thread has finished\n");

	return NULL;
}

int init_server(pthread_t *server_consumer_thread, pthread_t *server_producer_thread)
{
	int status = 0;

	mqueue_init(&queries, cfg.max_queries);

	/* Thread launching */
	status = pthread_create(server_consumer_thread, NULL, server_consumer_main, NULL);
	if (status) {
		perror("Cannot create consumer server thread");
		goto out_err;
	}

	status = pthread_create(server_producer_thread, NULL, server_producer_main, NULL);
	if (status) {
		perror("Cannot create producer server thread");
		goto out_err;
	}

out:
	return status;
out_err:
	mqueue_destroy(&queries);
	goto out;
}

void close_server()
{
	mqueue_destroy(&queries);
	CLOSE_FD(server_sfd);
}
