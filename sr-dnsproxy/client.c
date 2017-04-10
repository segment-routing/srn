#include <stdio.h>
#include <sys/select.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <ares.h>
#include <ares_dns.h>

#include "proxy.h"

ares_channel channel;
struct queue_thread replies;
pthread_mutex_t channel_mutex;

#if USE_DNS_CACHE
struct hashmap *dns_cache;
#endif

struct queue inner_queue;
int client_pipe_fd;

void client_callback(void *arg, int status, __attribute__((unused)) int timeouts, unsigned char *abuf, int alen)
{
	if (status != ARES_SUCCESS) {
		fprintf(stderr, "DNS server error: %s\n", ares_strerror(status));
		goto out;
	}

	struct callback_args *call_args = (struct callback_args *) arg;
	struct reply *reply = malloc(REPLY_ALLOC);
	if (!reply) {
		fprintf(stderr, "Out of memory !\n"); /* Ignore reply */
	} else {
		reply->data_length = alen;
		reply->buffer_size = REPLY_ALLOC;
		reply->additional_record_count = DNS_HEADER_ARCOUNT(abuf);
		reply->addr = call_args->addr;
		reply->addr_len = call_args->addr_len;
		reply->bandwidth_req = call_args->bandwidth_req;
		reply->latency_req = call_args->latency_req;
		strncpy(reply->app_name_req, call_args->app_name_req, SLEN +1);
		strncpy(reply->access_router, call_args->access_router, SLEN + 1);
		memcpy(reply->data, abuf, alen);
#if DEBUG_PERF
		reply->query_rcv_time = call_args->query_rcv_time;
		reply->query_forward_time = call_args->query_forward_time;
		if (clock_gettime(CLOCK_MONOTONIC, &reply->reply_rcv_time)) {
			perror("Cannot get reply_rcv time");
		}
#endif
		DNS_HEADER_SET_QID((char *) reply->data, call_args->qid);
		if (queue_append(&inner_queue, (struct llnode *) reply)) {
			/* Dropping reply */
			FREE_POINTER(reply);
		}
	}
out:
	FREE_POINTER(arg);
}

static int parse_aaaa_reply(struct reply *reply)
{
	struct hostent *host = NULL;
	if (ares_parse_aaaa_reply((unsigned char *) reply->data, reply->data_length,
                                  &host, NULL, NULL)) {
		return -1;
	}
	strncpy(reply->destination, host->h_name, SLEN +1);
	inet_ntop(AF_INET6, host->h_addr_list[0], reply->destination_addr, SLEN + 1);
	print_debug("DNS matching : %s -> %s\n", reply->destination, reply->destination_addr);
	ares_free_hostent(host);
	return 0;
}

#if USE_DNS_CACHE
static int push_to_dns_cache(struct reply *dns_reply)
{
	int err = 0;
	struct reply *stored_reply = malloc(REPLY_ALLOC);
	if (!stored_reply) {
		fprintf(stderr, "Out of memory\n");
		return -1;
	}
	memcpy(stored_reply, dns_reply, sizeof(*dns_reply) + dns_reply->data_length);

	hmap_write_lock(dns_cache);
	struct reply *entry = hmap_get(dns_cache, stored_reply->destination);
	if (!entry) {
		err = hmap_set(dns_cache, stored_reply->destination, stored_reply);
	}
	hmap_unlock(dns_cache);
	return err;
}
#endif

static void *client_producer_main(__attribute__((unused)) void *args)
{
	int err = 0;
	int nfds = 0;
	fd_set read_fds, write_fds;
	struct timeval timeout;
	struct reply *reply = NULL;
	char pipe_buffer [1000];

	print_debug("A client producer thread has started\n");

	client_pipe_fd = open(FIFO_CLIENT_SERVER_NAME, O_RDONLY);
	if (client_pipe_fd < 0) {
		perror("Cannot open pipe");
		return NULL;
	}

	print_debug("Pipe opened on client side\n");

	queue_init(&inner_queue);
	while (!stop) {
		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		timeout.tv_sec = TIMEOUT_LOOP;
		timeout.tv_usec = 0;
		FD_SET(client_pipe_fd, &read_fds);
		nfds = ares_fds(channel, &read_fds, &write_fds);
		err = select(nfds, &read_fds, &write_fds, NULL, &timeout);
		if (err < 0) {
			perror("Select fail");
			break;
		}

		if (FD_ISSET(client_pipe_fd, &read_fds) && read(client_pipe_fd, pipe_buffer, 1000) < 0)
			perror("Cannot read pipe");

		if (pthread_mutex_lock(&channel_mutex)) {
			perror("Cannot lock the mutex in client producer");
			break;
		}
		ares_process(channel, &read_fds, &write_fds);
		pthread_mutex_unlock(&channel_mutex);

		/* Transfer replies to the multi-threaded queue */
		queue_walk_dequeue(&inner_queue, reply, struct reply *) {
			/* Get back the DNS name and its resolved IPv6 address */
			if (parse_aaaa_reply(reply)) {
				print_debug("Invalid DNS reply received\n");
				/* Dropping reply */
				FREE_POINTER(reply);
				continue;
			}
			print_debug("Client producer will append a reply to the appropriate queue\n");
			if (mqueue_append(&replies, (struct llnode *) reply)) {
				/* Dropping reply */
				FREE_POINTER(reply);
				continue;
			}
#if USE_DNS_CACHE
			/* Place in cache */
			print_debug("Client producer will push the reply to the DNS cache\n");
			if (push_to_dns_cache(reply)) {
				fprintf(stderr, "Cannot insert entry in the DNS cache\n");
				/* Ignores this error */
			}
#endif
		}
	}
	queue_destroy(&inner_queue);
	print_debug("A client producer thread has finished\n");
	return NULL;
}

static void *client_consumer_main(__attribute__((unused)) void *args)
{
	struct srdb_table *router_tbl = srdb_table_by_name(srdb->tables, "RouterIds");
	struct srdb_router_entry router_entry;
	memset(&router_entry, 0, sizeof(router_entry));
	char thread_id [SLEN + 1];
	memset(&thread_id, 0, SLEN + 1);
	unsigned long req_counter = 0;

	struct srdb_table *tbl = srdb_table_by_name(srdb->tables, "FlowReq");
	struct srdb_flowreq_entry entry;
	memset(&entry, 0, sizeof(entry));

	struct reply *reply = NULL;

	print_debug("A client consumer thread has started\n");

	/* Get the OpenFlow ID of this thread */
	strncpy(router_entry.router, cfg.router_name, SLEN + 1);
	if (srdb_insert(srdb, router_tbl, (struct srdb_entry *) &router_entry, thread_id,
                        &transact_input, &transact_output)) {
		fprintf(stderr, "Problem during extraction of thread ID -> stop thread\n");
		return NULL;
	}

	print_debug("This client consumer thread got the ID %s\n", thread_id);

	mqueue_walk_dequeue(&replies, reply, struct reply *) {
		print_debug("Client consumer dequeues a reply\n");

		snprintf(reply->ovsdb_req_uuid, SLEN + 1, "%s-%ld", thread_id, req_counter);
		if (mqueue_append(&replies_waiting_controller, (struct llnode *) reply)) {
			FREE_POINTER(reply);
			break;
		}
		print_debug("Client consumer forwards a reply to the monitor's queue with id %s\n", reply->ovsdb_req_uuid);

		strncpy(entry.destination, reply->destination, SLEN + 1);
		strncpy(entry.dstaddr, reply->destination_addr, SLEN + 1);
		strncpy(entry.source, reply->app_name_req, SLEN + 1);
		entry.bandwidth = reply->bandwidth_req;
		entry.delay = reply->latency_req;
		strncpy(entry.router, reply->access_router, SLEN + 1);
		strncpy(entry.request_id, reply->ovsdb_req_uuid, SLEN + 1);
		strncpy(entry.proxy, cfg.router_name, SLEN + 1);

#if DEBUG_PERF
		if (clock_gettime(CLOCK_MONOTONIC, &reply->controller_query_time)) {
			perror("Cannot get controller_query time");
		}
#endif

		srdb_insert(srdb, tbl, (struct srdb_entry *) &entry, NULL, &transact_input,
								&transact_output);
		print_debug("Client consumer makes the insertion in the OVSDB table\n");

#if DEBUG_PERF
		if (clock_gettime(CLOCK_MONOTONIC, &reply->controller_after_query_time)) {
			perror("Cannot get controller_after_query time");
		}
#endif

		req_counter++; /* The next request will have another id */
	}
	print_debug("A client consumer thread has finished\n");
	return NULL;
}

int init_client(int optmask, struct ares_addr_node *servers,
                pthread_t *client_consumer_thread, pthread_t *client_producer_thread)
{

	int status = ARES_SUCCESS;
	struct ares_options options;
	memset(&options, 0, sizeof(struct ares_options));

	/* Create pipe between the client and the server */
	mkfifo(FIFO_CLIENT_SERVER_NAME, 0640);

	status = ares_library_init(ARES_LIB_INIT_ALL);
	if (status != ARES_SUCCESS) {
		fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
		goto out_err;
	}

	options.udp_port = (unsigned short) strtol(cfg.dns_server_port, NULL, 0);
	optmask |= ARES_OPT_UDP_PORT;
	options.flags |= ARES_FLAG_NOCHECKRESP; /* In order not to ignore REFUSED DNS replies */
	status = ares_init_options(&channel, &options, optmask);
	if (status != ARES_SUCCESS) {
		fprintf(stderr, "ares_init_options: %s\n", ares_strerror(status));
		goto out_cleanup_cares;
	}

	if(servers) {
		status = ares_set_servers(channel, servers);
		if (status != ARES_SUCCESS) {
			fprintf(stderr, "ares_set_servers: %s\n", ares_strerror(status));
			goto out_cleanup_cares;
		}
	}

#if USE_DNS_CACHE
	/* Init DNS cache */
	dns_cache = hmap_new(hash_str, compare_str);
	if (!dns_cache) {
		status = -1;
		fprintf(stderr, "Cannot initalize dns cache\n");
		goto out_cleanup_cares;
	}
#endif

	mqueue_init(&replies, max_queries);

	pthread_mutex_init(&channel_mutex, NULL);

	/* Thread launching */
	status = pthread_create(client_consumer_thread, NULL, client_consumer_main, NULL);
	if (status) {
		perror("Cannot create client consumer thread");
		goto out_cleanup_queue_mutex;
	}
	status = pthread_create(client_producer_thread, NULL, client_producer_main, NULL);
	if (status) {
		perror("Cannot create client producer thread");
		goto out_cleanup_queue_mutex;
	}

out:
	return status;
out_cleanup_queue_mutex:
#if USE_DNS_CACHE
	hmap_destroy(dns_cache);
#endif
	mqueue_destroy(&replies);
	pthread_mutex_destroy(&channel_mutex);
out_cleanup_cares:
	ares_library_cleanup();
out_err:
	if (channel) {
		ares_destroy(channel);
		channel = NULL;
	}
	goto out;
}

#if USE_DNS_CACHE
static void destroy_dns_cache()
{

	/* Free DNS names and DNS replies along with the arraylists */
	while (dns_cache->keys->elem_count) {
		char *name;
		alist_get(dns_cache->keys, 0, &name);
		struct reply *reply = hmap_get(dns_cache, name);
		hmap_delete(dns_cache, name);
		free(reply);
	}

	/* Destroy the hmap structure */
	hmap_destroy(dns_cache);
}
#endif

void close_client()
{
#if USE_DNS_CACHE
	destroy_dns_cache();
#endif
	mqueue_destroy(&replies);
	if (channel) {
		ares_destroy(channel);
		channel = NULL;
	}
	pthread_mutex_destroy(&channel_mutex);
	ares_library_cleanup();
}
