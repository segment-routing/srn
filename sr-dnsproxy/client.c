#include <stdio.h>
#include <sys/select.h>
#include <stdlib.h>
#include <string.h>

#include <ares.h>
#include <ares_dns.h>

#include "proxy.h"

#define C_IN 1
#define T_AAAA 28
#define DNS_RR_NAME_OFFSET 12

struct callback_args {
  uint16_t qid;
  struct sockaddr_in6 addr;
  socklen_t addr_len;
};

struct queue_thread queries;

static void callback(void *arg, int status, __attribute__((unused)) int timeouts, unsigned char *abuf, int alen) {

  if (status != ARES_SUCCESS) {
    fprintf(stderr, "DNS server error: %s\n", ares_strerror(status));
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
    memcpy(reply->data, abuf, alen);
    DNS_HEADER_SET_QID((char *) reply->data, call_args->qid);
    queue_append(&replies, (struct node *) reply);
    // TODO Make RPC to controller !
    // TODO Add to cache (+ add count of references in order to prevent segmentation faults)
  }
  FREE_POINTER(arg);
}

void client_process(ares_channel channel, fd_set *read_fds, fd_set *write_fds) {

  struct query *query = NULL;
  struct callback_args *args = NULL;

  if (!queue_is_empty(&queries)) { /* TODO REMOVE !!!!! */
  queue_walk_dequeue(&queries, query, struct query *) {

    char *name;
    unsigned char *aptr = ((unsigned char *) query->data) + DNS_RR_NAME_OFFSET;
    long len = 0;
    int status = 0;

    status = ares_expand_name(aptr, (unsigned char *) query->data, query->length, &name, &len);
    if (status != ARES_SUCCESS) {
      fprintf(stderr, "ERROR Expanding name: %s\n", ares_strerror(status)); /* drop query */
      goto free_query;
    }

    args = malloc(sizeof(struct callback_args));
    if (!args) {
      fprintf(stderr, "Out of memory !\n");
      goto free_ares_string;
    }

    args->qid = DNS_HEADER_QID((char *) query->data);
    args->addr = query->addr;
    args->addr_len = query->addr_len;
    ares_query(channel, name, C_IN, T_AAAA, callback, (void *) args);

free_ares_string:
    ares_free_string(name);
free_query:
    FREE_POINTER(query);
  }
}

  /* Handle pending replies (by callback) */
  ares_process(channel, read_fds, write_fds);
}

ares_channel init_client(int optmask, struct ares_addr_node *servers) {

  int status = ARES_SUCCESS;

  ares_channel channel = NULL;
  struct ares_options options;
  memset(&options, 0, sizeof(struct ares_options));

  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
    goto out_err;
  }

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

  queue_init(&queries, MAX_QUERIES);

out:
  return channel;
out_cleanup_cares:
  ares_library_cleanup();
out_err:
  if (channel) {
    ares_destroy(channel);
    channel = NULL;
  }
  goto out;
}

void close_client(ares_channel channel) {
  queue_destroy(&queries);
  if (channel) {
    ares_destroy(channel);
    channel = NULL;
  }
  ares_library_cleanup();
}
