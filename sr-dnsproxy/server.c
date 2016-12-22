#include <sys/select.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netdb.h>

#include <ares.h>
#include <ares_dns.h>

#include "proxy.h"

int server_sfd = -1;
struct queue_thread queries;

static void server_producer_process(fd_set *read_fds) {

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
      query->bandwidth_req = 5; /* TODO Extract */
      query->latency_req = 0; /* TODO Extract */
      query->app_name_req = "accessA"; /* TODO Extract */
      // TODO Look at the cache
      if (mqueue_append(&queries, (struct node *) query)) {
        /* Dropping request */
        FREE_POINTER(query);
        return;
      }
    }
  }
}

static void *server_producer_main(__attribute__((unused)) void *args) {

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

static void *server_consumer_main(__attribute__((unused)) void *_arg) {

  print_debug("A server consumer thread has started\n");

  int err = 0;
  struct query *query = NULL;
  struct callback_args *args = NULL;

  mqueue_walk_dequeue(&queries, query, struct query *) {

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
    args->bandwidth_req = query->bandwidth_req;
    args->latency_req = query->latency_req;
    args->app_name_req = query->app_name_req;

    if ((err = pthread_mutex_lock(&channel_mutex))) {
      perror("Cannot lock the mutex to append");
      goto free_ares_string;
    }
    ares_query(channel, name, C_IN, T_AAAA, client_callback, (void *) args);
    pthread_mutex_unlock(&channel_mutex);

free_ares_string:
    ares_free_string(name);
free_query:
    FREE_POINTER(query);
  }

  print_debug("A server consumer thread has finished\n");

  return NULL;
}

int init_server(pthread_t *server_consumer_thread, pthread_t *server_producer_thread) {

  int status = 0;

  mqueue_init(&queries, MAX_QUERIES);

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

void close_server() {
  mqueue_destroy(&queries);
  CLOSE_FD(server_sfd);
}
