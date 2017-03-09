#ifndef PROXY__H
#define PROXY__H

#include <unistd.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#include <ares.h>

#include <srdb.h>
#include <hashmap.h>

#include "linked_list.h"

#define FREE_POINTER(x) if (x) {\
  free(x);\
  x = NULL;\
}

#define CLOSE_FD(x) if (x >= 0) {\
  close(x);\
  x = -1;\
}

#define DEBUG 1
#define DEBUG_PERF 1
#define USE_DNS_CACHE 0

#if DEBUG
  #define print_debug(fmt, args...)					\
  			fprintf(stderr, __FILE__ ": %s: " fmt, __func__ , ##args);
#else
  #define print_debug(fmt, args...)
#endif

#define TIMEOUT_LOOP 1 /* (sec) */

#define FIFO_CLIENT_SERVER_NAME "client_server_fifo"

struct mapping_qid;

struct query {
  struct node node;
  struct sockaddr_in6 addr;
  socklen_t addr_len;
  size_t length;
  uint32_t bandwidth_req;
  uint32_t latency_req;
  char app_name_req [SLEN + 1];
  char access_router [SLEN + 1];
#if DEBUG_PERF
  struct timespec query_rcv_time;
  struct timespec query_forward_time;
  struct timespec query_after_query_time;
#endif
  char data [0];
};

struct reply {
  struct node node;
  struct sockaddr_in6 addr;
  socklen_t addr_len;
  size_t data_length;
  size_t buffer_size;
  uint16_t additional_record_count;
  uint32_t bandwidth_req;
  uint32_t latency_req;
  char app_name_req [SLEN + 1];
  char access_router [SLEN + 1];
  char ovsdb_req_uuid[SLEN + 1];
  char destination[SLEN + 1];
  char destination_addr[SLEN + 1];
#if DEBUG_PERF
  struct timespec query_rcv_time;
  struct timespec query_forward_time;
  struct timespec reply_rcv_time;
  struct timespec controller_query_time;
  struct timespec controller_after_query_time;
  struct timespec controller_reply_time;
  struct timespec reply_forward_time;
#endif
  char data [0];
};

struct callback_args {
  uint16_t qid;
  struct sockaddr_in6 addr;
  socklen_t addr_len;
  uint32_t bandwidth_req;
  uint32_t latency_req;
  char app_name_req [SLEN + 1];
  char access_router [SLEN + 1];
#if DEBUG_PERF
  struct timespec query_rcv_time;
  struct timespec query_forward_time;
#endif
};

struct monitor_arg {
	struct srdb *srdb;
	struct srdb_table *table;
	const char *columns;
};

struct config {
	struct ovsdb_config ovsdb_conf;
	char dns_fifo[SLEN + 1];
  char router_name[SLEN + 1];
  char max_parallel_queries[SLEN + 1];
  char proxy_listen_port[SLEN + 1];
  char dns_server_port[SLEN + 1];
};

extern volatile sig_atomic_t stop;
extern int max_queries;
extern struct config cfg;
extern struct queue_thread queries;
extern struct queue_thread replies;
extern struct queue_thread replies_waiting_controller;

pthread_mutex_t channel_mutex;
extern ares_channel channel;
extern int server_sfd;
extern struct hashmap *dns_cache;
extern struct srdb *srdb;

#define MAX_DNS_PACKET_SIZE 512 /* TODO Advertize value with EDNS0 */
#define MAX_SRH_RR_SIZE 100 /* TODO Discuss */
#define QUERY_ALLOC (MAX_DNS_PACKET_SIZE + sizeof(struct query))
#define REPLY_ALLOC (MAX_DNS_PACKET_SIZE + MAX_SRH_RR_SIZE + sizeof(struct reply))

static inline void destroy_addr_list(struct ares_addr_node *head) {

  while(head) {
    struct ares_addr_node *detached = head;
    head = head->next;
    free(detached);
  }
}

static inline void append_addr_list(struct ares_addr_node **head, struct ares_addr_node *node) {

  struct ares_addr_node *last;

  node->next = NULL;

  if(*head) {
    last = *head;
    while(last->next)
      last = last->next;
    last->next = node;
  }
  else
    *head = node;
}

int load_config(const char *fname, int *optmask, struct ares_addr_node **servers);

int init_server(pthread_t *server_consumer_thread, pthread_t *server_producer_thread);
void close_server();
void client_callback(void *arg, int status, __attribute__((unused)) int timeouts, unsigned char *abuf, int alen);

int init_client(int optmask, struct ares_addr_node *servers, pthread_t *client_consumer_thread, pthread_t *client_producer_thread);
void close_client();

int init_monitor(struct monitor_arg *args, pthread_t *monitor_flowreqs_thread, pthread_t *monitor_flows_thread);
void close_monitor();

#endif /* PROXY__H */
