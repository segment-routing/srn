#ifndef PROXY__H
#define PROXY__H

#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ares.h>

#include "linked_list.h"

#define FREE_POINTER(x) if (x) {\
  free(x);\
  x = NULL;\
}

#define CLOSE_FD(x) if (x >= 0) {\
  close(x);\
  x = -1;\
}

#define MAX_QUERIES 50000 /* TODO Change by parameter */

struct mapping_qid;

struct query {
  struct node node;
  struct sockaddr_in6 addr;
  socklen_t addr_len;
  size_t length;
  char data [0];
};

struct reply {
  struct node node;
  struct sockaddr_in6 addr;
  socklen_t addr_len;
  size_t data_length;
  size_t buffer_size;
  uint16_t additional_record_count;
  char data [0];
};

extern struct queue_thread queries;
extern struct queue_thread replies;
extern struct queue_thread replies_with_srh;

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

int parse_arguments(int argc, char *argv[], int *optmask, char **listen_port, char **remote_port, struct ares_addr_node **servers);

int init_server(const char *listen_port);
int server_fds(int server_sfd, fd_set *read_fds, fd_set *write_fds);
void server_process(int server_sfd, fd_set *read_fds, fd_set *write_fds);
void close_server(int server_sfd);

ares_channel init_client(int optmask, struct ares_addr_node *servers);
void client_process(ares_channel channel, fd_set *read_fds, fd_set *write_fds);
void close_client(ares_channel channel);

void init_monitor();
void close_monitor();

#endif /* PROXY__H */
