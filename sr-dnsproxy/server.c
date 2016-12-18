#include <sys/select.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netdb.h>

#include <ares.h>

#include "proxy.h"

struct reply replies;

void server_process(int server_sfd, fd_set *read_fds, fd_set *write_fds) {

  struct reply *reply = NULL;
  struct reply *tmp_reply = NULL;

  struct query *query = NULL;
  int length = 0;

  if (FD_ISSET(server_sfd, read_fds)) {

    /* Read request */
    query = malloc(QUERY_ALLOC);
    if (!query) {
      fprintf(stderr, "Out of memory !\n");
      return; /* Drop request */
    }

    query->data = ((char *) query) + sizeof(struct query);
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
      // TODO Look at the cache
      QUEUE_APPEND(&queries, query);
    }
  }

  if (FD_ISSET(server_sfd, write_fds)) {
    queue_walk_safe(&replies, reply, tmp_reply, struct reply *) {
      // TODO Add SRH to reply + change number of DNS_HEADER_SET_ARCOUNT()
      if (sendto(server_sfd, reply->data, reply->data_length, 0,
                 (struct sockaddr *) &reply->addr,
                 reply->addr_len) != (int) reply->data_length) {
        perror("Error forwarding reply"); /* Drop the reply */
      }
      QUEUE_REMOVE(&replies, reply);
      FREE_POINTER(reply);
    }
  }
}

int server_fds(int server_sfd, fd_set *read_fds, fd_set *write_fds) {

  // TODO Block if not enough memory/too much query in processing ???
  FD_SET(server_sfd, read_fds);
  if (!QUEUE_IS_EMPTY(&replies)) {
    FD_SET(server_sfd, write_fds);
  }
  return server_sfd + 1;
}

int init_server(const char *listen_port) {

  int server_sfd = -1;

  struct addrinfo hints;
  struct addrinfo *result, *rp;

  int status = 0;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
  hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
  hints.ai_protocol = 0;          /* Any protocol */
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  status = getaddrinfo(NULL, listen_port, &hints, &result);
  if (status != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    goto out;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    server_sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (server_sfd == -1)
      continue;

    if (bind(server_sfd, rp->ai_addr, rp->ai_addrlen) == 0)
      break;

    CLOSE_FD(server_sfd);
  }

  freeaddrinfo(result);

  if (rp == NULL) {
    fprintf(stderr, "Could not bind\n");
  }

  QUEUE_INIT(&replies);

out:
  return server_sfd;
}

void close_server(int server_sfd) {

  struct reply *reply = NULL;
  struct reply *tmp_reply = NULL;

  queue_walk_safe(&replies, reply, tmp_reply, struct reply *) {
    FREE_POINTER(reply); // data is stored in the same memory region
  }

  CLOSE_FD(server_sfd);
}
