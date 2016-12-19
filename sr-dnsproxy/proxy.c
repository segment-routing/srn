#include <sys/types.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>

#include <ares.h>
#include <ares_dns.h>

#include "proxy.h"

#define T_OPT_OPCODE_APP_NAME 65001
#define T_OPT_OPCODE_BANDWIDTH 65002
#define T_OPT_OPCODE_LATENCY 65003

#define MAX_MAPPING_LENGTH 1024

#define TIMEOUT_LOOP 1 /* (sec) */

struct mapping_qid *mapping [MAX_MAPPING_LENGTH];

volatile sig_atomic_t stop;

void inthand(__attribute__((unused)) int signum) {
    stop = 1;
}

static void add_srh() {
  struct reply *reply = NULL;
  /* TODO Temp: adds the SRH to the reply and forward to the other queue */
  /* TODO It is better to do it with callbacks and a way to check wether something new is available */
  if (!queue_is_empty(&replies)) {
    queue_walk_dequeue(&replies, reply, struct reply *) {
      // TODO Add SRH to reply
      // TODO DNS_HEADER_SET_ARCOUNT(replies->data, DNS_HEADER_ARCOUNT(replies->data) + 1);
      queue_append(&replies_with_srh, (struct node *) reply);
    }
  }
}

static int receive_and_forward_loop(int server_sfd, ares_channel channel) {

  int err = 0;

  int nfds = 0;
  int ares_nfds = 0;
  int server_nfds = 0;

  fd_set read_fds, write_fds;
  struct timeval timeout;

  for (;!stop;) {

    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    timeout.tv_sec = TIMEOUT_LOOP;
    timeout.tv_usec = 0;

    server_nfds = server_fds(server_sfd, &read_fds, &write_fds);
    ares_nfds = ares_fds(channel, &read_fds, &write_fds);
    nfds = (ares_nfds > server_nfds) ? ares_nfds : server_nfds;

    err = select(nfds, &read_fds, &write_fds, NULL, &timeout);
    if (err < 0) {
      perror("Select fail");
      goto out_err;
    }

    server_process(server_sfd, &read_fds, &write_fds);
    client_process(channel, &read_fds, &write_fds);
    add_srh();
  }

out:
  close_server(server_sfd);
  close_client(channel);
  close_monitor();
  return err;
out_err:
  err = -1;
  goto out;
}

int main(int argc, char *argv[]) {

  int err = EXIT_SUCCESS;

  char *listen_port = NULL;
  struct ares_addr_node *servers = NULL;
  char *remote_port = NULL;

  int server_sfd = -1;

  int optmask = ARES_OPT_FLAGS;
  ares_channel channel = NULL;

  if (parse_arguments(argc, argv, &optmask, &listen_port, &remote_port, &servers)) {
    goto out_err;
  }

  /* Setup of the listening socket */
  server_sfd = init_server(listen_port);
  if (server_sfd < 0) {
    goto out_err_free_args;
  }

  /* Setup of the c-ares request library */
  channel = init_client(optmask, servers);
  if (!channel) {
    goto out_err_free_args;
  }

  /* Setup controller monitoring */
  init_monitor();

  /* Get rid of memory allocated for arguments */
  FREE_POINTER(listen_port);
  FREE_POINTER(remote_port);
  destroy_addr_list(servers);
  servers = NULL;

  /* Gracefully kill the program when SIGINT is received */
  signal(SIGINT, inthand);

  /* Do the proxy */
  if (receive_and_forward_loop(server_sfd, channel) == -1) {
    goto out_err;
  }

out:
  exit(err);
out_err_free_args:
  FREE_POINTER(listen_port);
  FREE_POINTER(remote_port);
  destroy_addr_list(servers);
  servers = NULL;
out_err:
  err = EXIT_FAILURE;
  goto out;
}
