#include <stdlib.h>
#include <sys/select.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>

#include <ares.h>

#include "proxy.h"

/* Some of the code was taken from the "adig.c" file in the c-ares library */
int parse_arguments(int argc, char *argv[], int *optmask, char **listen_port, char **remote_port, struct ares_addr_node **servers) {

  int opt = 0;
  int err = 0;
  struct ares_addr_node *srvr = NULL;
  struct hostent *hostent = NULL;

  *listen_port = NULL;
  *remote_port = NULL;
  *servers = NULL;

  while ((opt = getopt(argc, argv, "p:r:q:")) != -1) {
    switch (opt) {
    case 'p':
      if (*listen_port) {
        fprintf(stderr, "The port to listen DNS requests was already specified\n");
        goto out_err;
      }
      *listen_port = malloc(strlen(optarg));
      if (!*listen_port) {
        fprintf(stderr, "Out of memory!\n");
        goto out_err;
      }
      strcpy(*listen_port, optarg);
      break;
    case 'r':
      /* User-specified name servers override default ones. */
      srvr = malloc(sizeof(struct ares_addr_node));
      if (!srvr) {
        fprintf(stderr, "Out of memory!\n");
        goto out_err;
      }
      append_addr_list(servers, srvr);
      if (ares_inet_pton(AF_INET, optarg, &srvr->addr.addr4) > 0)
        srvr->family = AF_INET;
      else if (ares_inet_pton(AF_INET6, optarg, &srvr->addr.addr6) > 0)
        srvr->family = AF_INET6;
      else {
        hostent = gethostbyname(optarg);
        if (!hostent) {
          fprintf(stderr, "adig: server %s not found.\n", optarg);
          goto out_err;
        }
        switch (hostent->h_addrtype) {
          case AF_INET:
            srvr->family = AF_INET;
            memcpy(&srvr->addr.addr4, hostent->h_addr_list[0],
                   sizeof(srvr->addr.addr4));
            break;
          case AF_INET6:
            srvr->family = AF_INET6;
            memcpy(&srvr->addr.addr6, hostent->h_addr_list[0],
                   sizeof(srvr->addr.addr6));
            break;
          default:
            fprintf(stderr, "adig: server %s unsupported address family.\n", optarg);
            goto out_err;
        }
      }
      /* Notice that calling ares_init_options() without servers in the
       * options struct and with ARES_OPT_SERVERS set simultaneously in
       * the options mask, results in an initialization with no servers.
       * When alternative name servers have been specified these are set
       * later calling ares_set_servers() overriding any existing server
       * configuration. To prevent initial configuration with default
       * servers that will be discarded later, ARES_OPT_SERVERS is set.
       * If this flag is not set here the result shall be the same but
       * ares_init_options() will do needless work. */
      *optmask |= ARES_OPT_SERVERS;
      break;
    case 'q':
      if (*remote_port) {
        fprintf(stderr, "The remote port of the DNS servers was already specified\n");
        goto out_err;
      }
      *remote_port = malloc(strlen(optarg));
      if (!*remote_port) {
        fprintf(stderr, "Out of memory !\n");
        goto out_err;
      }
      strcpy(*remote_port, optarg);
      break;
    default: /* '?' */
      fprintf(stderr, "Usage: %s [-p listen_port] [-r dns_server] [-q dns_port]\n", argv[0]);
      goto out_err;
    }
  }

  if (!*remote_port) {
    *remote_port = malloc(3);
    if (!*remote_port) {
      fprintf(stderr, "Out of memory !\n");
      goto out_err;
    }
    strncpy(*remote_port, "53", 3);
  }
  if (!*listen_port) {
    *listen_port = malloc(3);
    if (!*listen_port) {
      fprintf(stderr, "Out of memory !\n");
      goto out_err;
    }
    strncpy(*listen_port, "53", 3);
  }

out:
  return err;
out_err:
  FREE_POINTER(*listen_port);
  FREE_POINTER(*remote_port);
  destroy_addr_list(*servers);
  *servers = NULL;
  err = -1;
  goto out;
}
