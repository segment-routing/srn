#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>

#include "srdns.h"

struct callback_args {
  char *dest_addr;
  char *src_prefix;
  char *binding_segment;
};

#define C_IN 1
#define T_AAAA 28

static void destroy_addr_list(struct ares_addr_node *head)
{
  while(head)
    {
      struct ares_addr_node *detached = head;
      head = head->next;
      free(detached);
    }
}

static void append_addr_list(struct ares_addr_node **head,
                             struct ares_addr_node *node)
{
  struct ares_addr_node *last;
  node->next = NULL;
  if(*head)
    {
      last = *head;
      while(last->next)
        last = last->next;
      last->next = node;
    }
  else
    *head = node;
}

static void callback(void *_arg, int status, __attribute__((unused)) int timeouts, unsigned char *abuf, int alen) {

  struct callback_args *args = (struct callback_args *) _arg;
  struct ares_srh_reply *srh_out = NULL;
  struct hostent *host = NULL; // TODO free

  if (status != ARES_SUCCESS) {
    fprintf(stderr, "DNS server error: %s\n", ares_strerror(status));
    return;
  }

  if (ares_parse_aaaa_reply(abuf, alen, &host, NULL, NULL) != ARES_SUCCESS) {
    fprintf(stderr, "Problem parsing the AAAA record: %s\n", ares_strerror(status));
    return;
  }
  memcpy(args->dest_addr, host->h_addr, 16);

  if (ares_parse_srh_reply(abuf, alen, &srh_out) != ARES_SUCCESS) {
    fprintf(stderr, "Problem parsing the SRH record: %s\n", ares_strerror(status));
    goto free_aaaa;
  }
  memcpy(args->src_prefix, &srh_out->prefix.addr, 16);
  memcpy(args->binding_segment, &srh_out->binding_segment, 16);

  ares_free_data(srh_out);
free_aaaa:
  ares_free_hostent(host);
}

int make_srdns_request(const char *destination, const char *servername, char *application_name,
                       uint32_t bandwidth, uint32_t latency,
                       char *dest_addr, char *src_prefix, char *binding_segment) {

  struct edns_option application_name_opt = {
    .option_code = T_OPT_OPCODE_APP_NAME,
    .option_length = strlen(application_name),
    .option_data = application_name
  };
  struct edns_option bandwidth_opt = {
    .option_code = T_OPT_OPCODE_BANDWIDTH,
    .option_length = sizeof(bandwidth),
    .option_data = &bandwidth
  };
  struct edns_option latency_opt = {
    .option_code = T_OPT_OPCODE_LATENCY,
    .option_length = sizeof(latency),
    .option_data = &latency
  };
  struct edns_option *edns_options [4] = {&application_name_opt, &bandwidth_opt, &latency_opt, NULL};

  struct ares_addr_node *srvr, *servers = NULL;
  ares_channel channel = NULL;
  struct ares_options options;
  int optmask = ARES_OPT_FLAGS, dnsclass = C_IN, type = T_AAAA;
  options.ednspsz = 1280;
  optmask |= ARES_OPT_EDNSPSZ;
  options.flags |= ARES_FLAG_EDNS;

  fd_set read_fds, write_fds;
  int nfds = 0;
  struct timeval *tvp, tv;
  struct callback_args args = {
    .dest_addr = dest_addr,
    .src_prefix = src_prefix,
    .binding_segment = binding_segment
  };

  int status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
    return -1;
  }

  if (servername) {
    srvr = malloc(sizeof(struct ares_addr_node));
    if (!srvr) {
      fprintf(stderr, "Out of memory!\n");
      destroy_addr_list(servers);
      return -1;
    }
    append_addr_list(&servers, srvr);
    if (ares_inet_pton(AF_INET, servername, &srvr->addr.addr4) > 0)
      srvr->family = AF_INET;
    else if (ares_inet_pton(AF_INET6, servername, &srvr->addr.addr6) > 0)
      srvr->family = AF_INET6;
    else {
      fprintf(stderr, "%s is not an IPv4 nor IPv6 address\n", servername);
      destroy_addr_list(servers);
      return -1;
    }
    optmask |= ARES_OPT_SERVERS;
  }

  status = ares_init_options(&channel, &options, optmask);
  if (status != ARES_SUCCESS) {
    fprintf(stderr, "ares_init_options: %s\n",
            ares_strerror(status));
    return 1;
  }
  if (srvr) {
    status = ares_set_servers(channel, servers);
    destroy_addr_list(servers);
    if (status != ARES_SUCCESS) {
      fprintf(stderr, "ares_init_options: %s\n", ares_strerror(status));
      return 1;
    }
  }

  ares_edns_query(channel, destination, dnsclass, type,
                  edns_options, callback, (char *) &args);

  /* Wait for all queries to complete. */
  for (;;) {
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    nfds = ares_fds(channel, &read_fds, &write_fds);
    if (nfds == 0)
      break;
    tvp = ares_timeout(channel, NULL, &tv);
    status = select(nfds, &read_fds, &write_fds, NULL, tvp);
    if (status < 0) {
      printf("select fail: %d", status);
      return 1;
    }
    ares_process(channel, &read_fds, &write_fds);
  }

  ares_destroy(channel);

  ares_library_cleanup();
  return 0;
}
