#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>

#include <ares.h>

#include "srdns.h"

#ifndef __u8
#define __u8 uint8_t
#endif

struct callback_args {
  char *dest_addr;
  char *src_prefix;
  char *binding_segment;
  int *stop;
};

struct ipv6_sr_hdr {
        __u8    nexthdr;
        __u8    hdrlen;
        __u8    type;
        __u8    segments_left;
        __u8    first_segment;
        __u8    flag_1;
        __u8    flag_2;
        __u8    reserved;

        struct in6_addr segments[0];
};

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

static void plain_callback(void *_arg, int status, __attribute__((unused)) int timeouts, unsigned char *abuf, int alen) {

  struct callback_args *args = (struct callback_args *) _arg;
  struct hostent *host = NULL;
  int *stop = args->stop;

  if (status != ARES_SUCCESS) {
    fprintf(stderr, "DNS server error: %s\n", ares_strerror(status));
    return;
  }

  if (ares_parse_aaaa_reply(abuf, alen, &host, NULL, NULL) != ARES_SUCCESS) {
    fprintf(stderr, "Problem parsing the AAAA record: %s\n", ares_strerror(status));
    return;
  }
  memcpy(args->dest_addr, host->h_addr, 16);
  *stop = 1;
  ares_free_hostent(host);
}

int make_dns_request(const char *destination, const char *servername, char *dest_addr) {
  struct ares_addr_node *srvr = NULL, *servers = NULL;
  ares_channel channel = NULL;
  struct ares_options options;
  memset(&options, 0, sizeof(options));
  int optmask = ARES_OPT_FLAGS, dnsclass = C_IN, type = T_AAAA;
  options.ednspsz = 1280;
  optmask |= ARES_OPT_EDNSPSZ;
  options.flags |= ARES_FLAG_EDNS;

  fd_set read_fds, write_fds;
  int nfds = 0;
  struct timeval *tvp, tv;
  int stop = 0;
  struct callback_args args = {
    .dest_addr = dest_addr,
    .stop = &stop
  };

  int status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
    goto free_server_list;
  }

  if (servername) {
    srvr = malloc(sizeof(struct ares_addr_node));
    if (!srvr) {
      fprintf(stderr, "Out of memory!\n");
      status = -1;
      goto free_cares_lib;
    }
    append_addr_list(&servers, srvr);
    if (ares_inet_pton(AF_INET, servername, &srvr->addr.addr4) > 0)
      srvr->family = AF_INET;
    else if (ares_inet_pton(AF_INET6, servername, &srvr->addr.addr6) > 0)
      srvr->family = AF_INET6;
    else {
      fprintf(stderr, "%s is not an IPv4 nor IPv6 address\n", servername);
      status = -1;
      goto free_cares_lib;
    }
    optmask |= ARES_OPT_SERVERS;
  }

  options.flags |= ARES_FLAG_NOCHECKRESP; /* In order not to ignore REFUSED DNS replies */
  status = ares_init_options(&channel, &options, optmask);
  if (status != ARES_SUCCESS) {
    fprintf(stderr, "ares_init_options: %s\n", ares_strerror(status));
    goto free_cares_lib;
  }
  if (srvr) {
    status = ares_set_servers(channel, servers);
    destroy_addr_list(servers);
    servers = NULL;
    if (status != ARES_SUCCESS) {
      fprintf(stderr, "ares_init_options: %s\n", ares_strerror(status));
      goto free_cares_lib;
    }
  }

  ares_query(channel, destination, dnsclass, type, plain_callback, (char *) &args);

  /* Wait for all queries to complete. */
  for (;!stop;) {
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    nfds = ares_fds(channel, &read_fds, &write_fds);
    if (nfds == 0) {
      fprintf(stderr, "Did not manage to get an answer\n");
      status = -1;
      goto close_channel;
    }
    tvp = ares_timeout(channel, NULL, &tv);
    status = select(nfds, &read_fds, &write_fds, NULL, tvp);
    if (status < 0) {
      fprintf(stderr, "select fail: %d", status);
      goto close_channel;
    }
    ares_process(channel, &read_fds, &write_fds);
  }

close_channel:
  ares_destroy(channel);
free_server_list:
  if (servers)
    destroy_addr_list(servers);
free_cares_lib:
  ares_library_cleanup();
  return status;
}

static void callback(void *_arg, int status, __attribute__((unused)) int timeouts, unsigned char *abuf, int alen) {

  struct callback_args *args = (struct callback_args *) _arg;
  struct ares_srh_reply *srh_out = NULL;
  struct hostent *host = NULL;
  int *stop = args->stop;

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
  if (args->src_prefix) { /* Optional */
    memcpy(args->src_prefix, &srh_out->prefix.addr, 16);
  }
  memcpy(args->binding_segment, &srh_out->binding_segment, 16);

  *stop = 1;

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

  struct ares_addr_node *srvr = NULL, *servers = NULL;
  ares_channel channel = NULL;
  struct ares_options options;
  memset(&options, 0, sizeof(options));
  int optmask = ARES_OPT_FLAGS, dnsclass = C_IN, type = T_AAAA;
  options.ednspsz = 1280;
  optmask |= ARES_OPT_EDNSPSZ;
  options.flags |= ARES_FLAG_EDNS;

  fd_set read_fds, write_fds;
  int nfds = 0;
  struct timeval *tvp, tv;
  int stop = 0;
  struct callback_args args = {
    .dest_addr = dest_addr,
    .src_prefix = src_prefix,
    .binding_segment = binding_segment,
    .stop = &stop
  };

  bandwidth = htonl(bandwidth);
  latency = htonl(latency);

  int status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
    goto free_server_list;
  }

  if (servername) {
    srvr = malloc(sizeof(struct ares_addr_node));
    if (!srvr) {
      fprintf(stderr, "Out of memory!\n");
      status = -1;
      goto free_cares_lib;
    }
    append_addr_list(&servers, srvr);
    if (ares_inet_pton(AF_INET, servername, &srvr->addr.addr4) > 0)
      srvr->family = AF_INET;
    else if (ares_inet_pton(AF_INET6, servername, &srvr->addr.addr6) > 0)
      srvr->family = AF_INET6;
    else {
      fprintf(stderr, "%s is not an IPv4 nor IPv6 address\n", servername);
      status = -1;
      goto free_cares_lib;
    }
    optmask |= ARES_OPT_SERVERS;
  }

  status = ares_init_options(&channel, &options, optmask);
  if (status != ARES_SUCCESS) {
    fprintf(stderr, "ares_init_options: %s\n", ares_strerror(status));
    goto free_cares_lib;
  }
  if (srvr) {
    status = ares_set_servers(channel, servers);
    destroy_addr_list(servers);
    servers = NULL;
    if (status != ARES_SUCCESS) {
      fprintf(stderr, "ares_init_options: %s\n", ares_strerror(status));
      goto free_cares_lib;
    }
  }

  ares_edns_query(channel, destination, dnsclass, type,
                  edns_options, callback, (char *) &args);

  /* Wait for all queries to complete. */
  for (;!stop;) {
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    nfds = ares_fds(channel, &read_fds, &write_fds);
    if (nfds == 0) {
      fprintf(stderr, "Did not manage to get an answer\n");
      status = -1;
      goto close_channel;
    }
    tvp = ares_timeout(channel, NULL, &tv);
    status = select(nfds, &read_fds, &write_fds, NULL, tvp);
    if (status < 0) {
      fprintf(stderr, "select fail: %d", status);
      goto close_channel;
    }
    ares_process(channel, &read_fds, &write_fds);
  }

close_channel:
  ares_destroy(channel);
free_server_list:
  if (servers)
    destroy_addr_list(servers);
free_cares_lib:
  ares_library_cleanup();
  return status;
}

/* Creates a socket */
int sr_socket(int type, int proto, const char *dest, short dest_port,
              const char *dns_servername, char *application_name,
              uint32_t bandwidth, uint32_t latency) {

  int fd = 0, err = 0, srh_len = 0;
  struct ipv6_sr_hdr *srh = NULL;
  struct sockaddr_in6 sin6;
  memset(&sin6, 0, sizeof(sin6));

  srh_len = sizeof(*srh) + 2 * sizeof(struct in6_addr);
  srh = malloc(srh_len);
  if (!srh) {
    fprintf(stderr, "Out of memory\n");
    err = -1;
    goto out;
  }

  srh->nexthdr = 0;
  srh->hdrlen = 4;
  srh->type = 4;
  srh->segments_left = 1;
  srh->first_segment = 1;
  srh->flag_1 = 0;
  srh->flag_2 = 0;
  srh->reserved = 0;
  memset(&srh->segments[0], 0, sizeof(struct in6_addr));
  memset(&srh->segments[1], 0, sizeof(struct in6_addr));

  fd = socket(AF_INET6, type, proto);
  if (fd < 0) {
    perror("sr_socket - socket");
    err = fd;
    goto free_srh;
  }

  /* DNS request to the controller */
  err = make_srdns_request(dest, dns_servername, application_name, bandwidth,
                           latency, (char *) &sin6.sin6_addr, NULL,
                           (char *) &srh->segments[1]);
  if (err < 0) {
    fprintf(stderr, "DNS request failed\n");
    goto close_socket;
  }

  err = setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, srh, srh_len);
  if (err < 0) {
    perror("sr_socket - setsockopt");
    goto close_socket;
  }

  // TODO Bind to address matching the prefix returned by the controller

  sin6.sin6_family = AF_INET6;
  sin6.sin6_port = htons(dest_port);
  err = connect(fd, (struct sockaddr *)&sin6, sizeof(sin6));
  if (err < 0) {
    perror("sr_socket - connect");
    goto close_socket;
  }

  return fd;

close_socket:
  close(fd);
free_srh:
  free(srh);
out:
  return err;
}
