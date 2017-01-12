#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "client.h"

int parse_args(int argc, char * const argv[], struct client_conf *conf)
{
  int c;
  char *ptr = NULL;

  memset(conf, 0, sizeof(*conf));
  conf->number_req = 1;
  conf->number_parallel_req = 1;
  while ((c = getopt(argc, argv, "s:rn:p:N:")) != -1) {
    switch (c) {
    case 's':
      conf->custom_dns_servername = 1;
      strncpy(conf->dns_servername, optarg, STR_LEN + 1);
      break;
    case 'r':
      conf->only_requests = 1;
      break;
    case 'n':
      conf->number_req = strtol(optarg, &ptr, 10);
      if (*ptr != '\0' || conf->number_req < 0) {
        fprintf(stderr, "Invalid number of requests given\n");
        return -1;
      }
      break;
    case 'p':
      conf->probe_rate = strtol(optarg, &ptr, 10);
      if (*ptr != '\0' || conf->probe_rate < 0 || conf->probe_rate > 100) {
        fprintf(stderr, "Invalid probe rate given\n");
        return -1;
      }
      break;
    case 'N':
      conf->number_parallel_req = strtol(optarg, &ptr, 10);
      if (*ptr != '\0' || conf->number_parallel_req < 0) {
        fprintf(stderr, "Invalid number of parallel requests given\n");
        return -1;
      }
      break;
    case '?':
      if (optopt == 's' || optopt == 'n' || optopt == 'p' || optopt == 'N')
        fprintf(stderr, "Option -%c requires an argument.\n", optopt);
      else
        fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
    default:
      return -1;
    }
  }

  if (argc - optind < 2) {
    fprintf(stderr, "The destination and its port are not given\n");
    return -1;
  }

  strncpy(conf->destination, argv[optind], STR_LEN + 1);
  conf->destination_port = (short) strtol(argv[optind + 1], &ptr, 10);
  if (*ptr != '\0' || conf->destination_port < 0) {
    fprintf(stderr, "Invalid port number given\n");
    return -1;
  }

  return 0;
}
