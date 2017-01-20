#include <pthread.h>

#include <stdint.h>
#include <srdns.h>

#define STR_LEN 255

struct client_conf {
  pthread_mutex_t mutex;
  int only_requests;
  long number_req;
  long number_parallel_req;
  long probe_rate;

  int custom_dns_servername;
  char dns_servername [STR_LEN + 1];

  char destination [STR_LEN + 1];
  short destination_port;

  int regular_dns;
};

int parse_args(int argc, char * const argv[], struct client_conf *conf);
