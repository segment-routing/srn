#include <pthread.h>
#include <sys/stat.h>

#include <stdint.h>
#include <srdns.h>

#define STR_LEN 255

struct client_conf {
  pthread_mutex_t mutex;
  int only_requests;
  long number_req;
  long probe_rate;
  double request_rate; // in req/s

  int custom_dns_servername;
  char dns_servername [STR_LEN + 1];

  char destination [STR_LEN + 1];
  short destination_port;

  int regular_dns;
  int no_cache;

  int custom_file_suffix;
  char file_suffix [STR_LEN + 1];

  FILE *logs;
};

int mkpath(const char *path, mode_t mode);
int parse_args(int argc, char * const argv[], struct client_conf *conf);
