#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>

#include "client.h"

struct client_conf conf;

static int test_srdns(const char *dst, short port, const char *dns_servername)
{
  static char buf[] = "Hello with Segment Routing :)\n";
  int fd = sr_socket(SOCK_STREAM, IPPROTO_TCP, dst, port, dns_servername,
                     "accessA", 5, 5);
  if (fd < 0) {
    fprintf(stderr, "Cannot create socket\n");
    return -1;
  }

  int err = send(fd, buf, sizeof(buf), 0);
  if (err < 0) {
    perror("send");
    close(fd);
    return -1;
  }

  close(fd);
  return 0;
}

static int test_dns_only(const char *dst, const char *dns_servername)
{
  struct in6_addr *dest_addr = malloc(2*sizeof(*dest_addr));
  if (!dest_addr) {
    fprintf(stderr, "Out of memory\n");
    return -1;
  }
  struct in6_addr *binding_segment = dest_addr + 1;

  int err = make_srdns_request(dst, dns_servername, "accessA", 5, 5,
                               (char *) dest_addr, NULL,
                               (char *) binding_segment);
  if (err < 0) {
    fprintf(stderr, "Request failed\n");
  }
  free(dest_addr);
  return err;
}

static int test_regular_dns_only(const char *dst, const char *dns_servername)
{
  struct in6_addr *dest_addr = malloc(sizeof(*dest_addr));
  if (!dest_addr) {
    fprintf(stderr, "Out of memory\n");
    return -1;
  }

  int err = make_dns_request(dst, dns_servername, (char *) dest_addr);
  if (err < 0) {
    fprintf(stderr, "Request failed\n");
  }
  free(dest_addr);
  return err;
}

static void *main_client_thread(void *_arg)
{
  struct timespec start;
  struct timespec end;
  struct timespec sleep_time = {.tv_sec = 0, .tv_nsec = 100000000};

  FILE *logs = _arg; /* Logs stream for this thread */

  pthread_mutex_lock(&conf.mutex);
  for(conf.number_req--; conf.number_req >= 0; conf.number_req--) {
    pthread_mutex_unlock(&conf.mutex);

    int r = rand() % 100;
    if (r < conf.probe_rate) {
      if (clock_gettime(CLOCK_MONOTONIC, &start)) {
        perror("Cannot get start time");
        goto out;
      }
    }

    if (conf.regular_dns)
      test_regular_dns_only(conf.destination,
                            conf.custom_dns_servername ? conf.dns_servername : NULL);
    else if (conf.only_requests)
      test_dns_only(conf.destination,
                    conf.custom_dns_servername ? conf.dns_servername : NULL);
    else
      test_srdns(conf.destination, conf.destination_port,
                 conf.custom_dns_servername ? conf.dns_servername : NULL);

    if (r < conf.probe_rate) {
      if (clock_gettime(CLOCK_MONOTONIC, &end)) {
        perror("Cannot get end time");
        goto out;
      }
      // TODO Change format to avoid floating point issues
      fprintf(logs, "%ld.%ld -> %ld.%ld \n", start.tv_sec, start.tv_nsec, end.tv_sec, end.tv_nsec);
    }

    if (nanosleep(&sleep_time, NULL)) {
      perror("Cannot sleep");
    }

    pthread_mutex_lock(&conf.mutex);
  };
  pthread_mutex_unlock(&conf.mutex);

out:
  fclose(logs);
  return NULL;
}

int main(int argc, char * const argv[])
{
  int i = 0;
  char file_path [STR_LEN + 1];
  if (parse_args(argc, argv, &conf)) {
      fprintf(stderr, "Usage: %s dst port [-Dr] [-s servername] [-n number_req] [-N number_parallel_req] [-p probe_rate] \n", argv[0]);
      return -1;
  }

  pthread_t *thread = (pthread_t *) malloc(sizeof(*thread)*conf.number_parallel_req);
  if (!thread) {
    fprintf(stderr, "Out of memory\n");
    return -1;
  }

  if (pthread_mutex_init(&conf.mutex, NULL) != 0)
  {
      fprintf(stderr, "\n mutex init failed\n");
      free(thread);
      return -1;
  }

  for (i = 0; i < conf.number_parallel_req; i++) {
    snprintf(file_path, STR_LEN + 1, "latency_log_%d", i);
    FILE *logs = fopen(file_path, "w");
    if (!logs) {
      perror("File couldn't be openned => thread not launched");
      continue;
    }
    pthread_create(&thread[i], NULL, &main_client_thread, logs);
  }

  for (i=0; i < conf.number_parallel_req; i++) {
    pthread_join(thread[i], NULL);
  }

  pthread_mutex_destroy(&conf.mutex);

  free(thread);
  return 0;
}
