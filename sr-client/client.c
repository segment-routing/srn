#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/types.h>
#include <errno.h>

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
  int err = 0;

  FILE *logs = conf.logs;
  int probe = *((int *) _arg);
  if (probe) {
    if (clock_gettime(CLOCK_MONOTONIC, &start)) {
      perror("Cannot get start time");
      goto out;
    }
  }

  if (conf.regular_dns)
    err = test_regular_dns_only(conf.destination,
                                conf.custom_dns_servername ? conf.dns_servername : NULL);
  else if (conf.only_requests)
    err = test_dns_only(conf.destination,
                        conf.custom_dns_servername ? conf.dns_servername : NULL);
  else
    err = test_srdns(conf.destination, conf.destination_port,
                     conf.custom_dns_servername ? conf.dns_servername : NULL);

  if (probe) {
    if (clock_gettime(CLOCK_MONOTONIC, &end)) {
      perror("Cannot get end time");
      goto out;
    }
    pthread_mutex_lock(&conf.mutex);
    fprintf(logs, "%s%ld.%ld -> %ld.%ld\n", err < 0 ? "FAILURE: " : "",
            start.tv_sec, start.tv_nsec, end.tv_sec, end.tv_nsec);
    fflush(logs);
    pthread_mutex_unlock(&conf.mutex);
  }

out:
  return NULL;
}

int main(int argc, char * const argv[])
{
  int i = 0, status = -1;
  char directories [STR_LEN + 1];
  char parent_directory [STR_LEN + 1];
  char file_path [STR_LEN + 1];
  if (parse_args(argc, argv, &conf)) {
      fprintf(stderr, "Usage: %s dst port [-CDr] [-S output_file_suffix] [-s servername] [-n number_req] [-R request_rate] [-p probe_rate] \n", argv[0]);
      return -1;
  }

  /* Path and file creation */

  time_t timer;
  struct tm* tm_info;
  char day[3];
  char month[3];
  time(&timer);
  tm_info = localtime(&timer);
  strftime(day, 3, "%d", tm_info);
  strftime(month, 3, "%m", tm_info);

  snprintf(directories, STR_LEN + 1, "%s_%s/%s/%ldreqs_%.3frate_%ldprobes", day, month,
           conf.regular_dns ? "DNS" : (conf.no_cache ? "srdns_no_cache" : "srdns"),
           conf.number_req, conf.request_rate, conf.probe_rate);
  if (mkpath(directories, 0777)) {
    perror("Problem creating directories on the path");
    return -1;
  }
  for (i = 0; status; i++) {
    snprintf(parent_directory, STR_LEN + 1, "%s/launch_%d", directories, i);
    status = mkdir(parent_directory, 0777);
    if (status && errno != EEXIST) {
      perror("Problem creating parent directory");
      return -1;
    }
  }

  pthread_t *thread = (pthread_t *) malloc(sizeof(*thread)*conf.number_req);
  if (!thread) {
    fprintf(stderr, "Out of memory\n");
    return -1;
  }

  int *probe = malloc(sizeof(*probe)*conf.number_req);
  if (!probe) {
    fprintf(stderr, "Out of memory\n");
    free(thread);
    return -1;
  }

  if (pthread_mutex_init(&conf.mutex, NULL) != 0)
  {
      fprintf(stderr, "\n mutex init failed\n");
      free(thread);
      free(probe);
      return -1;
  }

  /* Convert request rate to sleep time between each request */
  struct timespec sleep_time = {.tv_sec = (long) (1 / conf.request_rate),
                                .tv_nsec = (long) (1000000000 / conf.request_rate)};
  sleep_time.tv_nsec = sleep_time.tv_nsec - sleep_time.tv_sec * 1000000000;

  snprintf(file_path, STR_LEN + 1, "%s/latencies_%s.log", parent_directory,
           conf.custom_file_suffix ? conf.file_suffix : "");
  conf.logs = fopen(file_path, "w");
  if (!conf.logs) {
    perror("File couldn't be openned");
    free(thread);
    free(probe);
    return -1;
  }

  for (i = 0; i < conf.number_req; i++) {
    // If the probe is to be taken every 5 measures, start by the probe
    probe[i] = !((i - 1 + (100 / conf.probe_rate)) % (100 / conf.probe_rate));
    pthread_create(&thread[i], NULL, &main_client_thread, &probe[i]);
    if (nanosleep(&sleep_time, NULL)) {
      perror("Cannot sleep");
    }
  }

  for (i=0; i < conf.number_req; i++) {
    pthread_join(thread[i], NULL);
  }

  pthread_mutex_destroy(&conf.mutex);
  fclose(conf.logs);
  free(thread);
  free(probe);
  return 0;
}
