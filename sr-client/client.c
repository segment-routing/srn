#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <srdns.h>


int test_srdns(const char *dst, short port, const char *dns_servername)
{
  static char buf[] = "Hello with Segment Routing :)\n";
  int fd = sr_socket(SOCK_STREAM, IPPROTO_TCP, dst, port, dns_servername,
                     "test.com", 5, 5);
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

int main(int ac, char **av)
{
    if (ac < 4) {
        fprintf(stderr, "Usage: %s dst port servername\n", av[0]);
        return -1;
    }

    return test_srdns(av[1], atoi(av[2]), av[3]);
}
