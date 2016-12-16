#ifndef _MISC_H
#define _MISC_H

#include <sys/syscall.h>
#include <linux/random.h>

#define __unused __attribute__((unused))
#define pr_err(arg, ...) { fprintf(stderr, "%s: " arg "\n", __func__, ##__VA_ARGS__); }

void strip_crlf(char *line);
void remove_trail(char *line);
char **strsplit(char *line, int *elems, char splitc);
void *memdup(void *from, size_t size);

static inline unsigned int hashint(unsigned int x) {
	x = ((x >> 16) ^ x) * 0x45d9f3b;
	x = ((x >> 16) ^ x) * 0x45d9f3b;
	x = (x >> 16) ^ x;
	return x;
}

static inline int get_random_bytes(void *buf, size_t buflen)
{
	return syscall(SYS_getrandom, buf, buflen, 0);
}

#endif
