#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

void strip_crlf(char *line)
{
	char *s;

	s = strchr(line, '\n');
	if (s)
		*s = 0;

	s = strchr(line, '\r');
	if (s)
		*s = 0;
}

void remove_trail(char *line)
{
	char *s;

	if (!line || !*line)
		return;

	for (s = line; *(s+1); s++);

	while (*s == ' ')
		*s-- = 0;
}

char **strsplit(char *line, int *elems, char splitc)
{
	int i, n = 0;
	char **vargs;
	char *s;

	remove_trail(line);

	for (s = line; *s; s++) {
		if (*s == splitc)
			n++;
	}

	n++;

	vargs = malloc((n + 1) * sizeof(char *));
	if (!vargs)
		return NULL;

	vargs[n] = NULL;

	s = line;
	for (i = 0; i < n; i++) {
		vargs[i] = s;
		s = strchr(s, splitc);
		if (s)
			*s++ = 0;
	}

	if (elems)
		*elems = n;

	return vargs;
}

void *memdup(void *from, size_t size)
{
	void *res;

	res = malloc(size);
	if (!res)
		return NULL;

	memcpy(res, from, size);
	return res;
}
