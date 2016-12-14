#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "arraylist.h"

struct arraylist *alist_new(size_t elem_size)
{
	struct arraylist *al;

	al = malloc(sizeof(*al));
	if (!al)
		return NULL;

	memset(al, 0, sizeof(*al));
	al->elem_size = elem_size;

	al->data = malloc(ARRAYLIST_INIT_BUF*elem_size);
	if (!al->data) {
		free(al);
		return NULL;
	}
	al->buffer_size = ARRAYLIST_INIT_BUF;

	return al;
}

int alist_insert_at(struct arraylist *al, void *elem, unsigned int idx)
{
	if (al->elem_count == al->buffer_size) {
		void *data2;
		data2 = realloc(al->data, al->buffer_size*al->elem_size*2);
		if (!data2)
			return -1;

		al->data = data2;
		al->buffer_size *= 2;
	}

	memmove(ALIST_ELEM(al, idx + 1), ALIST_ELEM(al, idx), (al->elem_count - idx) * al->elem_size);
	memcpy(ALIST_ELEM(al, idx), elem, al->elem_size);
	al->elem_count++;

	return idx;
}

int alist_insert(struct arraylist *al, void *elem)
{
	return alist_insert_at(al, elem, al->elem_count);
}

void alist_remove(struct arraylist *al, unsigned int idx)
{
	assert(idx < al->elem_count);

	memmove(ALIST_ELEM(al, idx), ALIST_ELEM(al, idx + 1), (al->elem_count - idx - 1) * al->elem_size);
	al->elem_count--;
}

void *alist_elem(struct arraylist *al, unsigned int idx)
{
	if (idx >= al->elem_count)
		return NULL;

	return al->data + idx * al->elem_size;
}

int alist_get(struct arraylist *al, unsigned int idx, void *buf)
{
	if (idx >= al->elem_count)
		return -1;

	memcpy(buf, al->data + idx * al->elem_size, al->elem_size);

	return 0;
}

void alist_destroy(struct arraylist *al)
{
	if (!al)
		return;

	free(al->data);
	free(al);
}

void alist_append(struct arraylist *dst, struct arraylist *src)
{
	unsigned int i;

	for (i = 0; i < src->elem_count; i++)
		alist_insert(dst, alist_elem(src, i));
}

struct arraylist *alist_copy(struct arraylist *al)
{
	struct arraylist *acopy;

	acopy = alist_new(al->elem_size);
	if (!acopy)
		return NULL;

	alist_append(acopy, al);

	return acopy;
}

struct arraylist *alist_copy_reverse(struct arraylist *al)
{
	struct arraylist *acopy;
	unsigned int i;

	acopy = alist_new(al->elem_size);
	if (!acopy)
		return NULL;

	for (i = 0; i < al->elem_count; i++)
		alist_insert(acopy, alist_elem(al, al->elem_count - 1 - i));

	return acopy;
}

bool alist_exist(struct arraylist *al, void *elem)
{
	unsigned int i;

	for (i = 0; i < al->elem_count; i++) {
		if (memcmp(alist_elem(al, i), elem, al->elem_size) == 0)
			return true;
	}

	return false;
}

void alist_flush(struct arraylist *al)
{
	while (al->elem_count)
		alist_remove(al, al->elem_count - 1);
}
