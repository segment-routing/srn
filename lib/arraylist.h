#ifndef _ARRAYLIST_H
#define _ARRAYLIST_H

#include <stdbool.h>

#define ARRAYLIST_INIT_BUF  32

#define ALIST_ELEM(a, i) ((a)->data + (i) * (a)->elem_size)

struct arraylist {
	void *data;
	size_t elem_size;
	int elem_count;
	int buffer_size;
};

struct arraylist *alist_new(size_t elem_size);
int alist_insert(struct arraylist *al, void *elem);
void alist_remove(struct arraylist *al, int idx);
void *alist_elem(struct arraylist *al, int idx);
int alist_get(struct arraylist *al, int idx, void *buf);
void alist_destroy(struct arraylist *al);
struct arraylist *alist_copy(struct arraylist *al);
struct arraylist *alist_copy_reverse(struct arraylist *al);
bool alist_exist(struct arraylist *al, void *elem);
int alist_insert_at(struct arraylist *al, void *elem, int idx);
void alist_append(struct arraylist *dst, struct arraylist *src);

#endif
