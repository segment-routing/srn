#ifndef _HASHMAP_H
#define _HASHMAP_H

#include "arraylist.h"

#define HASHMAP_SIZE	5003

struct hmap_entry {
	void *key;
	void *elem;
};

struct hashmap {
	int size;
	struct arraylist **map;
	struct arraylist *keys;
	unsigned int (*hash)(void *key);
	int (*compare)(void *k1, void *k2);
};

struct hashmap *hmap_new(unsigned int (*hash)(void *key),
			 int (*compare)(void *k1, void *k2));
void hmap_destroy(struct hashmap *hm);
int hmap_hash(struct hashmap *hm, void *key);
int hmap_set(struct hashmap *hm, void *key, void *elem);
void *hmap_get(struct hashmap *hm, void *key);
int hmap_delete(struct hashmap *hm, void *key);
bool hmap_key_exist(struct hashmap *hm, void *key);
void hmap_flush(struct hashmap *hm);

#endif
