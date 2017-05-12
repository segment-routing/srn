#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "hashmap.h"

struct hashmap *hmap_new(unsigned int (*hash)(void *key),
			 int (*compare)(void *k1, void *k2))
{
	struct hashmap *hm;
	int i;

	hm = calloc(1, sizeof(*hm));
	if (!hm)
		return NULL;

	hm->size = HASHMAP_SIZE;

	hm->map = calloc(hm->size, sizeof(struct llist_head));
	if (!hm->map) {
		free(hm);
		return NULL;
	}

	for (i = 0; i < hm->size; i++)
		llist_init(&hm->map[i]);

	llist_init(&hm->keys);

	hm->hash = hash;
	hm->compare = compare;

	pthread_rwlock_init(&hm->lock, NULL);

	return hm;
}

void hmap_destroy(struct hashmap *hm)
{
	pthread_rwlock_destroy(&hm->lock);

	hmap_flush(hm);
	free(hm->map);
	free(hm);
}

int hmap_hash(struct hashmap *hm, void *key)
{
	return hm->hash(key) % hm->size;
}

int hmap_set(struct hashmap *hm, void *key, void *elem)
{
	struct hmap_entry *he;
	unsigned int idx;

	idx = hmap_hash(hm, key);

	/* look for existing entry and overwrite */
	llist_foreach(&hm->map[idx], he, map_head) {
		if (hm->compare(he->key, key) == 0) {
			he->elem = elem;
			return 0;
		}
	}

	he = malloc(sizeof(*he));
	if (!he)
		return -1;

	he->key = key;
	he->elem = elem;

	llist_insert_tail(&hm->map[idx], &he->map_head);
	llist_insert_tail(&hm->keys, &he->key_head);

	return 0;
}

void *hmap_get(struct hashmap *hm, void *key)
{
	struct hmap_entry *he;
	unsigned int idx;

	idx = hmap_hash(hm, key);

	llist_foreach(&hm->map[idx], he, map_head) {
		if (hm->compare(he->key, key) == 0)
			return he->elem;
	}

	return NULL;
}

void hmap_delete(struct hashmap *hm, void *key)
{
	struct hmap_entry *he;
	unsigned int idx;

	idx = hmap_hash(hm, key);

	llist_foreach(&hm->map[idx], he, map_head) {
		if (hm->compare(he->key, key) == 0) {
			llist_remove(&he->map_head);
			llist_remove(&he->key_head);
			free(he);
			return;
		}
	}
}

void hmap_flush(struct hashmap *hm)
{
	struct hmap_entry *he;

	while (!llist_empty(&hm->keys)) {
		he = llist_first_entry(&hm->keys, struct hmap_entry, key_head);
		llist_remove(&he->key_head);
		llist_remove(&he->map_head);
		free(he);
	}
}
