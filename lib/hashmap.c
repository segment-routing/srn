#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "hashmap.h"

struct hashmap *hmap_new(unsigned int (*hash)(void *key),
			 int (*compare)(void *k1, void *k2))
{
	struct hashmap *hm;
	unsigned int i;

	hm = malloc(sizeof(*hm));
	if (!hm)
		return NULL;

	hm->size = HASHMAP_DEFAULT_SIZE;
	hm->elems = 0;

	hm->map = malloc(hm->size * sizeof(struct llist_head));
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
	return hm->hash(key) & (hm->size - 1);
}

static bool hmap_must_grow(struct hashmap *hm)
{
	return hm->elems > (hm->size / 4 * 3);
}

static int hmap_grow(struct hashmap *hm, size_t nsize)
{
	struct llist_head *new_map;
	struct hmap_entry *he;
	unsigned int idx, i;

	new_map = malloc(nsize * sizeof(struct llist_head));
	if (!new_map)
		return -1;

	for (i = 0; i < nsize; i++)
		llist_init(&new_map[i]);

	hm->size = nsize;

	llist_foreach(&hm->keys, he, key_head) {
		llist_remove(&he->map_head);
		idx = hmap_hash(hm, he->key);
		llist_insert_tail(&new_map[idx], &he->map_head);
	}

	free(hm->map);
	hm->map = new_map;

	return 0;
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

	if (hmap_must_grow(hm)) {
		if (hmap_grow(hm, hm->size * 2) < 0)
			return -1;

		idx = hmap_hash(hm, key);
	}

	he = malloc(sizeof(*he));
	if (!he)
		return -1;

	he->key = key;
	he->elem = elem;

	llist_insert_tail(&hm->map[idx], &he->map_head);
	llist_insert_tail(&hm->keys, &he->key_head);

	hm->elems++;

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
			hm->elems--;
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
		hm->elems--;
		free(he);
	}
}
