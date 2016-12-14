#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "hashmap.h"

struct hashmap *hmap_new(unsigned int (*hash)(void *key),
			 int (*compare)(void *k1, void *k2))
{
	struct hashmap *hm;

	hm = malloc(sizeof(*hm));
	if (!hm)
		return NULL;

	hm->size = HASHMAP_SIZE;
	hm->map = malloc(HASHMAP_SIZE*sizeof(struct arraylist *));
	memset(hm->map, 0, HASHMAP_SIZE*sizeof(struct arraylist *));
	hm->hash = hash;
	hm->compare = compare;
	hm->keys = alist_new(sizeof(void *));

	return hm;
}

void hmap_destroy(struct hashmap *hm)
{
	hmap_flush(hm);
	alist_destroy(hm->keys);
	free(hm->map);
	free(hm);
}

int hmap_hash(struct hashmap *hm, void *key)
{
	return hm->hash(key) % hm->size;
}

bool hmap_key_exist(struct hashmap *hm, void *key)
{
	struct key *k;
	unsigned int i;

	for (i = 0; i < hm->keys->elem_count; i++) {
		alist_get(hm->keys, i, &k);
		if (hm->compare(k, key) == 0)
			return true;
	}

	return false;
}

int hmap_set(struct hashmap *hm, void *key, void *elem)
{
	int idx;
	struct hmap_entry he;

	idx = hmap_hash(hm, key);

	if (hmap_key_exist(hm, key))
		hmap_delete(hm, key);

	if (hm->map[idx] == NULL) {
		hm->map[idx] = alist_new(sizeof(struct hmap_entry));
		if (!hm->map[idx])
			return -1;
	}

	he.key = key;
	he.elem = elem;

	alist_insert(hm->map[idx], &he);
	alist_insert(hm->keys, &key);

	return 0;
}

void *hmap_get(struct hashmap *hm, void *key)
{
	unsigned int i, idx;

	idx = hmap_hash(hm, key);
	if (hm->map[idx] == NULL)
		return NULL;

	for (i = 0; i < hm->map[idx]->elem_count; i++) {
		struct hmap_entry *he = alist_elem(hm->map[idx], i);

		if (hm->compare(key, he->key) == 0)
			return he->elem;
	}

	return NULL;
}

int hmap_delete(struct hashmap *hm, void *key)
{
	unsigned int i, idx;

	if (!alist_exist(hm->keys, &key))
		return -1;

	idx = hmap_hash(hm, key);
	if (hm->map[idx] == NULL)
		return -1;

	for (i = 0; i < hm->map[idx]->elem_count; i++) {
		struct hmap_entry *he = alist_elem(hm->map[idx], i);

		if (hm->compare(key, he->key) == 0) {
			alist_remove(hm->map[idx], i);
			break;
		}
	}

	if (!hm->map[idx]->elem_count) {
		alist_destroy(hm->map[idx]);
		hm->map[idx] = NULL;
	}

	for (i = 0; i < hm->keys->elem_count; i++) {
		struct key *k;

		alist_get(hm->keys, i, &k);
		if (hm->compare(key, k) == 0) {
			alist_remove(hm->keys, i);
			break;
		}
	}

	return 0;
}

void hmap_flush(struct hashmap *hm)
{
	while (hm->keys->elem_count) {
		void *key;

		alist_get(hm->keys, 0, &key);
		hmap_delete(hm, key);
	}
}
