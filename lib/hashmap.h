#ifndef _HASHMAP_H
#define _HASHMAP_H

#include <pthread.h>
#include <linux/in6.h>

#include "arraylist.h"
#include "misc.h"

#define HASHMAP_SIZE	5003

struct hmap_entry {
	void *key;
	void *elem;
};

struct hashmap {
	int size;
	struct arraylist **map;
	struct arraylist *keys;
	pthread_rwlock_t lock;

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

static inline void hmap_read_lock(struct hashmap *hm)
{
	pthread_rwlock_rdlock(&hm->lock);
}

static inline void hmap_write_lock(struct hashmap *hm)
{
	pthread_rwlock_wrlock(&hm->lock);
}

static inline void hmap_unlock(struct hashmap *hm)
{
	pthread_rwlock_unlock(&hm->lock);
}

static inline int compare_str(void *k1, void *k2)
{
	return strcmp((char *)k1, (char *)k2);
}

static inline unsigned int hash_str(void *key)
{
	unsigned char *str = key;
	unsigned int hash = 5381;
	unsigned int c;

	while ((c = *str++))
		hash = ((hash << 5) + hash) + c;

	return hash;
}

static inline int compare_in6(void *k1, void *k2)
{
	return memcmp(k1, k2, sizeof(struct in6_addr));
}

static inline unsigned int hash_in6(void *key)
{
	struct in6_addr *in6 = key;

	return hashint(hashint(in6->s6_addr32[0]) ^ hashint(in6->s6_addr32[1]) ^
		       hashint(in6->s6_addr32[2]) ^ hashint(in6->s6_addr32[3]));
}

#endif
