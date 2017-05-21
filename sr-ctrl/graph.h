#ifndef _GRAPH_H
#define _GRAPH_H

#include <stdint.h>
#include <pthread.h>

#include "atomic.h"
#include "llist.h"
#include "hashmap.h"

/* The refcounting system used in nodes and edges enables them to be referenced
 * outside of graph critical sections. It is the programmer's responsibility
 * to ensure that the refcount is properly maintained by using the *_hold()
 * and *_release() functions. When a node or edge is removed from a graph but
 * still has references, its ->orphan attribute is set to true.
 *
 * If ALIGN_REFCOUNT is defined, then refcount variables will be aligned
 * to a cacheline size (typically 64 bytes). It uses more bytes per structure,
 * but prevents invalidation of the cache line holding attributes that are
 * frequently read (e.g. edge's metric). The result is better cache hit rate
 * under high load.
 *
 * References are not taken in the graph's auxiliary structures
 * (min_edges, neigh, dcache) because we force them to be recomputed when
 * the graph is dirty. This may change in the future to avoid the recomputation
 * burden.
 */

struct node {
	unsigned int id;
	void *data;
	void (*destroy)(struct node *node);
	bool orphan;
	atomic_t refcount __refcount_aligned;
};

struct edge {
	struct node *local;
	struct node *remote;
	unsigned int id;
	uint32_t metric;
	void *data;
	void (*destroy)(struct edge *edge);
	bool orphan;
	atomic_t refcount __refcount_aligned;
};

struct nodepair {
	struct node *local;
	struct node *remote;
};

struct segment {
	union {
		struct node *node;
		struct edge *edge;
	};

	bool adjacency;
};

static inline void node_hold(struct node *node)
{
	atomic_inc(&node->refcount);
}

static inline void node_release(struct node *node)
{
	if (atomic_dec(&node->refcount) == 0) {
		if (node->destroy)
			node->destroy(node);
		free(node);
	}
}

static inline void edge_hold(struct edge *edge)
{
	atomic_inc(&edge->refcount);
}

static inline void edge_release(struct edge *edge)
{
	if (atomic_dec(&edge->refcount) == 0) {
		if (edge->destroy)
			edge->destroy(edge);
		node_release(edge->local);
		node_release(edge->remote);
		free(edge);
	}
}

/* (local,remote) => minimal edge (or null) */
/* node => neighbors */

struct graph_ops {
	bool (*node_equals)(struct node *n1, struct node *n2);
	bool (*node_data_equals)(void *d1, void *d2);
	bool (*edge_data_equals)(void *d1, void *d2);
	void *(*node_data_copy)(void *data);
	void *(*edge_data_copy)(void *data);
	void (*node_destroy)(struct node *node);
	void (*edge_destroy)(struct edge *edge);
};

struct graph {
	struct llist_node *nodes;
	struct llist_node *edges;
	unsigned int last_node;
	unsigned int last_edge;
	struct hashmap *min_edges;
	struct hashmap *neighs;
	struct hashmap *dcache;
	pthread_rwlock_t lock;
	bool dirty;
	struct graph_ops *ops;
	bool cloned;
};

struct dres {
	struct hashmap *dist;
	struct hashmap *path;
	struct hashmap *prev;
};

struct d_ops {
	void (*init)(const struct graph *g, struct node *src, void **state,
		     void *data);
	void (*destroy)(void *state);
	uint32_t (*cost)(uint32_t cur_cost, struct edge *edge, void *state,
			 void *data);
	void (*update)(struct edge *edge, void *state, void *data);
};

struct graph *graph_new(struct graph_ops *ops);
void graph_destroy(struct graph *g, bool shallow);
struct node *graph_add_node(struct graph *g, void *data);
void graph_remove_node(struct graph *g, struct node *node);
struct node *graph_get_node(struct graph *g, unsigned int id);
struct node *graph_get_node_noref(struct graph *g, unsigned int id);
struct node *graph_get_node_data(struct graph *g, void *data);
struct edge *graph_add_edge(struct graph *g, struct node *local,
			    struct node *remote, uint32_t metric, bool sym,
			    void *data);
void graph_remove_edge(struct graph *g, struct edge *edge);
struct edge *graph_get_edge_data(struct graph *g, void *data);
void graph_compute_minimal_edges(struct graph *g);
void graph_compute_all_neighbors(struct graph *g);
struct graph *graph_clone(struct graph *g);
void graph_dijkstra(const struct graph *g, struct node *src, struct dres *res,
		    struct d_ops *d_ops, void *data);
void graph_dijkstra_free(struct dres *res);
unsigned int graph_prune(struct graph *g,
			 bool (*prune)(struct edge *e, void *arg), void *_arg);
int graph_minseg(struct graph *g, struct llist_node *path,
		 struct llist_node *res);

void free_segments(struct llist_node *segs);
struct llist_node *copy_segments(struct llist_node *segs);
int graph_build_cache_one(struct graph *g, struct node *node);
int graph_build_cache(struct graph *g);
void graph_flush_cache(struct graph *g);
struct graph *graph_deepcopy(struct graph *g);

struct pathspec {
	struct node *src;
	struct node *dst;
	struct llist_node *via;
	void (*prune)(struct graph *g, struct pathspec *pspec);
	struct d_ops *d_ops;
	void *data;
};

struct llist_node *build_segpath(struct graph *g, struct pathspec *pspec);

static inline void graph_finalize(struct graph *g)
{
	graph_compute_minimal_edges(g);
	graph_compute_all_neighbors(g);
	g->dirty = false;
}

static inline void graph_read_lock(struct graph *g)
{
	pthread_rwlock_rdlock(&g->lock);
}

static inline void graph_write_lock(struct graph *g)
{
	pthread_rwlock_wrlock(&g->lock);
}

static inline void graph_unlock(struct graph *g)
{
	pthread_rwlock_unlock(&g->lock);
}

static inline int compare_node(void *k1, void *k2)
{
	return !(((struct node *)k1)->id == ((struct node *)k2)->id);
}

static inline unsigned int hash_node(void *key)
{
	return hashint(((struct node *)key)->id);
}

#endif
