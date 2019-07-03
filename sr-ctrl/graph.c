#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>
#include <math.h>
#include <zlog.h>

#include "graph.h"
#include "misc.h"

extern zlog_category_t *zc;

static bool node_equals_default(struct node *n1, struct node *n2)
{
	return n1->id == n2->id;
}

static bool data_equals_default(void *d1, void *d2)
{
	return d1 == d2;
}

static struct graph_ops g_ops_default = {
	.node_equals		= node_equals_default,
	.node_data_equals	= data_equals_default,
	.edge_data_equals	= data_equals_default,
	.node_destroy		= NULL,
	.edge_destroy		= NULL,
};

static unsigned int hash_nodepair(void *key)
{
	struct nodepair *p = key;

	return hashint((p->local->id << 16) | p->remote->id);
}

static int compare_nodepair(void *k1, void *k2)
{
	struct nodepair *p1 = k1, *p2 = k2;

	return !((p1->local->id == p2->local->id &&
		  p1->remote->id == p2->remote->id));
}

struct graph *graph_new(struct graph_ops *ops)
{
	struct graph *g;

	g = malloc(sizeof(*g));
	if (!g)
		return NULL;

	g->ops = ops ?: &g_ops_default;

	if (!g->ops->node_equals || !g->ops->node_data_equals)
		goto out_free_graph;

	g->nodes = llist_node_alloc();
	if (!g->nodes)
		goto out_free_graph;

	g->edges = llist_node_alloc();
	if (!g->edges)
		goto out_free_nodes;

	g->min_edges = hmap_new(hash_nodepair, compare_nodepair);
	if (!g->min_edges)
		goto out_free_edges;

	g->neighs = hmap_new(hash_node, compare_node);
	if (!g->neighs)
		goto out_free_minedges;

	g->dcache = hmap_new(hash_node, compare_node);
	if (!g->dcache)
		goto out_free_neighs;

	g->paths = hmap_new(hash_nodepair, compare_nodepair);
	if (!g->paths)
		goto out_free_dcache;

	pthread_rwlock_init(&g->lock, NULL);

	g->last_node = 0;
	g->last_edge = 0;
	g->dirty = false;
	g->cloned = false;

	return g;

out_free_dcache:
	hmap_destroy(g->dcache);
out_free_neighs:
	hmap_destroy(g->neighs);
out_free_minedges:
	hmap_destroy(g->min_edges);
out_free_edges:
	llist_node_destroy(g->edges);
out_free_nodes:
	llist_node_destroy(g->nodes);
out_free_graph:
	free(g);
	return NULL;
}

void graph_destroy(struct graph *g, bool shallow)
{
	struct llist_node *nhead, *tmp, *iter;
	struct hmap_entry *he;
	struct edge *e;
	struct node *n;

	graph_flush_cache(g);
	hmap_destroy(g->dcache);

	pthread_rwlock_destroy(&g->lock);

	hmap_foreach(g->neighs, he) {
		nhead = he->elem;
		llist_node_destroy(nhead);
	}

	hmap_destroy(g->min_edges);
	hmap_destroy(g->neighs);
	hmap_destroy(g->paths);

	llist_node_foreach_safe(g->edges, iter, tmp) {
		e = iter->data;
		if (shallow)
			edge_release(e);
		else
			graph_remove_edge(g, e);
	}

	llist_node_foreach_safe(g->nodes, iter, tmp) {
		n = iter->data;
		if (shallow)
			node_release(n);
		else
			graph_remove_node(g, n);
	}

	llist_node_destroy(g->edges);
	llist_node_destroy(g->nodes);

	free(g);
}

struct node *graph_add_node(struct graph *g, void *data)
{
	struct node *node;

	node = malloc(sizeof(*node));
	if (!node)
		return NULL;

	node->id = ++g->last_node;
	node->data = data;
	node->destroy = g->ops->node_destroy;
	node->orphan = false;
	node->refcount = 1;

	llist_node_insert_tail(g->nodes, node);

	g->dirty = true;

	return node;
}

void graph_remove_node(struct graph *g, struct node *node)
{
	struct llist_node *node_iter, *iter, *tmp;

	node_iter = llist_node_get_iter(g->nodes, node);
	if (!node_iter)
		return;

	llist_node_foreach_safe(g->edges, iter, tmp) {
		struct edge *e = iter->data;

		if (g->ops->node_equals(e->p_local, node) ||
		    g->ops->node_equals(e->p_remote, node))
			graph_remove_edge(g, e);
	}

	llist_node_remove(g->nodes, node_iter);

	node->orphan = true;
	node_release(node);

	g->dirty = true;
}

struct node *graph_get_node_noref(struct graph *g, unsigned int id)
{
	struct llist_node *iter;
	struct node *node;

	llist_node_foreach(g->nodes, iter) {
		node = iter->data;
		if (node->id == id)
			return node;
	}

	return NULL;
}

struct node *graph_get_node(struct graph *g, unsigned int id)
{
	struct node *node;

	node = graph_get_node_noref(g, id);
	if (node)
		node_hold(node);

	return node;
}

struct node *graph_get_node_data(struct graph *g, void *data)
{
	struct llist_node *iter;
	struct node *node;

	llist_node_foreach(g->nodes, iter) {
		node = iter->data;
		if (g->ops->node_data_equals(node->data, data))
			return node;
	}

	return NULL;
}

struct edge *graph_get_edge_noref(struct graph *g, unsigned int id)
{
	struct llist_node *iter;
	struct edge *edge;

	llist_node_foreach(g->edges, iter) {
		edge = iter->data;
		if (edge->id == id)
			return edge;
	}

	return NULL;
}

struct edge *graph_get_edge_data(struct graph *g, void *data)
{
	struct llist_node *iter;
	struct edge *edge;

	llist_node_foreach(g->edges, iter) {
		edge = iter->data;
		if (g->ops->edge_data_equals(edge->data, data))
			return edge;
	}

	return NULL;
}

struct edge *graph_add_edge(struct graph *g, struct node *local,
			    struct node *remote, uint32_t metric, bool sym,
			    void *data)
{
	struct edge *edge;

	if (sym)
		graph_add_edge(g, remote, local, metric, false, data);

	edge = calloc(1, sizeof(*edge));
	if (!edge)
		return NULL;

	edge->id = ++g->last_edge;
	edge->p_local = local;
	edge->p_remote = remote;
	edge->metric = metric;
	edge->data = data;
	edge->destroy = g->ops->edge_destroy;
	edge->orphan = false;
	edge->refcount = 1;

	node_hold(local);
	node_hold(remote);

	llist_node_insert_tail(g->edges, edge);

	g->dirty = true;

	return edge;
}

void graph_remove_edge(struct graph *g, struct edge *edge)
{
	struct llist_node *edge_iter;

	edge_iter = llist_node_get_iter(g->edges, edge);
	if (!edge_iter)
		return;

	llist_node_remove(g->edges, edge_iter);

	edge->orphan = true;
	edge_release(edge);

	g->dirty = true;
}

static struct edge *graph_get_minimal_edge(struct graph *g, struct node *local,
					   struct node *remote)
{
	struct edge *edge, *res = NULL;
	uint32_t metric = UINT32_MAX;
	struct llist_node *iter;

	llist_node_foreach(g->edges, iter) {
		edge = iter->data;

		if (edge->p_local->id != local->id ||
		    edge->p_remote->id != remote->id)
			continue;

		if (edge->metric < metric) {
			res = edge;
			metric = edge->metric;
		}
	}

	return res;
}

void graph_compute_minimal_edges(struct graph *g)
{
	struct llist_node *iter1, *iter2;
	struct node *node1, *node2;
	struct edge *edge;

	hmap_flush(g->min_edges);

	llist_node_foreach(g->nodes, iter1) {
		node1 = iter1->data;

		llist_node_foreach(g->nodes, iter2) {
			node2 = iter2->data;
			if (node1 == node2)
				continue;

			edge = graph_get_minimal_edge(g, node1, node2);
			if (!edge)
				continue;

			hmap_set(g->min_edges, (struct nodepair *)edge, edge);
		}
	}
}

static struct llist_node *graph_compute_neighbors(struct graph *g,
						  struct node *node)
{
	struct llist_node *neighs, *iter;
	struct edge *edge;

	neighs = llist_node_alloc();
	if (!neighs)
		return NULL;

	llist_node_foreach(g->edges, iter) {
		edge = iter->data;

		if (edge->p_local->id != node->id)
			continue;

		if (edge->metric == UINT32_MAX)
			continue;

		if (llist_node_exist(neighs, edge->p_remote))
			continue;

		llist_node_insert_tail(neighs, edge->p_remote);
	}

	return neighs;
}

void graph_compute_all_neighbors(struct graph *g)
{
	struct llist_node *neighs, *iter;
	struct hmap_entry *he;
	struct node *node;

	hmap_foreach(g->neighs, he) {
		neighs = he->elem;
		llist_node_destroy(neighs);
	}

	hmap_flush(g->neighs);

	llist_node_foreach(g->nodes, iter) {
		node = iter->data;
		neighs = graph_compute_neighbors(g, node);
		hmap_set(g->neighs, node, neighs);
	}
}

/* shallow copy */
struct graph *graph_clone(struct graph *g)
{
	struct llist_node *iter;
	struct graph *g_clone;
	struct node *n;
	struct edge *e;

	g_clone = graph_new(g->ops);
	if (!g_clone)
		return NULL;

	llist_node_foreach(g->nodes, iter) {
		n = iter->data;
		node_hold(n);
		llist_node_insert_tail(g_clone->nodes, n);
	}

	llist_node_foreach(g->edges, iter) {
		e = iter->data;
		edge_hold(e);
		llist_node_insert_tail(g_clone->edges, e);
	}

	g_clone->cloned = true;

	return g_clone;
}

struct graph *graph_deepcopy(struct graph *g)
{
	struct llist_node *iter;
	struct node *node, *n2;
	struct edge *edge, *e2;
	struct graph *g_copy;

	g_copy = graph_new(g->ops);
	if (!g_copy)
		return NULL;

	g_copy->last_node = g->last_node;
	g_copy->last_edge = g->last_edge;

	llist_node_foreach(g->nodes, iter) {
		node = iter->data;
		n2 = malloc(sizeof(*n2));
		n2->id = node->id;
		n2->destroy = g->ops->node_destroy;
		n2->data = g->ops->node_data_copy(node->data);
		n2->orphan = false;
		n2->refcount = 1;
		llist_node_insert_tail(g_copy->nodes, n2);
	}

	llist_node_foreach(g->edges, iter) {
		edge = iter->data;
		e2 = malloc(sizeof(*e2));
		e2->id = edge->id;
		e2->metric = edge->metric;
		e2->p_local = graph_get_node(g_copy, edge->p_local->id);
		e2->p_remote = graph_get_node(g_copy, edge->p_remote->id);
		e2->destroy = g->ops->edge_destroy;
		e2->data = g->ops->edge_data_copy(edge->data);
		e2->orphan = false;
		e2->refcount = 1;
		llist_node_insert_tail(g_copy->edges, e2);
	}

	return g_copy;
}

/* @res: list(list(node))
 * @tmp: list(node)
 */
static void __compute_paths(struct llist_node *res, struct llist_node *tmp,
			    struct hashmap *prev, struct node *u)
{
	struct llist_node *w, *iter;
	struct node *p;

	w = hmap_get(prev, u);
	if (llist_node_empty(w)) {
		llist_node_insert_tail(res, tmp);
		return;
	}

	llist_node_insert_tail(tmp, u);

	llist_node_foreach(w, iter) {
		p = iter->data;
		__compute_paths(res, llist_node_copy(tmp), prev, p);
	}

	llist_node_destroy(tmp);
}
static void compute_paths(struct llist_node *res, struct hashmap *prev,
			  struct node *u)
{
	struct llist_node *tmp;

	tmp = llist_node_alloc();
	__compute_paths(res, tmp, prev, u);
}

/* @res: list(list(node))
 * @tmp: list(node)
 */
static void __compute_paths_from_segments(struct llist_node *res, struct llist_node *tmp,
					  struct hashmap *prev, struct node *u, struct hashmap *g_cache)
{
	struct llist_node *w, *iter, *iter2, *iter3, *subpaths, *first_subpath;
	struct dres *u_dres;
	struct node *p, *intermediate_node;

	w = hmap_get(prev, u);
	if (llist_node_empty(w)) {
		llist_node_insert_tail(res, tmp);
		return;
	}

	llist_node_foreach(w, iter) {
		p = iter->data;
		u_dres = hmap_get(g_cache, u); // Dijkstra data with u as source
		subpaths = hmap_get(u_dres->path, p); // subpaths from u to p
		llist_node_foreach(subpaths, iter2) {
			first_subpath = iter2->data; // XXX Do not handle ECMP

			first_subpath = llist_node_copy_reverse(first_subpath);
			llist_node_foreach(first_subpath, iter3) { // Extend the path by the subpath to reach the intermediate point
				intermediate_node = iter3->data;
				llist_node_insert_head(tmp, intermediate_node);
			}
			llist_node_destroy(first_subpath);
			__compute_paths_from_segments(res, tmp, prev, p, g_cache);
			break; // XXX Do not handle ECMP
		}
		break; // XXX Do not handle ECMP
	}
}
static void compute_paths_from_segments(struct llist_node *res, struct hashmap *prev,
			  struct node *u, struct hashmap *g_cache)
{
	struct llist_node *tmp;

	tmp = llist_node_alloc();
	__compute_paths_from_segments(res, tmp, prev, u, g_cache);
}

static void destroy_pathres(struct llist_node *p)
{
	struct llist_node *pp, *iter;

	if (!p)
		return;

	llist_node_foreach(p, iter) {
		pp = iter->data;
		llist_node_destroy(pp);
	}

	llist_node_destroy(p);
}

void graph_dijkstra(const struct graph *g, struct node *src, struct dres *res,
		    struct d_ops *ops, void *data,
		    struct hashmap *forbidden_edges)
{
	struct hashmap *dist, *prev, *path;
	struct llist_node *Q, *iter;
	struct node *node;
	void *state;

	/* dist: node -> uint32_t
	 * prev: node -> list(node)
	 * path: node -> list(list(node))
	 */

	dist = hmap_new(hash_node, compare_node);
	prev = hmap_new(hash_node, compare_node);
	path = hmap_new(hash_node, compare_node);

	Q = llist_node_alloc();

	llist_node_foreach(g->nodes, iter) {
		node = iter->data;

		if (node->id == src->id)
			hmap_set(dist, node, (void *)(uintptr_t)0);
		else
			hmap_set(dist, node, (void *)(uintptr_t)UINT32_MAX);

		hmap_set(prev, node, llist_node_alloc());
		hmap_set(path, node, llist_node_alloc());

		llist_node_insert_tail(Q, node);
	}

	if (ops && ops->init)
		ops->init(g, src, &state, data);

	while (!llist_node_empty(Q)) {
		struct llist_node *S, *u_iter;
		struct llist_node *neighs;
		uint32_t cost, tmpcost;
		struct node *u, *v;

		tmpcost = UINT32_MAX;
		u_iter = NULL;
		S = NULL;
		u = NULL;

		llist_node_foreach(Q, iter) {
			v = iter->data;
			cost = (uintptr_t)hmap_get(dist, v);
			if (cost < tmpcost) {
				tmpcost = cost;
				u = v;
				u_iter = iter;
			}
		}

		if (!u)
			break;

		S = llist_node_alloc();

		destroy_pathres(hmap_get(path, u));
		compute_paths(S, prev, u);
		hmap_set(path, u, S);

		llist_node_remove(Q, u_iter);

		neighs = hmap_get(g->neighs, u);

		llist_node_foreach(neighs, iter) {
			struct llist_node *prev_list;
			uint32_t alt, u_dist, v_dist;
			struct edge *min_edge;
			struct nodepair pair;

			v = iter->data;
			if (!llist_node_exist(Q, v))
				continue;

			pair.local = u;
			pair.remote = v;
			/* If we want a disjoint path */
			if (forbidden_edges && hmap_get(forbidden_edges, &pair))
				continue;

			min_edge = hmap_get(g->min_edges, &pair);
			assert(min_edge);
			if (!min_edge)
				continue;

			u_dist = (uintptr_t)hmap_get(dist, u);
			v_dist = (uintptr_t)hmap_get(dist, v);

			if (ops && ops->cost)
				alt = ops->cost(u_dist, min_edge, state, data);
			else
				alt = u_dist + min_edge->metric;

			if (alt < v_dist) {
				prev_list = hmap_get(prev, v);
				llist_node_flush(prev_list);
				llist_node_insert_tail(prev_list, u);
				hmap_set(dist, v, (void *)(uintptr_t)alt);

				if (ops && ops->update)
					ops->update(min_edge, state, data);
			} else if (alt == v_dist) {
				prev_list = hmap_get(prev, v);
				llist_node_insert_tail(prev_list, u);
			}
		}
	}

	if (ops && ops->destroy)
		ops->destroy(state);

	llist_node_destroy(Q);

	res->dist = dist;
	res->path = path;
	res->prev = prev;
}

void graph_dijkstra_free(struct dres *res)
{
	struct llist_node *nhead;
	struct hmap_entry *he;

	hmap_foreach(res->path, he) {
		nhead = he->elem;
		destroy_pathres(nhead);
	}

	hmap_foreach(res->prev, he) {
		nhead = he->elem;
		llist_node_destroy(nhead);
	}

	hmap_destroy(res->prev);
	hmap_destroy(res->path);
	hmap_destroy(res->dist);
}

unsigned int graph_prune(struct graph *g,
			 bool (*prune)(struct edge *e, void *arg), void *_arg)
{
	struct llist_node *iter, *tmp;
	unsigned int rm = 0;
	struct edge *edge;

	if (llist_node_empty(g->edges))
		return 0;

	llist_node_foreach_safe(g->edges, iter, tmp) {
		edge = iter->data;

		if (prune(edge, _arg)) {
			llist_node_remove(g->edges, iter);
			rm++;
		}
	}

	return rm;
}

static int insert_node_segment(struct node *node_i, struct llist_node *res)
{
	struct segment *s;

	s = malloc(sizeof(*s));
	if (!s)
		return -1;

	s->adjacency = false;
	s->node = node_i;

	node_hold(node_i);

	llist_node_insert_tail(res, s);

	return 0;
}

static int insert_adj_segment(struct graph *g, struct node *node_i,
			      struct node *node_ii, struct llist_node *res)
{
	struct nodepair pair;
	struct edge *edge;
	struct segment *s;

	s = malloc(sizeof(*s));
	if (!s)
		return -1;

	pair.local = node_i;
	pair.remote = node_ii;
	edge = hmap_get(g->min_edges, &pair);
	if (!edge)
		return -1;

	s->adjacency = true;
	s->edge = edge;

	edge_hold(edge);

	llist_node_insert_tail(res, s);

	return 0;
}

void free_segments(struct llist_node *segs)
{
	struct llist_node *iter;
	struct segment *s;

	llist_node_foreach(segs, iter) {
		s = iter->data;
		if (s->adjacency)
			edge_release(s->edge);
		else
			node_release(s->node);
		free(s);
	}

	llist_node_destroy(segs);
}

struct llist_node *copy_segments(struct llist_node *segs)
{
	struct llist_node *nhead, *iter;
	struct segment *s, *s2;

	nhead = llist_node_alloc();
	if (!nhead)
		return NULL;

	llist_node_foreach(segs, iter) {
		s = iter->data;

		s2 = malloc(sizeof(*s2));
		if (!s2)
			goto out_free;

		memcpy(s2, s, sizeof(*s2));
		if (s->adjacency)
			edge_hold(s->edge);
		else
			node_hold(s->node);
		llist_node_insert_tail(nhead, s2);
	}

	return nhead;

out_free:
	free_segments(nhead);
	return NULL;
}

bool compare_segments(struct llist_node *segs1, struct llist_node *segs2)
{
	struct llist_node *iter1, *iter2;
	struct segment *s1, *s2;

	iter2 = llist_node_first_entry(segs2);

	if (llist_node_size(segs1) != llist_node_size(segs2))
		return false;

	llist_node_foreach(segs1, iter1) {
		s1 = iter1->data;
		s2 = iter2->data;

		if (s1->adjacency != s2->adjacency)
			return false;

		if (s1->adjacency && (s1->edge->id != s2->edge->id))
			return false;

		if (!s1->adjacency && (s1->node->id != s2->node->id))
			return false;

		iter2 = llist_node_next_entry(iter2);
	}

	return true;
}

int graph_build_cache_one(struct graph *g, struct node *node)
{
	struct dres *res, *old_res;

	res = malloc(sizeof(*res));
	if (!res)
		return -1;

	/* cache only SP-DAGs built without custom sp-ops,
	 * because it can unpredictably affect the result
	 * and yield wrong cache entries.
	 */
	graph_dijkstra(g, node, res, NULL, NULL, NULL);

	old_res = hmap_get(g->dcache, node);
	if (old_res)
		graph_dijkstra_free(old_res);

	hmap_set(g->dcache, node, res);

	return 0;
}

int graph_build_cache(struct graph *g)
{
	struct llist_node *iter;
	struct node *node;

	llist_node_foreach(g->nodes, iter) {
		node = iter->data;
		if (graph_build_cache_one(g, node) < 0)
			return -1;
	}

	return 0;
}

void graph_flush_cache(struct graph *g)
{
	struct hmap_entry *he;

	hmap_foreach(g->dcache, he) {
		graph_dijkstra_free(he->elem);
		free(he->elem);
	}

	hmap_flush(g->dcache);
}

bool path_is_forbidden(struct hashmap *src_paths, struct node *src, struct node *dst, struct hashmap *forbidden_edges)
{
	struct llist_node *iter;
	struct node *intermediate_node, *next_node;
	struct nodepair pair;

	struct llist_node *subpaths = hmap_get(src_paths, dst);
	struct llist_node *subpath = llist_node_first_entry(subpaths)->data; // XXX No ECMP Handling

	size_t i = llist_node_size(subpath);
	llist_node_foreach(subpath, iter) {
		intermediate_node = iter->data;
		if (i > 1)
			next_node = llist_next_entry(iter, head)->data;
		else
			next_node = src;
		pair.local = intermediate_node;
		pair.remote = next_node;
		if (hmap_get(forbidden_edges, &pair))
			return true;
		i -= 1;
	}
	return false;
}

/* Needs the hashmap cache filled by Dijkstra */
void graph_shortest_path_maxseg(struct graph *g, struct node *src,
				struct dres *res, __attribute__((unused)) struct d_ops *ops, __attribute__((unused)) void *data,
				struct hashmap *forbidden_edges, int maxseg)
{
	struct llist_node *iter_cur, *iter_pre;
	struct hashmap *dist, *prev, *path;
	struct node *cur, *pre;

	// TODO Cite algo source
	uint32_t cost[maxseg+1][llist_node_size(g->nodes)];
	for (int i = 0; i <= maxseg; i++) {
		for (uint32_t j = 0; j < llist_node_size(g->nodes); j++)
			cost[i][j] = UINT32_MAX;
	}
	cost[0][src->id] = 0;

	struct node *parent[maxseg+1][llist_node_size(g->nodes)];
	for (int i = 0; i <= maxseg; i++) {
		for (uint32_t j = 0; j < llist_node_size(g->nodes); j++)
			parent[i][j] = NULL;
	}

	for (int i = 1; i <= maxseg; i++) {
		llist_node_foreach(g->nodes, iter_cur) {
			cur = iter_cur->data;
			/* Don't use a new segment (even if limit raises) */
			cost[i][cur->id] = cost[i - 1][cur->id];
			parent[i][cur->id] = parent[i - 1][cur->id];

			/* We reach cur by coming from pre */
			llist_node_foreach(g->nodes, iter_pre) {
				pre = iter_pre->data;
				if(pre->id == cur->id)
					continue;

				/* Use cost and segment in a graph forbidding the forbidden edges */
				struct dres * pre_res = hmap_get(g->dcache, pre);
				uint32_t cost_pre_to_cur = (uintptr_t) hmap_get(pre_res->dist, cur);
				if(cost_pre_to_cur == UINT32_MAX || cost[i - 1][pre->id] == UINT32_MAX || path_is_forbidden(pre_res->path, pre, cur, forbidden_edges))
					continue;

				uint32_t l = cost[i - 1][pre->id] + cost_pre_to_cur;
				if(l < cost[i][cur->id]) {
					cost[i][cur->id] = l;
					parent[i][cur->id] = pre;
				}
				// TODO Add Adjacency segments
			}
		}
	}

	/* Recompute the dist, prev and path hashmaps */
	dist = hmap_new(hash_node, compare_node);
	prev = hmap_new(hash_node, compare_node);
	path = hmap_new(hash_node, compare_node);

	/* Needs the prev hashmap before computing paths */
	llist_node_foreach(g->nodes, iter_cur) {
		cur = iter_cur->data;
		hmap_set(dist, cur, (void *)(uintptr_t) cost[maxseg][cur->id]);

		struct llist_node *l = llist_node_alloc();
		if (parent[maxseg][cur->id]) {
			llist_node_insert_tail(l, parent[maxseg][cur->id]);
		}
		hmap_set(prev, cur, l);
	}

	llist_node_foreach(g->nodes, iter_cur) {
		cur = iter_cur->data;
		struct llist_node *sublist_paths = llist_node_alloc();
		if (((uint32_t) (uintptr_t) cost[maxseg][cur->id]) != UINT32_MAX) { // A path exists
			compute_paths_from_segments(sublist_paths, prev, cur, g->dcache);
		}
		hmap_set(path, cur, sublist_paths);
	}

	res->dist = dist;
	res->path = path;
	res->prev = prev;
}

int graph_minseg(struct graph *g, struct llist_node *path,
		 struct llist_node *res)
{
	struct dres *cache_res_r, *cache_res_i;
	struct node *node_r, *node_i, *node_ii;
	struct dres res_r, res_i;
	struct llist_node *iter;

	if (llist_node_empty(path))
		return 0;

	node_r = NULL;

	llist_node_foreach(path, iter) {
		struct llist_node *prev;

		/* iterate until N-1 */
		if (iter == llist_node_last_entry(path))
			break;

		node_i = iter->data;
		node_ii = llist_node_next_entry(iter)->data;
		if (!node_r)
			node_r = node_i;

		cache_res_i = hmap_get(g->dcache, node_i);
		cache_res_r = hmap_get(g->dcache, node_r);

		if (cache_res_i)
			res_i = *cache_res_i;
		else
			graph_dijkstra(g, node_i, &res_i, NULL, NULL, NULL);

		if (cache_res_r)
			res_r = *cache_res_r;
		else
			graph_dijkstra(g, node_r, &res_r, NULL, NULL, NULL);

		prev = hmap_get(res_r.prev, node_ii);
		if (!llist_node_exist(prev, node_i)) { /* MinSegECMP:4 */
			prev = hmap_get(res_i.prev, node_ii);
			if (llist_node_size(prev) == 1) { /* MinSegECMP:5 */
				insert_node_segment(node_i, res);
				node_r = node_i;
			} else {
				insert_node_segment(node_i, res);
				if (insert_adj_segment(g, node_i, node_ii,
						       res) < 0)
					goto out_error;
				node_r = node_ii;
			}
		} else {
			prev = hmap_get(res_r.prev, node_ii);
			if (llist_node_size(prev) <= 1) /* !MinSegECMP:11 */
				goto next_free;

			prev = hmap_get(res_i.prev, node_ii);
			if (llist_node_size(prev) > 1) { /* MinSegECMP:12 */
				insert_node_segment(node_i, res);
				if (insert_adj_segment(g, node_i, node_ii,
						       res) < 0)
					goto out_error;
				node_r = node_ii;
			} else {
				insert_node_segment(node_i, res);
				node_r = node_i;
			}
		}

next_free:
		if (!cache_res_i)
			graph_dijkstra_free(&res_i);
		if (!cache_res_r)
			graph_dijkstra_free(&res_r);
	}

	return 0;

out_error:
	if (!cache_res_i)
		graph_dijkstra_free(&res_i);
	if (!cache_res_r)
		graph_dijkstra_free(&res_r);

	return -1;
}

static struct llist_node *nodes_to_edges(struct graph *g,
					 struct llist_node *path)
{
	struct llist_node *res, *iter;
	struct node *node_i, *node_ii;
	struct nodepair pair;
	struct edge *edge;

	res = llist_node_alloc();
	if (!res)
		return NULL;

	llist_node_foreach(path, iter) {
		if (iter == llist_node_last_entry(path))
			break;

		node_i = iter->data;
		node_ii = llist_node_next_entry(iter)->data;

		pair.local = node_i;
		pair.remote = node_ii;

		edge = hmap_get(g->min_edges, &pair);
		if (!edge)
			goto out_err;

		edge_hold(edge);
		llist_node_insert_tail(res, edge);
	}

	return res;

out_err:
	llist_node_destroy(res);
	return NULL;
}

void destroy_edgepath(struct llist_node *path)
{
	struct llist_node *iter;

	if (!path)
		return;

	llist_node_foreach(path, iter) {
		edge_release((struct edge *)iter->data);
	}

	llist_node_destroy(path);
}

struct llist_node *copy_edgepath(struct llist_node *path)
{
	struct llist_node *iter, *res;
	struct edge *edge;

	if (!path)
		return NULL;

	res = llist_node_alloc();
	if (!res)
		return NULL;

	llist_node_foreach(path, iter) {
		edge = iter->data;
		edge_hold(edge);
		llist_node_insert_tail(res, edge);
	}

	return res;
}

struct llist_node *build_disjoint_segpath(struct graph *g,
					  struct pathspec *pspec,
					  struct llist_node **epath,
					  struct hashmap *forbidden_edges,
					  int maxseg)
{
	struct llist_node *res, *path, *iter, *debug_iter, *fpath = NULL;
	struct node *cur_node;
	struct graph *gc;
	struct dres gres;

	res = llist_node_alloc();
	if (!res)
		return NULL;

	path = llist_node_alloc();
	if (!path) {
		llist_node_destroy(res);
		return NULL;
	}

	if (epath) {
		fpath = llist_node_alloc();
		if (!fpath) {
			llist_node_destroy(path);
			llist_node_destroy(res);
			return NULL;
		}
	}

	gc = g;

	if (pspec->prune) {
		gc = graph_clone(g);
		pspec->prune(gc, pspec);
		graph_finalize(gc);
	}

	cur_node = pspec->src;

	if (pspec->via)
		llist_node_append(path, pspec->via);

	llist_node_insert_tail(path, pspec->dst);

	llist_node_foreach(path, iter) {
		struct llist_node *tmp_paths, *tmp_path, *rev_path;
		struct node *tmp_node;
		struct segment *s;

		tmp_node = iter->data;

		if (maxseg <= 0)
			graph_dijkstra(gc, cur_node, &gres, pspec->d_ops, pspec->data,
					forbidden_edges);
		else
			graph_shortest_path_maxseg(gc, cur_node, &gres, pspec->d_ops,
					   pspec->data, forbidden_edges, maxseg);
		tmp_paths = hmap_get(gres.path, tmp_node);
		if (llist_node_empty(tmp_paths))
			goto out_error;

		/* XXX modify here to support backup paths or modify
		 * path selection (e.g., random).
		 */
		tmp_path = llist_node_first_entry(tmp_paths)->data;

		if (maxseg <= 0) { /* Different path format in graph_dijkstra */
			rev_path = llist_node_copy_reverse(tmp_path);
			llist_node_insert_head(rev_path, cur_node);
		} else {
			rev_path = llist_node_copy(tmp_path);
			llist_node_insert_tail(rev_path, tmp_node);
		}

		char buf [1024];
		char buf2 [1024];
		snprintf(buf, 1024, "Path from %d to %d is: [", cur_node->id, tmp_node->id);
		llist_node_foreach(rev_path, debug_iter) {
			struct node *intermediate_node = debug_iter->data;
			snprintf(buf2, 1024, " %d ", intermediate_node->id);
			strncat(buf, buf2, 1023);
		}
		zlog_debug(zc, "%s]", buf);

		if (graph_minseg(g, rev_path, res) < 0)
			goto out_error;

		if (fpath)
			llist_node_append(fpath, rev_path);

		/* append waypoint segment only if there is no adjacency
		 * segment for the last hop (i.e. breaking link bundle)
		 */
		s = llist_node_last_entry(res)->data;
		if (!s || !(s->adjacency && s->edge->p_remote == tmp_node))
			insert_node_segment(tmp_node, res);

		llist_node_destroy(rev_path);
		cur_node = tmp_node;

		graph_dijkstra_free(&gres);
	}

	if (gc->cloned)
		graph_destroy(gc, true);

	llist_node_destroy(path);

	if (fpath) {
		*epath = nodes_to_edges(g, fpath);
		llist_node_destroy(fpath);
	}

	return res;

out_error:
	graph_dijkstra_free(&gres);
	if (gc->cloned)
		graph_destroy(gc, true);
	if (fpath)
		llist_node_destroy(fpath);
	llist_node_destroy(path);
	free_segments(res);
	return NULL;
}

struct llist_node *build_segpath(struct graph *g, struct pathspec *pspec,
				 struct llist_node **epath)
{
	return build_disjoint_segpath(g, pspec, epath, NULL, -1);
}
