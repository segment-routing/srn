#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>

#include "graph.h"
#include "misc.h"

static bool node_equals_default(struct node *n1, struct node *n2)
{
	return n1->id == n2->id;
}

static bool node_data_equals_default(void *d1, void *d2)
{
	return d1 == d2;
}

static struct graph_ops g_ops_default = {
	.node_equals		= node_equals_default,
	.node_data_equals	= node_data_equals_default,
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

	g = calloc(1, sizeof(*g));
	if (!g)
		return NULL;

	g->ops = ops ?: &g_ops_default;

	if (!g->ops->node_equals || !g->ops->node_data_equals) {
		free(g);
		return NULL;
	}

	g->nodes = alist_new(sizeof(struct node *));
	if (!g->nodes) {
		free(g);
		return NULL;
	}

	g->edges = alist_new(sizeof(struct edge *));
	if (!g->edges) {
		alist_destroy(g->nodes);
		free(g);
		return NULL;
	}

	g->min_edges = hmap_new(hash_nodepair, compare_nodepair);
	if (!g->min_edges) {
		alist_destroy(g->edges);
		alist_destroy(g->nodes);
		free(g);
		return NULL;
	}

	g->neighs = hmap_new(hash_node, compare_node);
	if (!g->neighs) {
		alist_destroy(g->edges);
		alist_destroy(g->nodes);
		hmap_destroy(g->min_edges);
		free(g);
		return NULL;
	}

	pthread_rwlock_init(&g->lock, NULL);

	g->dirty = true;

	return g;
}

void graph_destroy(struct graph *g, bool shallow)
{
	unsigned int i;
	struct edge *e;
	struct node *n;

	pthread_rwlock_destroy(&g->lock);

	for (i = 0; i < g->neighs->keys->elem_count; i++) {
		alist_get(g->neighs->keys, i, &n);
		alist_destroy(hmap_get(g->neighs, n));
	}

	hmap_destroy(g->min_edges);
	hmap_destroy(g->neighs);

	while (g->edges->elem_count) {
		alist_get(g->edges, 0, &e);
		graph_remove_edge(g, e);
		if (!shallow)
			free(e);
	}

	while (g->nodes->elem_count) {
		alist_get(g->nodes, 0, &n);
		graph_remove_node(g, n);
		if (!shallow)
			free(n);
	}

	alist_destroy(g->edges);
	alist_destroy(g->nodes);

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

	alist_insert(g->nodes, &node);

	g->dirty = true;

	return node;
}

static int get_node_index(struct arraylist *nodes, unsigned int id)
{
	struct node *node;
	unsigned int i;

	for (i = 0; i < nodes->elem_count; i++) {
		alist_get(nodes, i, &node);
		if (node->id == id)
			return i;
	}

	return -1;
}

static int get_edge_index(struct arraylist *edges, unsigned int id)
{
	struct edge *edge;
	unsigned int i;

	for (i = 0; i < edges->elem_count; i++) {
		alist_get(edges, i, &edge);
		if (edge->id == id)
			return i;
	}

	return -1;
}

void graph_remove_node(struct graph *g, struct node *node)
{
	unsigned int j;
	int i;

	i = get_node_index(g->nodes, node->id);
	if (i < 0)
		return;

	for (j = 0; j < g->edges->elem_count; j++) {
		struct edge *edge;

		alist_get(g->edges, j, &edge);
		if (g->ops->node_equals(edge->local, node) ||
		    g->ops->node_equals(edge->remote, node)) {
			graph_remove_edge(g, edge);
			j--;
		}
	}

	alist_remove(g->nodes, i);
	g->dirty = true;
}

struct node *graph_get_node(struct graph *g, unsigned int id)
{
	struct node *node;
	unsigned int i;

	for (i = 0; i < g->nodes->elem_count; i++) {
		alist_get(g->nodes, i, &node);
		if (node->id == id)
			return node;
	}

	return NULL;
}

struct node *graph_get_node_data(struct graph *g, void *data)
{
	struct node *node;
	unsigned int i;

	for (i = 0; i < g->nodes->elem_count; i++) {
		alist_get(g->nodes, i, &node);
		if (g->ops->node_data_equals(node->data, data))
			return node;
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
	edge->local = local;
	edge->remote = remote;
	edge->metric = metric;
	edge->data = data;

	alist_insert(g->edges, &edge);

	g->dirty = true;

	return edge;
}

void graph_remove_edge(struct graph *g, struct edge *edge)
{
	int i;

	i = get_edge_index(g->edges, edge->id);
	if (i < 0)
		return;

	alist_remove(g->edges, i);
	g->dirty = true;
}

static struct edge *graph_get_minimal_edge(struct graph *g, struct node *local,
					   struct node *remote)
{
	struct edge *edge, *res = NULL;
	uint32_t metric = UINT32_MAX;
	unsigned int i;

	for (i = 0; i < g->edges->elem_count; i++) {
		alist_get(g->edges, i, &edge);

		if (edge->local->id != local->id ||
		    edge->remote->id != remote->id)
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
	struct node *node1, *node2;
	struct edge *edge;
	unsigned int i, j;

	hmap_flush(g->min_edges);

	for (i = 0; i < g->nodes->elem_count; i++) {
		alist_get(g->nodes, i, &node1);
		for (j = 0; j < g->nodes->elem_count; j++) {
			if (i == j)
				continue;
			alist_get(g->nodes, j, &node2);
			edge = graph_get_minimal_edge(g, node1, node2);
			if (!edge)
				continue;
			hmap_set(g->min_edges, (struct nodepair *)edge, edge);
		}
	}
}

static struct arraylist *graph_compute_neighbors(struct graph *g,
						 struct node *node)
{
	struct arraylist *neighs;
	struct edge *edge;
	unsigned int i;

	neighs = alist_new(sizeof(struct node *));
	if (!neighs)
		return NULL;

	for (i = 0; i < g->edges->elem_count; i++) {
		alist_get(g->edges, i, &edge);

		if (edge->local->id != node->id)
			continue;

		if (alist_exist(neighs, &edge->remote))
			continue;

		alist_insert(neighs, &edge->remote);
	}

	return neighs;
}

void graph_compute_all_neighbors(struct graph *g)
{
	struct arraylist *neighs;
	struct node *node;
	unsigned int i;

	for (i = 0; i < g->neighs->keys->elem_count; i++) {
		alist_get(g->neighs->keys, i, &node);
		alist_destroy(hmap_get(g->neighs, node));
	}

	hmap_flush(g->neighs);

	for (i = 0; i < g->nodes->elem_count; i++) {
		alist_get(g->nodes, i, &node);

		neighs = graph_compute_neighbors(g, node);
		assert(neighs);
		if (!neighs)
			return;

		hmap_set(g->neighs, node, neighs);
	}
}

struct graph *graph_clone(struct graph *g)
{
	struct graph *g_clone;

	g_clone = graph_new(g->ops);
	if (!g_clone)
		return NULL;

	alist_append(g_clone->nodes, g->nodes);
	alist_append(g_clone->edges, g->edges);

	return g_clone;
}

/* @res: arraylist(arraylist(node))
 * @tmp: arraylist(node)
 */
static void __compute_paths(struct arraylist *res, struct arraylist *tmp,
			    struct hashmap *prev, struct node *u)
{
	struct arraylist *w;
	struct node *p;
	unsigned int i;

	w = hmap_get(prev, u);
	if (!w->elem_count) {
		alist_insert(res, &tmp);
		return;
	}

	alist_insert(tmp, &u);

	if (w->elem_count == 1) {
		alist_get(w, 0, &p);
		__compute_paths(res, tmp, prev, p);
		return;
	}

	for (i = 0; i < w->elem_count; i++) {
		alist_get(w, i, &p);

		__compute_paths(res, alist_copy(tmp), prev, p);
	}

	alist_destroy(tmp);
}

static void compute_paths(struct arraylist *res, struct hashmap *prev,
			  struct node *u)
{
	struct arraylist *tmp;

	tmp = alist_new(sizeof(struct node *));
	__compute_paths(res, tmp, prev, u);
}

static void destroy_alist2(struct arraylist *al)
{
	struct arraylist *entry;
	unsigned int i;

	if (!al)
		return;

	for (i = 0; i < al->elem_count; i++) {
		alist_get(al, i, &entry);
		alist_destroy(entry);
	}

	alist_destroy(al);
}

void graph_dijkstra(struct graph *g, struct node *src, struct dres *res,
		    struct d_ops *ops, void *data)
{
	struct hashmap *dist, *prev, *path;
	struct arraylist *Q;
	struct node *node;
	unsigned int i;
	void *state;

	/* dist: node -> uint32_t
	 * prev: node -> arraylist(node)
	 * path: node -> arraylist(arraylist(node))
	 */

	if (g->dirty)
		graph_finalize(g);

	dist = hmap_new(hash_node, compare_node);
	prev = hmap_new(hash_node, compare_node);
	path = hmap_new(hash_node, compare_node);

	Q = alist_new(sizeof(struct node *));

	for (i = 0; i < g->nodes->elem_count; i++) {
		alist_get(g->nodes, i, &node);

		if (node->id == src->id)
			hmap_set(dist, node, (void *)(uintptr_t)0);
		else
			hmap_set(dist, node, (void *)(uintptr_t)UINT32_MAX);

		hmap_set(prev, node, alist_new(sizeof(struct node *)));
		hmap_set(path, node, alist_new(sizeof(struct arraylist *)));

		alist_insert(Q, &node);
	}

	if (ops)
		ops->init(g, src, &state, data);

	while (Q->elem_count > 0) {
		struct arraylist *S = NULL;
		struct arraylist *neighs;
		uint32_t cost, tmpcost;
		struct node *u, *v;
		int u_idx = -1;

		tmpcost = UINT32_MAX;
		u = NULL;

		for (i = 0; i < Q->elem_count; i++) {
			alist_get(Q, i, &v);
			cost = (uintptr_t)hmap_get(dist, v);
			if (cost < tmpcost) {
				tmpcost = cost;
				u = v;
				u_idx = i;
			}
		}

		if (u_idx == -1)
			break;

		S = alist_new(sizeof(struct arraylist *));

		destroy_alist2(hmap_get(path, u));
		compute_paths(S, prev, u);
		hmap_set(path, u, S);

		alist_remove(Q, u_idx);

		neighs = hmap_get(g->neighs, u);
		for (i = 0; i < neighs->elem_count; i++) {
			struct arraylist *prev_array;
			uint32_t alt, u_dist, v_dist;
			struct edge *min_edge;
			struct nodepair pair;

			alist_get(neighs, i, &v);
			if (!alist_exist(Q, &v))
				continue;

			pair.local = u;
			pair.remote = v;
			min_edge = hmap_get(g->min_edges, &pair);

			assert(min_edge);
			if (!min_edge)
				continue;

			u_dist = (uintptr_t)hmap_get(dist, u);
			v_dist = (uintptr_t)hmap_get(dist, v);

			if (ops)
				alt = ops->cost(u_dist, min_edge, state, data);
			else
				alt = u_dist + min_edge->metric;

			if (alt < v_dist) {
				prev_array = hmap_get(prev, v);
				alist_flush(prev_array);
				alist_insert(prev_array, &u);
				hmap_set(dist, v, (void *)(uintptr_t)alt);

				if (ops)
					ops->update(min_edge, state, data);
			} else if (alt == v_dist) {
				prev_array = hmap_get(prev, v);
				alist_insert(prev_array, &u);
			}
		}
	}

	if (ops)
		ops->destroy(state);

	alist_destroy(Q);

	res->dist = dist;
	res->path = path;
	res->prev = prev;
}

void graph_dijkstra_free(struct dres *res)
{
	unsigned int i;

	for (i = 0; i < res->path->keys->elem_count; i++) {
		struct node *n;

		alist_get(res->path->keys, i, &n);
		destroy_alist2(hmap_get(res->path, n));
	}

	for (i = 0; i < res->prev->keys->elem_count; i++) {
		void *key;

		alist_get(res->prev->keys, i, &key);
		alist_destroy(hmap_get(res->prev, key));
	}

	hmap_destroy(res->prev);
	hmap_destroy(res->path);
	hmap_destroy(res->dist);
}

int graph_prune(struct graph *g, bool (*prune)(struct edge *e, void *arg),
		void *_arg)
{
	struct edge *edge;
	unsigned int i;
	int rm = 0;

	for (i = 0; i < g->edges->elem_count; i++) {
		alist_get(g->edges, i, &edge);

		if (prune(edge, _arg)) {
			graph_remove_edge(g, edge);
			rm++;
			i--;
		}
	}

	return rm;
}

static void insert_node_segment(struct node *node_i, struct arraylist *res)
{
	struct segment s;

	s.adjacency = false;
	s.node = node_i;
	alist_insert(res, &s);
}

static int insert_adj_segment(struct graph *g, struct node *node_i,
			      struct node *node_ii, struct arraylist *res)
{
	struct nodepair pair;
	struct edge *edge;
	struct segment s;

	pair.local = node_i;
	pair.remote = node_ii;
	edge = hmap_get(g->min_edges, &pair);
	if (!edge)
		return -1;

	s.adjacency = true;
	s.edge = edge;
	alist_insert(res, &s);

	return 0;
}

int graph_minseg(struct graph *g, struct arraylist *path,
		 struct arraylist *res)
{
	struct node *node_r, *node_i, *node_ii;
	struct dres res_r, res_i;
	unsigned int i, r;

	if (!path->elem_count)
		return 0;

	r = 0;

	/* path forward */
	for (i = 0; i < path->elem_count - 1; i++) {
		struct arraylist *prev;

		alist_get(path, i, &node_i);
		alist_get(path, i + 1, &node_ii);
		alist_get(path, r, &node_r);

		graph_dijkstra(g, node_i, &res_i, NULL, NULL);
		graph_dijkstra(g, node_r, &res_r, NULL, NULL);

		prev = hmap_get(res_r.prev, node_ii);
		if (!alist_exist(prev, &node_i)) { /* MinSegECMP:4 */
			prev = hmap_get(res_i.prev, node_ii);
			if (prev->elem_count == 1) { /* MinSegECMP:5 */
				insert_node_segment(node_i, res);
				r = i;
			} else {
				insert_node_segment(node_i, res);
				if (insert_adj_segment(g, node_i, node_ii,
						       res) < 0)
					goto out_error;
				r = i + 1;
			}
		} else {
			prev = hmap_get(res_r.prev, node_ii);
			if (prev->elem_count <= 1) /* !MinSegECMP:11 */
				goto next_free;

			prev = hmap_get(res_i.prev, node_ii);
			if (prev->elem_count > 1) { /* MinSegECMP:12 */
				insert_node_segment(node_i, res);
				if (insert_adj_segment(g, node_i, node_ii,
						       res) < 0)
					goto out_error;
				r = i + 1;
			} else {
				insert_node_segment(node_i, res);
				r = i;
			}
		}

next_free:
		graph_dijkstra_free(&res_i);
		graph_dijkstra_free(&res_r);
	}

	return 0;

out_error:
	graph_dijkstra_free(&res_i);
	graph_dijkstra_free(&res_r);

	return -1;
}

struct arraylist *build_segpath(struct graph *g, struct pathspec *pspec)
{
	struct arraylist *res, *path;
	struct node *cur_node;
	struct graph *gc;
	struct dres gres;
	unsigned int i;

	res = alist_new(sizeof(struct segment));
	if (!res)
		return NULL;

	path = alist_new(sizeof(struct node *));
	if (!path)
		return NULL;

	gc = graph_clone(g);

	if (pspec->prune)
		pspec->prune(gc, pspec);

	cur_node = pspec->src;

	if (pspec->via)
		alist_append(path, pspec->via);

	alist_insert(path, &pspec->dst);

	for (i = 0; i < path->elem_count; i++) {
		struct arraylist *tmp_paths, *tmp_path, *rev_path;
		struct node *tmp_node;
		struct segment s;

		alist_get(path, i, &tmp_node);

		graph_dijkstra(gc, cur_node, &gres, pspec->d_ops, pspec->data);
		tmp_paths = hmap_get(gres.path, tmp_node);
		if (!tmp_paths->elem_count)
			goto out_error;

		/* XXX modify here to support backup paths or modify
		 * path selection (e.g., random).
		 */
		alist_get(tmp_paths, 0, &tmp_path);
		rev_path = alist_copy_reverse(tmp_path);
		alist_insert_at(rev_path, &cur_node, 0);

		if (graph_minseg(g, rev_path, res) < 0)
			goto out_error;

		/* append waypoint segment only if there is no adjacency
		 * segment for the last hop (i.e. breaking link bundle)
		 */
		alist_get(res, res->elem_count - 1, &s);
		if (!(s.adjacency && s.edge->remote == tmp_node)) {
			s.adjacency = false;
			s.node = tmp_node;
			alist_insert(res, &s);
		}

		alist_destroy(rev_path);
		cur_node = tmp_node;

		graph_dijkstra_free(&gres);
	}

	graph_destroy(gc, true);
	alist_destroy(path);
	return res;

out_error:
	graph_dijkstra_free(&gres);
	graph_destroy(gc, true);
	alist_destroy(path);
	alist_destroy(res);
	return NULL;
}
