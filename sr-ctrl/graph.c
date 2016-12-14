#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>

#include "graph.h"
#include "misc.h"

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

static int compare_node(void *k1, void *k2)
{
	return !(((struct node *)k1)->id == ((struct node *)k2)->id);
}

static unsigned int hash_node(void *key)
{
	return hashint(((struct node *)key)->id);
}

struct graph *graph_new(void)
{
	struct graph *g;

	g = calloc(1, sizeof(*g));
	if (!g)
		return NULL;

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

	return g;
}

void graph_destroy(struct graph *g, bool shallow)
{
	struct edge *e;
	struct node *n;

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
	hmap_destroy(g->min_edges);
	hmap_destroy(g->neighs);

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

	return node;
}

static int get_node_index(struct arraylist *nodes, unsigned int id)
{
	struct node *node;
	int i;

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
	int i;

	for (i = 0; i < edges->elem_count; i++) {
		alist_get(edges, i, &edge);
		if (edge->id == id)
			return i;
	}

	return -1;
}

void graph_remove_node(struct graph *g, struct node *node)
{
	int i;

	i = get_node_index(g->nodes, node->id);
	if (i < 0)
		return;

	alist_remove(g->nodes, i);
}

struct node *graph_get_node(struct graph *g, unsigned int id)
{
	struct node *node;
	int i;

	for (i = 0; i < g->nodes->elem_count; i++) {
		alist_get(g->nodes, i, &node);
		if (node->id == id)
			return node;
	}

	return NULL;
}

struct edge *graph_add_edge(struct graph *g, struct node *local,
			    struct node *remote)
{
	struct edge *edge;

	edge = calloc(1, sizeof(*edge));
	if (!edge)
		return NULL;

	edge->id = ++g->last_edge;
	edge->local = local;
	edge->remote = remote;

	alist_insert(g->edges, &edge);

	return edge;
}

void graph_remove_edge(struct graph *g, struct edge *edge)
{
	int i;

	i = get_edge_index(g->edges, edge->id);
	if (i < 0)
		return;

	alist_remove(g->edges, i);
}

static struct edge *graph_get_minimal_edge(struct graph *g, struct node *local,
					   struct node *remote)
{
	struct edge *edge, *res = NULL;
	uint32_t metric = UINT32_MAX;
	int i;

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
	int i, j;

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
	int i;

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
	int i;

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

	g_clone = graph_new();
	if (!g_clone)
		return NULL;

	alist_append(g_clone->nodes, g->nodes);
	alist_append(g_clone->edges, g->edges);

	graph_finalize(g_clone);

	return g_clone;
}

void graph_dijkstra(struct graph *g, struct node *src, struct dres *res)
{
	struct hashmap *dist, *prev, *path;
	struct arraylist *Q;
	struct node *node;
	int n_nodes;
	int i;

	n_nodes = g->nodes->elem_count;

	/* dist: node -> uint32_t
	 * prev: node -> node
	 * path: node -> arraylist
	 */

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

		hmap_set(prev, node, NULL);
		hmap_set(path, node, NULL);

		alist_insert(Q, &node);
	}

	while (Q->elem_count > 0) {
		struct arraylist *S = NULL;
		struct arraylist *neighs;
		struct node *u, *v, *w;
		uint32_t cost, tmpcost;
		int u_idx = -1;
		void *val;

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

		S = alist_new(sizeof(struct node *));
		w = u;

		val = hmap_get(prev, w);
		while (val) {
			alist_insert(S, &w);
			w = val;
			val = hmap_get(prev, w);
		}

		val = hmap_get(path, u);
		if (val)
			alist_destroy(val);
		val = alist_copy_reverse(S);
		hmap_set(path, u, val);

		alist_remove(Q, u_idx);

		neighs = hmap_get(g->neighs, u);
		for (i = 0; i < neighs->elem_count; i++) {
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

			alt = u_dist + min_edge->metric;
			if (alt < v_dist) {
				hmap_set(dist, v, (void *)(uintptr_t)alt);
				hmap_set(prev, v, u);
			}
		}

		if (S) {
			alist_destroy(S);
			S = NULL;
		}
	}

	hmap_destroy(prev);
	alist_destroy(Q);

	res->dist = dist;
	res->path = path;
	res->n_nodes = n_nodes;
}

void graph_dijkstra_free(struct dres *res)
{
	int i;

	for (i = 0; i < res->path->keys->elem_count; i++) {
		struct arraylist *rpath;
		struct node *n;

		alist_get(res->path->keys, i, &n);
		rpath = hmap_get(res->path, n);
		alist_destroy(rpath);
	}

	hmap_destroy(res->path);
	hmap_destroy(res->dist);
}

int graph_prune(struct graph *g, bool (*prune)(struct edge *e, void *arg),
		void *_arg)
{
	struct edge *edge;
	int rm = 0;
	int i;

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
