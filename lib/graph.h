#ifndef _CSPF_H
#define _CSPF_H

#include <stdint.h>

#include "arraylist.h"

struct node {
    int id;
};

struct edge {
    int n1;
    int n2;

    int id;
    uint32_t metric;
    uint32_t bw;
    uint32_t ava_bw;
    uint32_t delay;
};

struct graph {
    struct arraylist *nodes;
    struct arraylist *edges;

    struct edge **medges;
};

struct dres {
    uint32_t *dist;
    struct arraylist **path;
    int n_nodes;
};

struct graph *graph_new(void);
int graph_add_node(struct graph *g, uint32_t node_id);
struct node *graph_get_node(struct graph *g, int node_id);
struct edge *graph_add_edge(struct graph *g, uint32_t edge_id, uint32_t n1, uint32_t n2, uint32_t metric, uint32_t bw);
struct edge *graph_get_edge(struct graph *g, int n1, int n2);
struct arraylist *graph_get_neighbors(struct graph *g, int nid);
struct graph *graph_clone(struct graph *g);
void graph_dijkstra(struct graph *g, int src, struct dres *res);
void graph_dijkstra_free(struct dres *res);
struct node *graph_remove_node(struct graph *g, int id);
struct edge *graph_remove_edge(struct graph *g, int id);
struct edge *__graph_get_minimal_edge(struct graph *g, int n1, int n2);
void graph_compute_minimal_edges(struct graph *g);

#endif
