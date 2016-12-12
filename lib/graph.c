#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>

#include "graph.h"

struct graph *graph_new(void)
{
    struct graph *g;

    g = malloc(sizeof(*g));
    if (!g)
        return NULL;

    memset(g, 0, sizeof(*g));

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

    return g;
}

void graph_destroy(struct graph *g, int shallow)
{
    struct edge *e;
    struct node *n;

    while (g->edges->elem_count > 0) {
        e = *(struct edge **)alist_elem(g->edges, 0);
        graph_remove_edge(g, e->id);
        if (!shallow)
            free(e);
    }

    while (g->nodes->elem_count > 0) {
        n = *(struct node **)alist_elem(g->nodes, 0);
        graph_remove_node(g, n->id);
        if (!shallow)
            free(n);
    }

    alist_destroy(g->edges);
    alist_destroy(g->nodes);

    if (g->medges)
        free(g->medges);
    free(g);
}

int graph_add_node(struct graph *g, uint32_t node_id)
{
    struct node *node;

    node = malloc(sizeof(*node));
    if (!node)
        return -1;

    node->id = node_id;

    alist_insert(g->nodes, &node);

    return 0;
}

struct node *graph_remove_node(struct graph *g, int id)
{
    struct node *node;
    int i;

    for (i = 0; i < g->nodes->elem_count; i++) {
        node = *(struct node **)alist_elem(g->nodes, i);
        if (node->id == id) {
            alist_remove(g->nodes, i);
            return node;
        }
    }

    return NULL;
}

struct node *graph_get_node(struct graph *g, int node_id)
{
    int i;
    struct arraylist *nodes = g->nodes;
    struct node **node_ptr, *node;

    for (i = 0; i < nodes->elem_count; i++) {
        node_ptr = alist_elem(nodes, i);
        node = *node_ptr;
        if (node->id == node_id)
            return node;
    }

    return NULL;
}

struct edge *graph_add_edge(struct graph *g, uint32_t edge_id, uint32_t n1, uint32_t n2, uint32_t metric, uint32_t bw)
{
    struct edge *edge;

    edge = malloc(sizeof(*edge));
    if (!edge)
        return NULL;

    edge->id = edge_id;
    edge->n1 = n1;
    edge->n2 = n2;
    edge->metric = metric;
    edge->bw = bw;
    edge->ava_bw = bw;

    alist_insert(g->edges, &edge);

    return edge;
}

struct edge *graph_remove_edge(struct graph *g, int id)
{
    struct edge *edge;
    int i;

    for (i = 0; i < g->edges->elem_count; i++) {
        edge = *(struct edge **)alist_elem(g->edges, i);
        if (edge->id == id) {
            alist_remove(g->edges, i);
            return edge;
        }
    }

    return NULL;
}

struct edge *graph_get_edge(struct graph *g, int n1, int n2)
{
    int i;
    struct arraylist *edges = g->edges;
    struct edge *edge;

    for (i = 0; i < edges->elem_count; i++) {
        edge = *(struct edge **)alist_elem(edges, i);
        if ((edge->n1 == n1 && edge->n2 == n2) || (edge->n1 == n2 && edge->n2 == n1))
            return edge;
    }

    return NULL;
}

struct edge *__graph_get_minimal_edge(struct graph *g, int n1, int n2)
{   
    int i; 
    struct arraylist *edges = g->edges;
    struct edge *edge, *res = NULL;
    uint32_t weight = UINT32_MAX;
    
    for (i = 0; i < edges->elem_count; i++) {
        edge = *(struct edge **)alist_elem(edges, i);
        if ((edge->n1 == n1 && edge->n2 == n2) || (edge->n1 == n2 && edge->n2 == n1)) {
            if (edge->metric < weight)
                res = edge;
        }
    }

    return res;
}

void graph_compute_minimal_edges(struct graph *g)
{
    int i, j;
    struct node *n1, *n2;

    if (g->medges)
        free(g->medges);

    g->medges = malloc(g->nodes->elem_count * g->nodes->elem_count * sizeof(struct edge *));

    for (i = 0; i < g->nodes->elem_count; i++) {
        n1 = *(struct node **)alist_elem(g->nodes, i);
        for (j = 0; j < g->nodes->elem_count; j++) {
            n2 = *(struct node **)alist_elem(g->nodes, j);
            g->medges[n1->id + n2->id*g->nodes->elem_count] = __graph_get_minimal_edge(g, n1->id, n2->id);
        }
    }
}

struct edge *graph_get_minimal_edge(struct graph *g, int n1, int n2)
{
    if (g->medges)
        return g->medges[n1 + n2*g->nodes->elem_count];

    return __graph_get_minimal_edge(g, n1, n2);
}

struct arraylist *graph_get_neighbors(struct graph *g, int nid)
{
    struct arraylist *neighs;
    int i, n;
    struct edge *edge;
    struct node *node;

    neighs = alist_new(sizeof(struct node *));
    if (!neighs)
        return NULL;

    for (i = 0; i < g->edges->elem_count; i++) {
        n = -1;
        edge = *(struct edge **)alist_elem(g->edges, i);
        if (edge->n1 == nid)
            n = edge->n2;
        else if (edge->n2 == nid)
            n = edge->n1;
        if (n == -1)
            continue;
        node = graph_get_node(g, n);
        if (alist_exist(neighs, &node))
            continue;
        alist_insert(neighs, &node);
    }

    return neighs;
}

struct graph *graph_clone(struct graph *g)
{
    struct graph *g_clone;

    g_clone = malloc(sizeof(*g_clone));
    if (!g_clone)
        return NULL;

    memset(g_clone, 0, sizeof(*g_clone));

    g_clone->nodes = alist_copy(g->nodes);
    if (!g_clone->nodes) {
        free(g_clone);
        return NULL;
    }

    g_clone->edges = alist_copy(g->edges);
    if (!g_clone->edges) {
        alist_destroy(g_clone->nodes);
        free(g_clone);
        return NULL;
    }

    return g_clone;
}

int graph_highest_node(struct graph *g)
{
    int nmax = -1;
    int i;
    struct node *n;

    for (i = 0; i < g->nodes->elem_count; i++) {
        n = *(struct node **)alist_elem(g->nodes, i);
        if (n->id > nmax)
            nmax = n->id;
    }

    return nmax;
}

void graph_dijkstra(struct graph *g, int src, struct dres *res)
{
    uint32_t *dist;
    struct node **prev;
    struct arraylist **path;
    struct arraylist *Q;
    int n_nodes;
    int i;
    struct node *node;

//    n_nodes = g->nodes->elem_count;
    n_nodes = graph_highest_node(g) + 1;

    dist = malloc(n_nodes * sizeof(uint32_t));
    prev = malloc(n_nodes * sizeof(struct node *));
    path = malloc(n_nodes * sizeof(struct arraylist *));

    Q = alist_new(sizeof(struct node *));

    for (i = 0; i < g->nodes->elem_count; i++) {
        node = *(struct node **)alist_elem(g->nodes, i);

        if (node->id == src)
            dist[node->id] = 0;
        else
            dist[node->id] = UINT32_MAX;

        prev[node->id] = NULL;
        path[node->id] = NULL;

        alist_insert(Q, &node);
    }

    while (Q->elem_count > 0) {
        struct node *u, *v, *w;
        struct arraylist *neighs;
        struct arraylist *S = NULL;
        uint32_t tmpcost;
        int u_idx = -1;

        tmpcost = UINT32_MAX;
        u = NULL;

        for (i = 0; i < Q->elem_count; i++) {
            v = *(struct node **)alist_elem(Q, i);
//            printf("dist[%d]: %u, tmpcost: %u\n", v->id, dist[v->id], tmpcost);
            if (dist[v->id] < tmpcost) {
                tmpcost = dist[v->id];
                u = v;
                u_idx = i;
            }
        }

        if (u_idx == -1) {
//            printf("graph is disconnected, no more edge available, exiting\n");
            break;
        }

//        printf("u_idx: %d\n", u_idx);

        S = alist_new(sizeof(struct node *));
        w = u;
//        printf("w: %p\n", w);
        while (prev[w->id] != NULL) {
            alist_insert(S, &w);
            w = prev[w->id];
        }

        if (path[u->id])
            alist_destroy(path[u->id]);
        path[u->id] = alist_copy_reverse(S);

//        printf("Removing u %d\n", u->id);
        alist_remove(Q, u_idx);

        neighs = graph_get_neighbors(g, u->id);
        for (i = 0; i < neighs->elem_count; i++) {
            uint32_t alt;

            v = *(struct node **)alist_elem(neighs, i);
            if (!alist_exist(Q, &v))
                continue;
            alt = dist[u->id] + graph_get_minimal_edge(g, u->id, v->id)->metric;
            if (alt < dist[v->id]) {
//                printf("updating dist[%d] to %d\n", v->id, alt);
                dist[v->id] = alt;
                prev[v->id] = u;
            }
        }
        alist_destroy(neighs);
        if (S) {
            alist_destroy(S);
            S = NULL;
        }
    }

    free(prev);
    alist_destroy(Q);

    res->dist = dist;
    res->path = path;
    res->n_nodes = n_nodes;
}

void graph_dijkstra_free(struct dres *res)
{
    int i;

    for (i = 0; i < res->n_nodes; i++) {
        if (res->path[i])
            alist_destroy(res->path[i]);
    }

    free(res->path);
    free(res->dist);
}

/*void graph_remove_disconnected(struct graph *g)
{
    int i;
    struct node *n;
    struct arraylist *toprune, *neighs;

    toprune = alist_new(sizeof(struct node *));

    for (i = 0; i < g->nodes->elem_count; i++) {
        n = *(struct node **)alist_elem(g->nodes, i);
        neighs = graph_get_neighbors(g, n->id);

        if (neighs->elem_count == 0)
            alist_insert(toprune, &n);

        alist_destroy(neighs);
    }

    printf("pruning %d nodes\n", toprune->elem_count);

    for (i = 0; i < toprune->elem_count; i++) {
        n = *(struct node **)alist_elem(toprune, i);
        graph_remove_node(g, n->id);
    }

    alist_destroy(toprune);
}*/

int graph_prune(struct graph *g, bool (*prune)(struct edge *e, void *arg), void *_arg)
{
    int i;
    struct edge *e;
    int cnt = g->edges->elem_count;
    int rm = 0;

    for (i = 0; i < cnt; i++) {
        e = *(struct edge **)alist_elem(g->edges, i);
        if (prune(e, _arg)) {
            graph_remove_edge(g, e->id);
            i = 0;
            cnt = g->edges->elem_count;
            rm++;
        }
    }

//    printf("pruned %d edges\n", rm);

    return rm;
}

static bool prune_min_bw(struct edge *e, void *arg)
{
    uint32_t bw = (uint64_t)arg;

    if (e->bw < bw)
        return true;

    return false;
}

struct graph *read_topo(const char *fname)
{
    FILE *fp;
    struct graph *g;
    char line[256];
    char *s;
    int n1, n2, eid = 0;
    uint32_t bw;

    fp = fopen(fname, "r");
    if (!fp)
        return NULL;

    g = graph_new();

    while (fgets(line, 255, fp)) {
        s = strtok(line, " ");
        n1 = atoi(s);
        s = strtok(NULL, " ");
        n2 = atoi(s);
        s = strtok(NULL, " ");
        bw = strtoul(s, NULL, 10);

        if (!graph_get_node(g, n1))
            graph_add_node(g, n1);
        if (!graph_get_node(g, n2))
            graph_add_node(g, n2);

        graph_add_edge(g, eid++, n1, n2, 1, bw);
    }

    fclose(fp);

    return g;
}

void run_test(struct graph *g, int src);

int main(int ac, char **av)
{
    struct graph *g;
    int i;
    struct node *n;

    g = read_topo(av[1]);
    if (!g) {
        printf("cannot read graph\n");
        return -1;
    }

    printf("# %d nodes, %d edges\n", g->nodes->elem_count, g->edges->elem_count);

    graph_compute_minimal_edges(g);

    for (i = 0; i < g->nodes->elem_count; i++) {
        struct timeval tv1, tv2, tvres;
        n = *(struct node **)alist_elem(g->nodes, i);
        gettimeofday(&tv1, NULL);
        run_test(g, n->id);
        gettimeofday(&tv2, NULL);
        timersub(&tv2, &tv1, &tvres);
        printf("%lu\n", tvres.tv_usec);
    }

    graph_destroy(g, 0);

    return 0;
}

void run_test(struct graph *g, int src)
{
//    struct graph *g2;
    struct dres res;
    struct arraylist *rpath;
    struct node *n;
    int i;

//    g2 = graph_clone(g);
//    graph_compute_minimal_edges(g2);
//    graph_prune(g2, prune_min_bw, (void *)2500);

    graph_dijkstra(g, src, &res);

/*    printf("distance to node 11: %u\n", res.dist[11]);
    printf("path to node 11: %p\n", res.path[11]);
    rpath = res.path[11];

    if (rpath) {
        for (i = 0; i < rpath->elem_count; i++) {
            n = *(struct node **)alist_elem(rpath, i);
            printf("%d ", n->id);
        }
        printf("\n");
    }*/

    graph_dijkstra_free(&res);
//    graph_destroy(g2, 1);
}

int main2()
{
    struct graph *g, *g2;
    struct dres res;

    g = graph_new();

    graph_add_node(g, 0);
    graph_add_node(g, 1);
    graph_add_node(g, 2);
    graph_add_node(g, 3);

    graph_add_edge(g, 0, 0, 1, 10, 90);
    graph_add_edge(g, 1, 0, 2, 10, 100);
    graph_add_edge(g, 2, 1, 3, 10, 100);
    graph_add_edge(g, 3, 2, 3, 20, 100);

    g2 = graph_clone(g);
    graph_prune(g2, prune_min_bw, (void *)95);

    graph_dijkstra(g2, 0, &res);

    printf("distance to node 3: %u\n", res.dist[3]);

    graph_dijkstra_free(&res);

    graph_destroy(g2, 1);
    graph_destroy(g, 0);

    return 0;
}
