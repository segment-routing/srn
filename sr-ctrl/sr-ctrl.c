#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#include "arraylist.h"
#include "misc.h"
#include "srdb.h"
#include "rules.h"
#include "hashmap.h"
#include "graph.h"
#include "lpm.h"
#include "sr-ctrl.h"
#include "mq.h"

#define DEFAULT_CONFIG	"sr-ctrl.conf"

struct provider {
	char router[SLEN + 1];
	char name[SLEN + 1];
	char addr[SLEN + 1];
	char prefix_len;
	int priority;
};

struct provider internal_provider = {
	.name = "internal",
	.addr = "::",
	.prefix_len = 0,
	.priority = 0
};

struct config {
	char rules_file[SLEN + 1];
	struct ovsdb_config ovsdb_conf;
	unsigned int worker_threads;
	unsigned int req_queue_size;
	struct provider *providers;
	unsigned int nb_providers;

	/* internal data */
	struct srdb *srdb;
	struct arraylist *rules;
	struct rule *defrule;
	struct graph *graph;
	struct hashmap *routers;
	struct lpm_tree *prefixes;
	struct mqueue *req_queue;
};

static struct config _cfg;

static void config_set_defaults(struct config *cfg)
{
	strcpy(cfg->rules_file, "rules.conf");
	strcpy(cfg->ovsdb_conf.ovsdb_client, "ovsdb-client");
	strcpy(cfg->ovsdb_conf.ovsdb_server, "tcp:[::1]:6640");
	strcpy(cfg->ovsdb_conf.ovsdb_database, "SR_test");
	cfg->worker_threads = 1;
	cfg->req_queue_size = 16;
	cfg->providers = &internal_provider;
	cfg->nb_providers = 1;
}

static int set_status(struct srdb_flowreq_entry *req, enum flowreq_status st,
		      struct queue_thread *input, struct queue_thread *output)
{
	struct srdb_table *tbl;

	tbl = srdb_table_by_name(_cfg.srdb->tables, "FlowReq");
	req->status = st;

	return srdb_update(_cfg.srdb, tbl, (struct srdb_entry *)req, "status",
			   input, output);
}

static int commit_flow(struct srdb_flowreq_entry *req, struct router *rt,
		       struct flow *fl, struct queue_thread *input,
		       struct queue_thread *output)
{
	struct srdb_flow_entry flow_entry;
	unsigned int i;
	unsigned int j = 0;
	unsigned int k = 0;
	unsigned int p = 0;
	unsigned int m = 0;
	int length = 0;
	int ret = 0;

	memset(&flow_entry, 0, sizeof(flow_entry));

	memcpy(flow_entry.destination, fl->dst, SLEN);
	memcpy(flow_entry.source, fl->src, SLEN);
	inet_ntop(AF_INET6, &fl->dstaddr, flow_entry.dstaddr, INET6_ADDRSTRLEN);


	flow_entry.segments = calloc(1, SLEN_LIST + 1);
	if (!flow_entry.segments)
		return -1;

	for (i = 0; i < fl->nb_prefixes; i++) {
		length = snprintf(flow_entry.sourceIPs + j, SLEN_LIST + 1 - j,
				  "%s[%d,\"%s\",%d]%s", i == 0 ? "[" : "",
				  fl->src_prefixes[i].priority, fl->src_prefixes[i].addr,
				  fl->src_prefixes[i].prefix_len,
				  i == fl->nb_prefixes - 1 ? "]" : ",");
		if (length >= (int) (SLEN_LIST + 1 - j))
			goto err_many_segs;
		j += length;

		length = snprintf(flow_entry.bsid + k, SLEN_LIST + 1 - k, "%s\"", i == 0 ? "[" : "");
		if (length >= (int) (SLEN_LIST + 1 - k))
			goto err_many_segs;
		k += length;

		inet_ntop(AF_INET6, &fl->src_prefixes[i].bsid, flow_entry.bsid + k, SLEN_LIST + 1 - k);
		k += strlen(flow_entry.bsid + k);

		length = snprintf(flow_entry.bsid + k, SLEN_LIST + 1 - k, "\"%s",
				  i == fl->nb_prefixes - 1 ? "]" : ",");
		if (length >= (int) (SLEN_LIST + 1 - k))
			goto err_many_segs;
			k += length;

		length = snprintf(flow_entry.segments + m, SLEN_LIST + 1 - m, "%s[", i == 0 ? "[" : "");
		if (length >= (int) (SLEN_LIST + 1 - m))
			goto err_many_segs;
		m += length;
		for (p = 0; p < fl->src_prefixes[i].segs->elem_count; p++) {
			struct segment *s;
			struct in6_addr *seg_addr;

			flow_entry.segments[m] = '"';
			m++;

			s = alist_elem(fl->src_prefixes[i].segs, p);
			if (!s->adjacency) {
				struct router *r;

				r = s->node->data;
				seg_addr = &r->addr;
			} else {
				struct link *l;

				l = s->edge->data;
				seg_addr = &l->remote;
			}

			inet_ntop(AF_INET6, seg_addr, flow_entry.segments + m, SLEN_LIST + 1 - m);
			m += strlen(flow_entry.segments + m);
			if (m + 1 >= SLEN_LIST)
				goto err_many_segs;

			flow_entry.segments[m] = '"';
			m++;
			if (p < fl->src_prefixes[i].segs->elem_count - 1) {
				flow_entry.segments[m] = ',';
				m++;
			}
		}
		length = snprintf(flow_entry.segments + m, SLEN_LIST + 1 - m, "]%s",
				  i == fl->nb_prefixes - 1 ? "]" : ",");
		if (length >= (int) (SLEN_LIST + 1 - m))
		goto err_many_segs;
		m += length;
	}

	memcpy(flow_entry.router, rt->name, SLEN);
	memcpy(flow_entry.proxy, req->proxy, SLEN);

	flow_entry.bandwidth = fl->bw;
	flow_entry.delay = fl->delay;
	flow_entry.ttl = fl->ttl;
	flow_entry.idle = fl->idle;
	flow_entry.timestamp = time(NULL);
	flow_entry.status = FLOW_STATUS_ACTIVE;

	memcpy(flow_entry.request_id, req->request_id, SLEN);

	ret = srdb_insert(_cfg.srdb,
			  srdb_table_by_name(_cfg.srdb->tables, "FlowState"),
			  (struct srdb_entry *)&flow_entry, NULL, input, output);

out:
	free(flow_entry.segments);

	return ret;
err_many_segs:
	ret = -1;
	goto out;
}

static void generate_bsid(struct router *rt, struct in6_addr *res)
{
	int len = (128 - rt->pbsid.len) >> 3;
	memcpy(res, &rt->pbsid.addr, sizeof(struct in6_addr));
	get_random_bytes((unsigned char *)res + (16 - len), len);
}

static void generate_unique_bsid(struct router *rt, struct in6_addr *res)
{
	do {
		generate_bsid(rt, res);
	} while (hmap_key_exist(rt->flows, res));
}

static bool prune_bw(struct edge *e, void *arg)
{
	uint32_t bw = (uintptr_t)arg;
	struct link *link;

	link = (struct link *)e->data;

	return link->ava_bw < bw;
}

static void pre_prune(struct graph *g, struct pathspec *pspec)
{
	struct flow *fl = pspec->data;

	if (fl->bw)
		graph_prune(g, prune_bw, (void *)(uintptr_t)fl->bw);
}

static void delay_init(struct graph *g, struct node *src, void **state,
		       void *data __unused)
{
	struct hashmap *dist;
	struct node *n;
	unsigned int i;

	dist = hmap_new(hash_node, compare_node);

	for (i = 0; i < g->nodes->elem_count; i++) {
		alist_get(g->nodes, i, &n);

		if (n->id == src->id)
			hmap_set(dist, n, (void *)(uintptr_t)0);
		else
			hmap_set(dist, n, (void *)(uintptr_t)UINT32_MAX);
	}

	*state = dist;
}

static void delay_destroy(void *state)
{
	hmap_destroy(state);
}

static uint32_t delay_below_cost(uint32_t cur_cost, struct edge *e, void *state,
				 void *data)
{
	struct hashmap *dist = state;
	struct flow *fl = data;
	uint32_t cur_delay;
	struct link *l;

	l = e->data;
	cur_delay = (uintptr_t)hmap_get(dist, e->local);

	if (cur_delay + l->delay > fl->delay)
		return UINT32_MAX;

	return cur_cost + e->metric;
}

static void delay_update(struct edge *e, void *state, void *data __unused)
{
	struct hashmap *dist = state;
	uint32_t cur_delay;
	struct link *l;

	l = e->data;
	cur_delay = (uintptr_t)hmap_get(dist, e->local);
	hmap_set(dist, e->remote, (void *)(uintptr_t)(cur_delay + l->delay));
}

struct d_ops delay_below_ops = {
	.init 		= delay_init,
	.destroy	= delay_destroy,
	.cost		= delay_below_cost,
	.update		= delay_update,
};

static bool rt_node_data_equals(void *d1, void *d2)
{
	struct router *rt1, *rt2;

	rt1 = d1;
	rt2 = d2;

	return !strcasecmp(rt1->name, rt2->name);
}

static bool rt_node_equals(struct node *n1, struct node *n2)
{
	return rt_node_data_equals(n1->data, n2->data);
}

struct graph_ops g_ops_srdns = {
	.node_equals		= rt_node_equals,
	.node_data_equals	= rt_node_data_equals,
	.node_destroy		= NULL,
	.edge_destroy		= NULL,
};

static int select_providers(struct flow *fl)
{
	/* XXX A real decision algorithm can be designed with monitoring data */
	/* XXX Lookup to BGP routing tables
	 * (for now every provider is assumed to be able to access anything)
	 */
	/* XXX Rules could also be used */
	unsigned int i;

	fl->src_prefixes = calloc(_cfg.nb_providers, sizeof(struct src_prefix));
	if (!fl->src_prefixes)
		return -1;

	fl->nb_prefixes = _cfg.nb_providers;

	for (i = 0; i < fl->nb_prefixes; i++) {
		strncpy(fl->src_prefixes[i].addr, _cfg.providers[i].addr, SLEN);
		strncpy(fl->src_prefixes[i].router, _cfg.providers[i].router,
			SLEN);
		fl->src_prefixes[i].prefix_len = _cfg.providers[i].prefix_len;
		fl->src_prefixes[i].priority = 0; /* XXX Play with it */
	}

	return fl->nb_prefixes;;
}

static void process_request(struct srdb_entry *entry,
			    struct queue_thread *input,
			    struct queue_thread *output)
{
	struct srdb_flowreq_entry *req = (struct srdb_flowreq_entry *)entry;
	struct router *rt, *dstrt;
	enum flowreq_status rstat;
	struct arraylist *segs;
	struct pathspec pspec;
	struct in6_addr addr;
	struct rule *rule;
	struct flow *fl;
	unsigned int i;

	rule = match_rules(_cfg.rules, req->source, req->destination);
	if (!rule)
		rule = _cfg.defrule;

	if (rule->type == RULE_ALLOW)
		rstat = REQ_STATUS_ALLOWED;
	else
		rstat = REQ_STATUS_DENIED;

	if (rstat == REQ_STATUS_DENIED) {
		if (set_status(req, rstat, input, output) < 0)
			pr_err("failed to update row uuid %s to status %d\n",
			       req->_row, rstat);
		return;
	}

	fl = calloc(1, sizeof(*fl));
	if (!fl) {
		set_status(req, REQ_STATUS_ERROR, input, output);
		return;
	}

	strncpy(fl->src, req->source, SLEN);
	strncpy(fl->dst, req->destination, SLEN);
	inet_pton(AF_INET6, req->dstaddr, &fl->dstaddr);
	fl->bw = rule->bw ?: req->bandwidth;
	fl->delay = rule->delay ?: req->delay;
	fl->ttl = rule->ttl;
	fl->idle = rule->idle;

	rt = hmap_get(_cfg.routers, req->router);
	if (!rt) {
		set_status(req, REQ_STATUS_NOROUTER, input, output);
		goto free_flow;
	}

	inet_pton(AF_INET6, req->dstaddr, &addr);
	dstrt = lpm_lookup(_cfg.prefixes, &addr);

	fl->srcrt = rt;
	fl->dstrt = dstrt;

	/* Negative or null return value for select_providers means that
	 * either an error occurred or no source prefix is available.
	 */
	if (select_providers(fl) <= 0) {
		if (set_status(req, REQ_STATUS_ERROR, input, output) < 0)
			pr_err("failed to update row uuid %s to status %d\n",
			       req->_row, REQ_STATUS_ERROR);
		goto free_flow;
	}

	memset(&pspec, 0, sizeof(pspec));
	pspec.src = rt->node;
	pspec.dst = dstrt->node;
	pspec.via = rule->path;
	pspec.data = fl;
	pspec.prune = pre_prune;
	if (fl->delay)
		pspec.d_ops = &delay_below_ops;

	/* Currently, all providers yield the same seglist so do not
	 * discriminate. This may change with per-prefix preferences.
	 */
	graph_read_lock(_cfg.graph);
	segs = build_segpath(_cfg.graph, &pspec);
	graph_unlock(_cfg.graph);

	if (!segs) {
		set_status(req, REQ_STATUS_UNAVAILABLE, input, output);
		goto free_src_prefixes;
	}

	fl->src_prefixes[0].segs = segs;

	hmap_write_lock(rt->flows);
	generate_unique_bsid(rt, &fl->src_prefixes[0].bsid);
	hmap_set(rt->flows, &fl->src_prefixes[0].bsid, fl);
	fl->refcount++;
	hmap_unlock(rt->flows);

	for (i = 1; i < fl->nb_prefixes; i++) {
		fl->src_prefixes[i].segs = alist_copy(segs);

		if (dstrt) {
			fl->src_prefixes[i].bsid = fl->src_prefixes[0].bsid;
		} else {
			hmap_write_lock(rt->flows);
			generate_unique_bsid(rt, &fl->src_prefixes[i].bsid);
			hmap_set(rt->flows, &fl->src_prefixes[i].bsid, fl);
			fl->refcount++;
			hmap_unlock(rt->flows);
		}
	}

	if (commit_flow(req, rt, fl, input, output)) {
		set_status(req, REQ_STATUS_ERROR, input, output);
		goto free_segs;
	}

	set_status(req, REQ_STATUS_ALLOWED, input, output);

	return;

free_segs:
	for (i = 0; i < fl->nb_prefixes; i++)
		hmap_delete(rt->flows, &fl->src_prefixes[i].bsid);

	for (i = 0; i < fl->nb_prefixes; i++)
		alist_destroy(fl->src_prefixes[i].segs);

free_src_prefixes:
	free(fl->src_prefixes);
free_flow:
	free(fl);
}

static int read_flowreq(struct srdb_entry *entry)
{
	struct srdb_flowreq_entry *req = (struct srdb_flowreq_entry *)entry;

	mq_push(_cfg.req_queue, &req);

	return 0;
}

static void routers_destroy(struct arraylist *nodes)
{
	unsigned int i;
	for (i = 0; i < nodes->elem_count; i++) {
		struct node *node;
		struct router *rt;

		alist_get(nodes, i, &node);
		rt = node->data;

		alist_destroy(rt->prefixes);

		while (rt->flows->keys->elem_count) {
			struct in6_addr *bsid;
			struct flow *fl;

			alist_get(rt->flows->keys, 0, &bsid);
			fl = hmap_get(rt->flows, bsid);
			hmap_delete(rt->flows, bsid);

			fl->refcount--;
			if (!fl->refcount) {
				free(fl->src_prefixes);
				free(fl);
			}
		}
		hmap_destroy(rt->flows);

		free(rt);
		node->data = NULL;
	}
}

static void links_destroy(struct arraylist *edges)
{
	unsigned int i;

	for (i = 0; i < edges->elem_count; i++) {
		struct edge *edge;
		struct link *link;

		alist_get(edges, i, &edge);
		link = edge->data;
		link->refcount--;

		/* Because two directed edges reference a single link */
		if (!link->refcount)
			free(link);

		edge->data = NULL;
	}
}

static int read_nodestate(struct srdb_entry *entry)
{
	struct srdb_nodestate_entry *node_entry;
	struct router *rt;
	struct prefix p;
	char **vargs;
	char **pref;
	int vargc;

	node_entry = (struct srdb_nodestate_entry *)entry;

	rt = hmap_get(_cfg.routers, node_entry->name);
	if (rt) {
		pr_err("duplicate router entry `%s'.", node_entry->name);
		return 0;
	}

	rt = calloc(1, sizeof(*rt));
	if (!rt)
		return -1;

	memcpy(rt->name, node_entry->name, SLEN);
	inet_pton(AF_INET6, node_entry->addr, &rt->addr);

	if (*node_entry->pbsid)
		pref_pton(node_entry->pbsid, &rt->pbsid);

	rt->prefixes = alist_new(sizeof(struct prefix));

	vargs = strsplit(node_entry->prefix, &vargc, ';');
	for (pref = vargs; *pref; pref++) {
		if (!**pref)
			continue;

		pref_pton(*pref, &p);
		alist_insert(rt->prefixes, &p);

		lpm_insert(_cfg.prefixes, &p.addr, p.len, rt);
	}
	free(vargs);

	rt->flows = hmap_new(hash_in6, compare_in6);

	graph_write_lock(_cfg.graph);
	rt->node = graph_add_node(_cfg.graph, rt);
	graph_unlock(_cfg.graph);

	hmap_set(_cfg.routers, rt->name, rt);

	return 0;
}

static int read_linkstate(struct srdb_entry *entry)
{
	struct srdb_linkstate_entry *link_entry;
	struct router *rt1, *rt2;
	struct link *link;
	uint32_t metric;

	link_entry = (struct srdb_linkstate_entry *)entry;

	link = calloc(1, sizeof(*link));
	if (!link)
		return -1;

	rt1 = hmap_get(_cfg.routers, link_entry->name1);
	rt2 = hmap_get(_cfg.routers, link_entry->name2);
	if (!rt1 || !rt2) {
		pr_err("unknown router entry for link (`%s', `%s').",
		       link_entry->name1, link_entry->name2);
		return 0; // TODO Discussion here if we stop monitoring
	}

	inet_pton(AF_INET6, link_entry->addr1, &link->local);
	inet_pton(AF_INET6, link_entry->addr2, &link->remote);
	link->bw = link_entry->bw;
	link->ava_bw = link_entry->ava_bw;
	link->delay = link_entry->delay;

	metric = (uint32_t)link_entry->metric ?: UINT32_MAX;
	graph_write_lock(_cfg.graph);
	graph_add_edge(_cfg.graph, rt1->node, rt2->node, metric, true, link);
	link->refcount = 2;
	graph_unlock(_cfg.graph);

	return 0;
}

#define READ_STRING(b, arg, dst) sscanf(b, #arg " \"%[^\"]\"", (dst)->arg)
#define READ_INT(b, arg, dst) sscanf(b, #arg " %i", &(dst)->arg)

static int load_config(const char *fname, struct config *cfg)
{
	char buf[128];
	int ret = 0;
	FILE *fp;

	fp = fopen(fname, "r");
	if (!fp)
		return -1;

	while (fgets(buf, 128, fp)) {
		strip_crlf(buf);
		if (READ_STRING(buf, ovsdb_client, &cfg->ovsdb_conf))
			continue;
		if (READ_STRING(buf, ovsdb_server, &cfg->ovsdb_conf))
			continue;
		if (READ_STRING(buf, ovsdb_database, &cfg->ovsdb_conf))
			continue;
		if (READ_STRING(buf, rules_file, cfg))
			continue;
		if (READ_INT(buf, worker_threads, cfg)) {
			if (!cfg->worker_threads)
				cfg->worker_threads = 1;
			continue;
		}
		if (READ_INT(buf, req_queue_size, cfg)) {
			if (!cfg->req_queue_size)
				cfg->req_queue_size = 1;
			continue;
		}
		if (!strncmp(buf, "providers ", 10)) {
			unsigned int i = 0;
			char *ptr = buf + 10;
			for (ptr = buf; *ptr; ptr++) {
				if (*ptr == ' ' || *ptr == '/') {
					*ptr = '\0';
					i++;
				}
			}
			ptr = buf + 10;
			cfg->nb_providers = i / 4;
			cfg->providers = malloc(sizeof(struct provider) * cfg->nb_providers);
			for (i = 0; i < cfg->nb_providers; i++) {
				strncpy(cfg->providers[i].name, ptr, SLEN + 1);
				ptr += strlen(ptr) + 1;
				strncpy(cfg->providers[i].addr, ptr, SLEN + 1);
				ptr += strlen(ptr) + 1;
				cfg->providers[i].prefix_len = (char) strtol(ptr, NULL, 10);
				ptr += strlen(ptr) + 1;
				ptr += strlen(ptr) + 1; /* via */
				strncpy(cfg->providers[i].router, ptr, SLEN + 1);
				ptr += strlen(ptr) + 1;
			}
			continue;
		}
		pr_err("parse error: unknown line `%s'.", buf);
		ret = -1;
		break;
	}

	fclose(fp);
	return ret;
}

static void *thread_transact(__attribute__((unused)) void *_arg)
{
	struct queue_thread *input = _arg;
	struct queue_thread *output = input + 1;
	srdb_transaction(&_cfg.srdb->conf, input, output);
	return NULL;
}

static void *thread_worker(void *arg __unused)
{
	struct srdb_entry *entry;
	struct srdb_table *tbl;

	pthread_t transact_thread;

	tbl = srdb_table_by_name(_cfg.srdb->tables, "FlowReq");

	struct queue_thread queues[2];
	struct queue_thread *transact_input = &queues[0];
	struct queue_thread *transact_output = &queues[1];
	mqueue_init(transact_input, _cfg.req_queue_size);
	mqueue_init(transact_output, _cfg.req_queue_size);
	pthread_create(&transact_thread, NULL, thread_transact, queues);

	for (;;) {
		mq_pop(_cfg.req_queue, &entry);
		if (!entry)
			break;
		process_request(entry, transact_input, transact_output);
		free_srdb_entry(tbl->desc, entry);
	}

	mqueue_close(transact_input, 1, 2);
	mqueue_close(transact_output, 1, 2);

	pthread_join(transact_thread, NULL);

	mqueue_destroy(transact_input);
	mqueue_destroy(transact_output);

	return NULL;
}

struct monitor_arg {
	struct srdb *srdb;
	struct srdb_table *table;
	int modify;
	int initial;
	int insert;
	int delete;
};

static void *thread_monitor(void *_arg)
{
	struct monitor_arg *arg = _arg;
	int ret;

	ret = srdb_monitor(arg->srdb, arg->table, arg->modify, arg->initial,
			   arg->insert, arg->delete);

	return (void *)(intptr_t)ret;
}

static void launch_srdb(pthread_t *thr, struct monitor_arg *args)
{
	struct srdb_table *tbl;
	struct timeval tv;

	/* The tables need to be read in specific order: first nodes,
	 * then links, finally flow requests. With the existing OVSDB
	 * interface, it is not possible to know in advance the number
	 * of initial rows. The workaround is to wait for 200 ms after
	 * the latest insertion in each table before reading the next
	 * table. This timer might be changed according to network
	 * conditions. Fortunately, this ugly hack is only performed
	 * at initialization.
	 */

	tbl = srdb_table_by_name(_cfg.srdb->tables, "NodeState");
	srdb_set_read_cb(_cfg.srdb, "NodeState", read_nodestate);
	args[0].srdb = _cfg.srdb;
	args[0].table = tbl;
	args[0].initial = 1;
	args[0].modify = 1;
	args[0].insert = 1;
	args[0].delete = 1;

	printf("starting nodestate\n");

	gettimeofday(&tbl->last_read, NULL);
	pthread_create(&thr[0], NULL, thread_monitor, (void *)&args[0]);

	do {
		gettimeofday(&tv, NULL);
		usleep(100000);
	} while (getmsdiff(&tv, &tbl->last_read) < 200);

	printf("starting linkstate\n");

	tbl = srdb_table_by_name(_cfg.srdb->tables, "LinkState");
	srdb_set_read_cb(_cfg.srdb, "LinkState", read_linkstate);
	args[1].srdb = _cfg.srdb;
	args[1].table = tbl;
	args[1].initial = 1;
	args[1].modify = 1;
	args[1].insert = 1;
	args[1].delete = 1;

	gettimeofday(&tbl->last_read, NULL);
	pthread_create(&thr[1], NULL, thread_monitor, (void *)&args[1]);

	do {
		gettimeofday(&tv, NULL);
		usleep(100000);
	} while (getmsdiff(&tv, &tbl->last_read) < 200);

	printf("starting flowreq\n");

	tbl = srdb_table_by_name(_cfg.srdb->tables, "FlowReq");
	srdb_set_read_cb(_cfg.srdb, "FlowReq", read_flowreq);
	tbl->delayed_free = true;
	args[2].srdb = _cfg.srdb;
	args[2].table = tbl;
	args[2].initial = 1;
	args[2].modify = 0;
	args[2].insert = 1;
	args[2].delete = 0;

	pthread_create(&thr[2], NULL, thread_monitor, (void *)&args[2]);
}

int main(int argc, char **argv)
{
	const char *conf = DEFAULT_CONFIG;
	struct monitor_arg margs[3];
	pthread_t mon_thr[3];
	pthread_t *workers;
	unsigned int i;
	int ret = 0;

	if (argc > 2) {
		fprintf(stderr, "Usage: %s [configfile]\n", argv[0]);
		return -1;
	}

	if (argc == 2)
		conf = argv[1];

	config_set_defaults(&_cfg);

	if (load_config(conf, &_cfg) < 0) {
		pr_err("failed to load configuration file.");
		return -1;
	}

	_cfg.rules = load_rules(_cfg.rules_file, &_cfg.defrule);
	if (!_cfg.rules) {
		pr_err("failed to load rules file.");
		ret = -1;
		goto free_conf;
	}

	_cfg.srdb = srdb_new(&_cfg.ovsdb_conf);
	if (!_cfg.srdb) {
		pr_err("failed to initialize SRDB.");
		ret = -1;
		goto free_rules;
	}

	_cfg.graph = graph_new(&g_ops_srdns);
	if (!_cfg.graph) {
		pr_err("failed to initialize network graph.");
		ret = -1;
		goto free_srdb;
	}

	_cfg.routers = hmap_new(hash_str, compare_str);
	if (!_cfg.routers) {
		pr_err("failed to initialize routers map.");
		ret = -1;
		goto free_graph;
	}

	_cfg.prefixes = lpm_new();
	if (!_cfg.prefixes) {
		pr_err("failed to initialize prefix tree.");
		ret = -1;
		goto free_routers_hmap;
	}

	_cfg.req_queue = mq_init(_cfg.req_queue_size,
				 sizeof(struct srdb_entry *));
	if (!_cfg.req_queue) {
		pr_err("failed to initialize request queue.\n");
		ret = -1;
		goto free_lpm;
	}

	workers = malloc(_cfg.worker_threads * sizeof(pthread_t));
	if (!workers) {
		pr_err("failed to allocate space for worker threads.\n");
		ret = -1;
		goto free_req_queue;
	}

	for (i = 0; i < _cfg.worker_threads; i++)
		pthread_create(&workers[i], NULL, thread_worker, NULL);

	launch_srdb(mon_thr, margs);

	for (i = 0; i < sizeof(mon_thr) / sizeof(pthread_t); i++)
		pthread_join(mon_thr[i], NULL);

	for (i = 0; i < sizeof(mon_thr) / sizeof(pthread_t); i++) {
		void *null_entry = NULL;

		mq_push(_cfg.req_queue, &null_entry);
	}

	for (i = 0; i < _cfg.worker_threads; i++)
		pthread_join(workers[i], NULL);

	free(workers);
free_req_queue:
	mq_destroy(_cfg.req_queue);
free_lpm:
	lpm_destroy(_cfg.prefixes);
free_routers_hmap:
	hmap_destroy(_cfg.routers);
free_graph:
	routers_destroy(_cfg.graph->nodes);
	links_destroy(_cfg.graph->edges);
	graph_destroy(_cfg.graph, false);
free_srdb:
	srdb_destroy(_cfg.srdb);
free_rules:
	destroy_rules(_cfg.rules, _cfg.defrule);
free_conf:
	if (_cfg.providers && _cfg.providers != &internal_provider)
		free(_cfg.providers);
	return ret;
}
