#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <assert.h>

#include "llist.h"
#include "misc.h"
#include "srdb.h"
#include "rules.h"
#include "hashmap.h"
#include "graph.h"
#include "lpm.h"
#include "sr-ctrl.h"
#include "sbuf.h"

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

struct netstate {
	struct graph *graph;
	struct graph *graph_staging;
	struct timeval gs_mod;
	struct timeval gs_dirty;
	struct hashmap *routers;
	struct lpm_tree *prefixes;
	pthread_rwlock_t lock;
};

struct config {
	char rules_file[SLEN + 1];
	struct ovsdb_config ovsdb_conf;
	unsigned int worker_threads;
	unsigned int req_buffer_size;
	struct provider *providers;
	unsigned int nb_providers;
	char logfile[SLEN + 1];

	/* internal data */
	struct srdb *srdb;
	struct llist_node *rules;
	struct rule *defrule;
	struct sbuf *req_buffer;
	struct netstate ns;
	struct hashmap *flows;
};

static struct config _cfg;

static void net_state_read_lock(struct netstate *ns)
{
	pthread_rwlock_rdlock(&ns->lock);
}

static void net_state_write_lock(struct netstate *ns)
{
	pthread_rwlock_wrlock(&ns->lock);
}

static void net_state_unlock(struct netstate *ns)
{
	pthread_rwlock_unlock(&ns->lock);
}

static void config_set_defaults(struct config *cfg)
{
	strcpy(cfg->rules_file, "rules.conf");
	strcpy(cfg->ovsdb_conf.ovsdb_client, "ovsdb-client");
	strcpy(cfg->ovsdb_conf.ovsdb_server, "tcp:[::1]:6640");
	strcpy(cfg->ovsdb_conf.ovsdb_database, "SR_test");
	strcpy(cfg->logfile, "");
	cfg->ovsdb_conf.ntransacts = 1;
	cfg->worker_threads = 1;
	cfg->req_buffer_size = 16;
	cfg->providers = &internal_provider;
	cfg->nb_providers = 1;
}

static int init_netstate(struct netstate *ns)
{
	ns->graph = graph_new(&g_ops_srdns);
	if (!ns->graph)
		return -1;

	ns->graph_staging = graph_new(&g_ops_srdns);
	if (!ns->graph_staging)
		goto out_free_graph;

	ns->routers = hmap_new(hash_str, compare_str);
	if (!ns->routers)
		goto out_free_graph2;

	ns->prefixes = lpm_new();
	if (!ns->prefixes)
		goto out_free_rt;

	pthread_rwlock_init(&ns->lock, NULL);

	return 0;

out_free_rt:
	hmap_destroy(ns->routers);
out_free_graph2:
	graph_destroy(ns->graph_staging, false);
out_free_graph:
	graph_destroy(ns->graph, false);
	return -1;
}

static void destroy_netstate(void)
{
	struct netstate *ns = &_cfg.ns;
	struct hmap_entry *he;

	hmap_foreach(_cfg.flows, he)
		flow_release(he->elem);

	graph_destroy(ns->graph, false);
	graph_destroy(ns->graph_staging, false);

	hmap_foreach(ns->routers, he)
		rt_release(he->elem);

	hmap_destroy(ns->routers);

	lpm_destroy(ns->prefixes);
}

static void mark_graph_dirty(void)
{
	if (!_cfg.ns.graph_staging->dirty)
		gettimeofday(&_cfg.ns.gs_dirty, NULL);

	gettimeofday(&_cfg.ns.gs_mod, NULL);

	_cfg.ns.graph_staging->dirty = true;
}

static int netstate_graph_sync(struct netstate *ns)
{
	struct graph *g, *old_g;

	graph_read_lock(ns->graph_staging);

	if (!ns->graph_staging->dirty) {
		graph_unlock(ns->graph_staging);
		return 0;
	}

	g = graph_deepcopy(ns->graph_staging);

	graph_unlock(ns->graph_staging);

	if (!g)
		return -1;

	graph_finalize(g);
	graph_build_cache(g);

	net_state_write_lock(ns);

	old_g = ns->graph;
	ns->graph = g;

	net_state_unlock(ns);

	graph_destroy(old_g, false);

	graph_write_lock(ns->graph_staging);
	ns->graph_staging->dirty = false;
	graph_unlock(ns->graph_staging);

	return 0;
}

static int set_flowreq_status(struct srdb_flowreq_entry *req,
			      enum flowreq_status st)
{
	struct srdb_table *tbl;

	tbl = srdb_table_by_name(_cfg.srdb->tables, "FlowReq");
	req->status = st;

	return srdb_update_sync(_cfg.srdb, tbl, (struct srdb_entry *)req,
				FREQ_STATUS, NULL);
}

static int set_flow_status(struct flow *fl, enum flow_status st)
{
	struct srdb_flow_entry fe;
	struct srdb_table *tbl;

	fl->status = st;

	tbl = srdb_table_by_name(_cfg.srdb->tables, "FlowState");
	strncpy(fe._row, fl->uuid, SLEN);
	fe.status = st;

	return srdb_update_sync(_cfg.srdb, tbl, (struct srdb_entry *)&fe,
				FE_STATUS, NULL);
}

static json_t *pref_bsid_to_json(struct flow *fl)
{
	char ip[INET6_ADDRSTRLEN];
	unsigned int i;
	json_t *json;

	json = json_array();

	for (i = 0; i < fl->nb_prefixes; i++) {
		inet_ntop(AF_INET6, &fl->src_prefixes[i].bsid, ip,
			  INET6_ADDRSTRLEN);
		json_array_append_new(json, json_string(ip));
	}

	return json;
}

static json_t *pref_srcips_to_json(struct flow *fl)
{
	char ip[INET6_ADDRSTRLEN];
	unsigned int i;
	json_t *json;

	json = json_array();

	for (i = 0; i < fl->nb_prefixes; i++) {
		json_t *srcip;

		srcip = json_array();
		inet_ntop(AF_INET6, &fl->src_prefixes[i].addr, ip,
			  INET6_ADDRSTRLEN);
		json_array_append_new(srcip,
				json_integer(fl->src_prefixes[i].priority));
		json_array_append_new(srcip, json_string(ip));
		json_array_append_new(srcip,
				json_integer(fl->src_prefixes[i].prefix_len));
		json_array_append_new(json, srcip);
	}

	return json;
}

static json_t *pref_segs_to_json(struct flow *fl)
{
	char ip[INET6_ADDRSTRLEN];
	struct llist_node *iter;
	unsigned int i;
	json_t *json;

	json = json_array();

	for (i = 0; i < fl->nb_prefixes; i++) {
		json_t *segs;

		segs = json_array();
		llist_node_foreach(fl->src_prefixes[i].segs, iter) {
			struct segment *s = iter->data;
			struct in6_addr *addr;

			addr = segment_addr(s);
			inet_ntop(AF_INET6, addr, ip, INET6_ADDRSTRLEN);
			json_array_append_new(segs, json_string(ip));
		}
		json_array_append_new(json, segs);
	}

	return json;
}

static void flow_to_flowentry(struct flow *fl, struct srdb_flow_entry *fe,
			      unsigned int fields)
{
	json_t *jsegs_all, *jsrcips_all, *jbsid_all;

	memset(fe, 0, sizeof(struct srdb_flow_entry));

	memcpy(fe->_row, fl->uuid, SLEN);

	if (fields & ENTRY_MASK(FE_DESTINATION))
		memcpy(fe->destination, fl->dst, SLEN);

	if (fields & ENTRY_MASK(FE_SOURCE))
		memcpy(fe->source, fl->src, SLEN);

	if (fields & ENTRY_MASK(FE_DSTADDR))
		inet_ntop(AF_INET6, &fl->dstaddr, fe->dstaddr, INET6_ADDRSTRLEN);

	/* sourceIPs: [[5,2001:abcd::,64],[1,2001:abcd::42,64]]
	 * bsid: [bsid1,bsid2]
	 * segments: [[S1_1,S1_2,S1_3],[S2_1,S2_2]]
	 */

	if (fields & ENTRY_MASK(FE_SEGMENTS)) {
		jsegs_all = pref_segs_to_json(fl);
		fe->segments = json_dumps(jsegs_all, JSON_COMPACT);
		json_decref(jsegs_all);
	}

	if (fields & ENTRY_MASK(FE_SOURCEIPS)) {
		jsrcips_all = pref_srcips_to_json(fl);
		fe->sourceIPs = json_dumps(jsrcips_all, JSON_COMPACT);
		json_decref(jsrcips_all);
	}

	if (fields & ENTRY_MASK(FE_BSID)) {
		jbsid_all = pref_bsid_to_json(fl);
		fe->bsid = json_dumps(jbsid_all, JSON_COMPACT);
		json_decref(jbsid_all);
	}

	if (fields & ENTRY_MASK(FE_ROUTER))
		memcpy(fe->router, fl->srcrt->name, SLEN);

	if (fields & ENTRY_MASK(FE_PROXY))
		memcpy(fe->proxy, fl->proxy, SLEN);

	if (fields & ENTRY_MASK(FE_REQID))
		memcpy(fe->request_id, fl->request_id, SLEN);

	if (fields & ENTRY_MASK(FE_BANDWIDTH))
		fe->bandwidth = fl->bw;

	if (fields & ENTRY_MASK(FE_DELAY))
		fe->delay = fl->delay;

	if (fields & ENTRY_MASK(FE_TTL))
		fe->ttl = fl->ttl;

	if (fields & ENTRY_MASK(FE_IDLE))
		fe->idle = fl->idle;

	if (fields & ENTRY_MASK(FE_TS))
		fe->timestamp = fl->timestamp;

	if (fields & ENTRY_MASK(FE_STATUS))
		fe->status = fl->status;
}

static int commit_flow(struct flow *fl)
{
	struct srdb_flow_entry *fe;
	struct srdb_table *tbl;
	int ret;

	fe = malloc(sizeof(*fe));
	if (!fe)
		return -1;

	tbl = srdb_table_by_name(_cfg.srdb->tables, "FlowState");
	if (!tbl)
		return -1;

	flow_to_flowentry(fl, fe, FE_ALL);

	ret =  srdb_insert_sync(_cfg.srdb, tbl,
				(struct srdb_entry *)fe, fl->uuid);

	free_srdb_entry(tbl->desc, (struct srdb_entry *)fe);

	return ret;
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
	} while (hmap_get(_cfg.flows, res));
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

static void delay_init(const struct graph *g, struct node *src, void **state,
		       void *data __unused)
{
	struct llist_node *iter;
	struct hashmap *dist;
	struct node *n;

	dist = hmap_new(hash_node, compare_node);

	llist_node_foreach(g->nodes, iter) {
		n = iter->data;

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

static uint32_t delay_min_cost(uint32_t cur_cost, struct edge *e,
			       void *state __unused, void *data __unused)
{
	struct link *l = e->data;

	return cur_cost + l->delay;
}

struct d_ops delay_min_ops = {
	.init		= NULL,
	.destroy	= NULL,
	.cost		= delay_min_cost,
	.update		= NULL,
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

static void *rt_node_data_copy(void *data)
{
	return data;
}

static void *link_edge_data_copy(void *data)
{
	struct link *l;

	l = malloc(sizeof(*l));
	memcpy(l, data, sizeof(*l));
	l->refcount = 1;

	return l;
}

static bool link_edge_data_equals(void *d1, void *d2)
{
	struct link *l1, *l2;

	l1 = d1;
	l2 = d2;

	return !memcmp(&l1->local, &l2->local, sizeof(struct in6_addr)) &&
	       !memcmp(&l1->remote, &l2->remote, sizeof(struct in6_addr));
}

static void link_edge_destroy(struct edge *e)
{
	link_release(e->data);
}

struct graph_ops g_ops_srdns = {
	.node_equals		= rt_node_equals,
	.node_data_equals	= rt_node_data_equals,
	.edge_data_equals	= link_edge_data_equals,
	.node_destroy		= NULL,
	.edge_destroy		= link_edge_destroy,
	.node_data_copy		= rt_node_data_copy,
	.edge_data_copy		= link_edge_data_copy,
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

	return fl->nb_prefixes;
}

static void process_request(struct srdb_entry *entry)
{
	struct srdb_flowreq_entry *req = (struct srdb_flowreq_entry *)entry;
	struct node *src_node, *dst_node;
	struct router *rt, *dstrt;
	enum flowreq_status rstat;
	struct llist_node *epath;
	struct llist_node *segs;
	struct pathspec pspec;
	struct in6_addr addr;
	struct rule *rule;
	struct flow *fl;
	unsigned int i;

	if (req->status != REQ_STATUS_PENDING)
		return;

	rule = match_rules(_cfg.rules, req->source, req->destination);
	if (!rule)
		rule = _cfg.defrule;

	if (rule->type == RULE_ALLOW)
		rstat = REQ_STATUS_ALLOWED;
	else
		rstat = REQ_STATUS_DENIED;

	if (rstat == REQ_STATUS_DENIED) {
		if (set_flowreq_status(req, rstat) < 0)
			pr_err("failed to update row uuid %s to status %d\n",
			       req->_row, rstat);
		return;
	}

	fl = calloc(1, sizeof(*fl));
	if (!fl) {
		set_flowreq_status(req, REQ_STATUS_ERROR);
		return;
	}

	strncpy(fl->src, req->source, SLEN);
	strncpy(fl->dst, req->destination, SLEN);
	strncpy(fl->proxy, req->proxy, SLEN);
	strncpy(fl->request_id, req->request_id, SLEN);
	inet_pton(AF_INET6, req->dstaddr, &fl->dstaddr);
	fl->bw = rule->bw ?: req->bandwidth;
	fl->delay = rule->delay ?: req->delay;
	fl->ttl = rule->ttl;
	fl->idle = rule->idle;

	net_state_read_lock(&_cfg.ns);

	rt = hmap_get(_cfg.ns.routers, req->router);
	if (!rt) {
		set_flowreq_status(req, REQ_STATUS_NOROUTER);
		goto free_flow;
	}

	inet_pton(AF_INET6, req->dstaddr, &addr);
	dstrt = lpm_lookup(_cfg.ns.prefixes, &addr);

	if (!dstrt) {
		set_flowreq_status(req, REQ_STATUS_NOPREFIX);
		goto free_flow;
	}

	src_node = graph_get_node_noref(_cfg.ns.graph, rt->node_id);
	dst_node = graph_get_node_noref(_cfg.ns.graph, dstrt->node_id);

	/* this may happen in the rare case where a new router appeared in the
	 * network and was correspondingly inserted in the netstate, but its
	 * associated graph node is still in the staging graph.
	 */
	if (!src_node || !dst_node) {
		set_flowreq_status(req, REQ_STATUS_UNAVAILABLE);
		goto free_flow;
	}

	fl->srcrt = rt;
	fl->dstrt = dstrt;

	/* Negative or null return value for select_providers means that
	 * either an error occurred or no source prefix is available.
	 */
	if (select_providers(fl) <= 0) {
		if (set_flowreq_status(req, REQ_STATUS_ERROR) < 0)
			pr_err("failed to update row uuid %s to status %d\n",
			       req->_row, REQ_STATUS_ERROR);
		goto free_flow;
	}

	memset(&pspec, 0, sizeof(pspec));
	pspec.src = src_node;
	pspec.dst = dst_node;
	pspec.via = rule->path;
	pspec.data = fl;
	pspec.prune = pre_prune;
	if (fl->delay)
		pspec.d_ops = &delay_min_ops;

	epath = NULL;
	segs = build_segpath(_cfg.ns.graph, &pspec, &epath);

	if (!segs) {
		set_flowreq_status(req, REQ_STATUS_UNAVAILABLE);
		destroy_edgepath(epath);
		goto free_src_prefixes;
	}

	fl->src_prefixes[0].segs = segs;
	fl->src_prefixes[0].epath = epath;
	fl->refcount = 1;
	fl->timestamp = time(NULL);
	fl->status = FLOW_STATUS_ACTIVE;

	hmap_write_lock(_cfg.flows);
	generate_unique_bsid(rt, &fl->src_prefixes[0].bsid);
	hmap_set(_cfg.flows, &fl->src_prefixes[0].bsid, fl);

	for (i = 1; i < fl->nb_prefixes; i++) {
		fl->src_prefixes[i].segs = copy_segments(segs);
		fl->src_prefixes[i].epath = copy_edgepath(epath);

		if (dstrt) {
			fl->src_prefixes[i].bsid = fl->src_prefixes[0].bsid;
		} else {
			generate_unique_bsid(rt, &fl->src_prefixes[i].bsid);
			fl->refcount++;
			hmap_set(_cfg.flows, &fl->src_prefixes[i].bsid, fl);
		}
	}

	hmap_unlock(_cfg.flows);

	if (commit_flow(fl)) {
		set_flowreq_status(req, REQ_STATUS_ERROR);
		goto free_segs;
	}

	set_flowreq_status(req, REQ_STATUS_ALLOWED);

	net_state_unlock(&_cfg.ns);

	return;

free_segs:
	hmap_write_lock(_cfg.flows);
	for (i = 0; i < fl->nb_prefixes; i++)
		hmap_delete(_cfg.flows, &fl->src_prefixes[i].bsid);
	hmap_unlock(_cfg.flows);

	for (i = 0; i < fl->nb_prefixes; i++) {
		free_segments(fl->src_prefixes[i].segs);
		destroy_edgepath(fl->src_prefixes[i].epath);
	}

free_src_prefixes:
	free(fl->src_prefixes);
free_flow:
	free(fl);
	net_state_unlock(&_cfg.ns);
}

static int flowreq_read(struct srdb_entry *entry)
{
	struct srdb_flowreq_entry *req = (struct srdb_flowreq_entry *)entry;

	sbuf_push(_cfg.req_buffer, req);

	return 0;
}

static int nodestate_read(struct srdb_entry *entry)
{
	struct srdb_nodestate_entry *node_entry;
	struct node *rt_node;
	struct router *rt;
	struct prefix *p;
	char **vargs;
	char **pref;
	int ret = 0;
	int vargc;

	node_entry = (struct srdb_nodestate_entry *)entry;

	net_state_write_lock(&_cfg.ns);

	rt = hmap_get(_cfg.ns.routers, node_entry->name);
	if (rt) {
		pr_err("duplicate router entry `%s'.", node_entry->name);
		goto out_err;
	}

	rt = malloc(sizeof(*rt));
	if (!rt)
		goto out_err;

	memcpy(rt->name, node_entry->name, SLEN);
	inet_pton(AF_INET6, node_entry->addr, &rt->addr);

	if (*node_entry->pbsid)
		pref_pton(node_entry->pbsid, &rt->pbsid);

	rt->prefixes = llist_node_alloc();

	vargs = strsplit(node_entry->prefix, &vargc, ';');
	for (pref = vargs; *pref; pref++) {
		if (!**pref)
			continue;

		p = malloc(sizeof(*p));
		pref_pton(*pref, p);
		llist_node_insert_tail(rt->prefixes, p);

		lpm_insert(_cfg.ns.prefixes, &p->addr, p->len, rt);
	}
	free(vargs);

	graph_write_lock(_cfg.ns.graph_staging);

	mark_graph_dirty();

	rt_node = graph_add_node(_cfg.ns.graph_staging, rt);
	rt->node_id = rt_node->id;

	graph_unlock(_cfg.ns.graph_staging);

	rt->refcount = 1;

	hmap_set(_cfg.ns.routers, rt->name, rt);

out_unlock:
	net_state_unlock(&_cfg.ns);
	return ret;
out_err:
	ret = -1;
	goto out_unlock;
}

static int linkstate_read(struct srdb_entry *entry)
{
	struct srdb_linkstate_entry *link_entry;
	struct node *rt1_node, *rt2_node;
	struct link *link, *link2;
	struct router *rt1, *rt2;
	uint32_t metric;
	int ret = 0;

	link_entry = (struct srdb_linkstate_entry *)entry;

	link = malloc(sizeof(*link));
	if (!link)
		return -1;

	link2 = malloc(sizeof(*link2));
	if (!link2)
		return -1;

	net_state_read_lock(&_cfg.ns);

	rt1 = hmap_get(_cfg.ns.routers, link_entry->name1);
	rt2 = hmap_get(_cfg.ns.routers, link_entry->name2);
	if (!rt1 || !rt2) {
		pr_err("unknown router entry for link (`%s', `%s').",
		       link_entry->name1, link_entry->name2);

		goto out_free;
	}

	inet_pton(AF_INET6, link_entry->addr1, &link->local);
	inet_pton(AF_INET6, link_entry->addr2, &link->remote);
	link->bw = link_entry->bw;
	link->ava_bw = link_entry->ava_bw;
	link->delay = link_entry->delay;
	link->refcount = 1;

	inet_pton(AF_INET6, link_entry->addr1, &link2->remote);
	inet_pton(AF_INET6, link_entry->addr2, &link2->local);
	link2->bw = link_entry->bw;
	link2->ava_bw = link_entry->ava_bw;
	link2->delay = link_entry->delay;
	link2->refcount = 1;

	metric = (uint32_t)link_entry->metric ?: UINT32_MAX;

	graph_write_lock(_cfg.ns.graph_staging);

	if (graph_get_edge_data(_cfg.ns.graph_staging, link)) {
		pr_err("duplicate link entry %s -> %s.", link_entry->addr1,
		       link_entry->addr2);

		graph_unlock(_cfg.ns.graph_staging);
		goto out_free;
	}

	if (graph_get_edge_data(_cfg.ns.graph_staging, link2)) {
		pr_err("duplicate link entry %s -> %s.", link_entry->addr2,
		       link_entry->addr1);

		graph_unlock(_cfg.ns.graph_staging);
		goto out_free;
	}

	mark_graph_dirty();

	rt1_node = graph_get_node_noref(_cfg.ns.graph_staging, rt1->node_id);
	rt2_node = graph_get_node_noref(_cfg.ns.graph_staging, rt2->node_id);

	assert(rt1_node && rt2_node);

	graph_add_edge(_cfg.ns.graph_staging, rt1_node, rt2_node, metric,
		       false, link);
	graph_add_edge(_cfg.ns.graph_staging, rt2_node, rt1_node, metric,
		       false, link2);

	graph_unlock(_cfg.ns.graph_staging);

out_nsunlock:
	net_state_unlock(&_cfg.ns);
	return ret;

out_free:
	free(link);
	free(link2);
	ret = -1;
	goto out_nsunlock;
}

static int linkstate_update(struct srdb_entry *entry,
			    struct srdb_entry *diff __unused,
			    unsigned int fmask)
{
	struct srdb_linkstate_entry *link_entry;
	struct edge *edge, *edge2;
	struct link *link, *link2;
	struct linkpair lp1, lp2;
	int ret = 0;

	link_entry = (struct srdb_linkstate_entry *)entry;

	inet_pton(AF_INET6, link_entry->addr1, &lp1.local);
	inet_pton(AF_INET6, link_entry->addr2, &lp1.remote);

	inet_pton(AF_INET6, link_entry->addr1, &lp2.remote);
	inet_pton(AF_INET6, link_entry->addr2, &lp2.local);

	graph_write_lock(_cfg.ns.graph_staging);

	edge = graph_get_edge_data(_cfg.ns.graph_staging, &lp1);
	if (!edge)
		goto out_err;

	link = edge->data;
	if (!link)
		goto out_err;

	edge2 = graph_get_edge_data(_cfg.ns.graph_staging, &lp2);
	if (!edge2)
		goto out_err;

	link2 = edge->data;
	if (!link2)
		goto out_err;

	if (fmask & ENTRY_MASK(LS_METRIC)) {
		uint32_t metric;

		metric = (uint32_t)link_entry->metric ?: UINT32_MAX;
		edge->metric = metric;
		edge2->metric = metric;
		fmask &= ~ENTRY_MASK(LS_METRIC);
	}

	if (fmask & ENTRY_MASK(LS_BW)) {
		link->bw = link_entry->bw;
		link2->bw = link_entry->bw;
		fmask &= ~ENTRY_MASK(LS_BW);
	}

	if (fmask & ENTRY_MASK(LS_AVA_BW)) {
		link->ava_bw = link_entry->ava_bw;
		link2->ava_bw = link_entry->ava_bw;
		fmask &= ~ENTRY_MASK(LS_AVA_BW);
	}

	if (fmask & ENTRY_MASK(LS_DELAY)) {
		link->delay = link_entry->delay;
		link2->delay = link_entry->delay;
		fmask &= ~ENTRY_MASK(LS_DELAY);
	}

	mark_graph_dirty();

	graph_unlock(_cfg.ns.graph_staging);

	if (fmask)
		pr_err("non-empty field mask after update (%u).", fmask);

out:
	return ret;
out_err:
	graph_unlock(_cfg.ns.graph_staging);
	ret = -1;
	goto out;
}

static int linkstate_delete(struct srdb_entry *entry)
{
	struct srdb_linkstate_entry *link_entry;
	struct linkpair lp1, lp2;
	struct edge *edge;

	link_entry = (struct srdb_linkstate_entry *)entry;

	inet_pton(AF_INET6, link_entry->addr1, &lp1.local);
	inet_pton(AF_INET6, link_entry->addr2, &lp1.remote);

	inet_pton(AF_INET6, link_entry->addr1, &lp2.remote);
	inet_pton(AF_INET6, link_entry->addr2, &lp2.local);

	graph_write_lock(_cfg.ns.graph_staging);

	edge = graph_get_edge_data(_cfg.ns.graph_staging, &lp1);
	if (edge)
		graph_remove_edge(_cfg.ns.graph_staging, edge);

	edge = graph_get_edge_data(_cfg.ns.graph_staging, &lp2);
	if (edge)
		graph_remove_edge(_cfg.ns.graph_staging, edge);

	mark_graph_dirty();

	graph_unlock(_cfg.ns.graph_staging);

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
		if (READ_STRING(buf, logfile, cfg))
			continue;
		if (READ_STRING(buf, ovsdb_client, &cfg->ovsdb_conf))
			continue;
		if (READ_STRING(buf, ovsdb_server, &cfg->ovsdb_conf))
			continue;
		if (READ_STRING(buf, ovsdb_database, &cfg->ovsdb_conf))
			continue;
		if (READ_INT(buf, ntransacts, &cfg->ovsdb_conf)) {
			if (!cfg->ovsdb_conf.ntransacts)
				cfg->ovsdb_conf.ntransacts = 1;
			continue;
		}
		if (READ_STRING(buf, rules_file, cfg))
			continue;
		if (READ_INT(buf, worker_threads, cfg)) {
			if (!cfg->worker_threads)
				cfg->worker_threads = 1;
			continue;
		}
		if (READ_INT(buf, req_buffer_size, cfg)) {
			if (!cfg->req_buffer_size)
				cfg->req_buffer_size = 1;
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

static void *thread_worker(void *arg __unused)
{
	struct srdb_entry *entry;
	struct srdb_table *tbl;

	tbl = srdb_table_by_name(_cfg.srdb->tables, "FlowReq");

	for (;;) {
		entry = sbuf_pop(_cfg.req_buffer);
		if (!entry)
			break;
		process_request(entry);
		free_srdb_entry(tbl->desc, entry);
	}

	return NULL;
}

static void gc_flows(void)
{
	struct llist_node *nhead, *iter;
	struct hmap_entry *he, *tmp;
	struct flow *fl;
	time_t now;

	/* Using a temporary list to store flows to be removed enables to
	 * minimize the work performed with the flows write lock held.
	 * The most expensive function is set_flow_status() which performs
	 * a synchronous SRDB transaction and must be realised outside the
	 * critical section.
	 */
	nhead = llist_node_alloc();
	if (!nhead)
		return;

	now = time(NULL);

	hmap_write_lock(_cfg.flows);

	hmap_foreach_safe(_cfg.flows, he, tmp) {
		fl = he->elem;

		/* Flows are orphaned when the source or destination router's
		 * node is removed from the network.
		 */
		if ((fl->ttl && now > fl->timestamp + fl->ttl) ||
		    fl->status == FLOW_STATUS_ORPHAN) {
			hmap_delete(_cfg.flows, he->key);
			llist_node_insert_tail(nhead, fl);
		}
	}

	hmap_unlock(_cfg.flows);

	llist_node_foreach(nhead, iter) {
		fl = iter->data;
		set_flow_status(fl, FLOW_STATUS_EXPIRED);
		flow_release(fl);
	}

	llist_node_destroy(nhead);
}

static void recompute_flow(struct flow *fl)
{
	struct node *src_node, *dst_node;
	struct srdb_update_transact *utr;
	struct srdb_flow_entry fe;
	struct llist_node *epath;
	struct llist_node *segs;
	struct srdb_table *tbl;
	struct transaction *tr;
	struct pathspec pspec;
	bool diff = false;
	unsigned int i;

	memset(&pspec, 0, sizeof(pspec));

	net_state_read_lock(&_cfg.ns);

	src_node = graph_get_node_noref(_cfg.ns.graph, fl->srcrt->node_id);
	dst_node = graph_get_node_noref(_cfg.ns.graph, fl->dstrt->node_id);

	if (!src_node || !dst_node) {
		fl->status = FLOW_STATUS_ORPHAN;
		goto out_unlock;
	}

	pspec.src = src_node;
	pspec.dst = dst_node;
	pspec.data = fl;
	pspec.prune = pre_prune;
	if (fl->delay)
		pspec.d_ops = &delay_min_ops;

	epath = NULL;
	segs = build_segpath(_cfg.ns.graph, &pspec, &epath);

	if (!segs)
		goto out_unlock;

	/* commit flow with updated segments */

	if (!compare_segments(segs, fl->src_prefixes[0].segs))
		diff = true;

	free_segments(fl->src_prefixes[0].segs);
	destroy_edgepath(fl->src_prefixes[0].epath);
	fl->src_prefixes[0].segs = segs;
	fl->src_prefixes[0].epath = epath;

	for (i = 1; i < fl->nb_prefixes; i++) {
		if (!compare_segments(segs, fl->src_prefixes[i].segs))
			diff = true;

		free_segments(fl->src_prefixes[i].segs);
		destroy_edgepath(fl->src_prefixes[i].epath);
		fl->src_prefixes[i].segs = copy_segments(segs);
		fl->src_prefixes[i].epath = copy_edgepath(epath);
	}

	/* do not update srdb if segments are unchanged */
	if (!diff)
		goto out_unlock;

	flow_to_flowentry(fl, &fe, ENTRY_MASK(FE_SEGMENTS));

	tbl = srdb_table_by_name(_cfg.srdb->tables, "FlowState");
	utr = srdb_update_prepare(_cfg.srdb, tbl, (struct srdb_entry *)&fe);
	srdb_update_append(utr, FE_SEGMENTS);

	tr = srdb_update_commit(utr);

	if (srdb_update_result(tr, NULL) < 0)
		pr_err("failed to commit recomputed segments.");

out_unlock:
	net_state_unlock(&_cfg.ns);
}

static bool flow_affected(struct flow *fl)
{
	struct llist_node *iter;
	struct edge *e1, *e2;
	unsigned int i;

	for (i = 0; i < fl->nb_prefixes; i++) {
		llist_node_foreach(fl->src_prefixes[i].epath, iter) {
			e1 = iter->data;
			e2 = graph_get_edge_noref(_cfg.ns.graph, e1->id);

			if (!e2)
				return true;

			/* TODO add hook to check edge data (delay, bw, ...) */
			if (e1->metric != e2->metric)
				return true;
		}
	}

	return false;
}

static void recompute_flows(void)
{
	struct llist_node *nhead, *iter;
	struct hmap_entry *he;
	struct flow *fl;

	nhead = llist_node_alloc();
	if (!nhead)
		return;

	net_state_read_lock(&_cfg.ns);
	hmap_read_lock(_cfg.flows);

	hmap_foreach(_cfg.flows, he) {
		fl = he->elem;

		if (flow_affected(fl)) {
			flow_hold(fl);
			llist_node_insert_tail(nhead, fl);
		}
	}

	hmap_unlock(_cfg.flows);
	net_state_unlock(&_cfg.ns);

	printf("%lu affected flows.\n", llist_node_size(nhead));

	llist_node_foreach(nhead, iter) {
		fl = iter->data;
		recompute_flow(fl);
		flow_release(fl);
	}

	llist_node_destroy(nhead);
}

#define NETMON_LOOP_SLEEP	1
#define GSYNC_SOFT_TIMEOUT	5
#define GSYNC_HARD_TIMEOUT	50
#define GC_FLOWS_TIMEOUT	1000

static void *thread_netmon(void *arg)
{
	struct netstate *ns = &_cfg.ns;
	struct timeval gc_time, now;
	sem_t *stop = arg;

	gettimeofday(&gc_time, NULL);

	while (sem_trywait(stop)) {
		gettimeofday(&now, NULL);

		if (getmsdiff(&now, &gc_time) > GC_FLOWS_TIMEOUT) {
			gc_flows();
			gc_time = now;
		}

		/* attempt to resync graph if dirty and either:
		 * - last graph mod > NS_GSYNC_SOFT_TIMEOUT
		 * - dirty set time > NS_GSYNC_HARD_TIMEOUT
		 */

		if (!_cfg.ns.graph_staging->dirty)
			goto next;

		/* check adversely affected flows. Normally, by constraint but
		 * for benchmarks, consider link-down events as adverse
		 */

		if (getmsdiff(&now, &_cfg.ns.gs_mod) > GSYNC_SOFT_TIMEOUT ||
		    getmsdiff(&now, &_cfg.ns.gs_dirty) > GSYNC_HARD_TIMEOUT) {
			if (netstate_graph_sync(ns) < 0) {
				pr_err("failed to synchronize staging network "
					"graph.");
				goto next;
			}

			recompute_flows();
		}

next:
		usleep(NETMON_LOOP_SLEEP * 1000);
	}

	return NULL;
}

static int launch_srdb(void)
{
	unsigned int mon_flags;

	mon_flags = MON_INITIAL | MON_INSERT | MON_UPDATE | MON_DELETE;

	if (srdb_monitor(_cfg.srdb, "NodeState", mon_flags, nodestate_read,
			 NULL, NULL, false, true) < 0) {
		pr_err("failed to start NodeState monitor.");
		return -1;
	}


	if (srdb_monitor(_cfg.srdb, "LinkState", mon_flags, linkstate_read,
			 linkstate_update, linkstate_delete, false, true) < 0) {
		pr_err("failed to start LinkState monitor.");
		return -1;
	}

	mon_flags = MON_INITIAL | MON_INSERT;

	if (srdb_monitor(_cfg.srdb, "FlowReq", mon_flags, flowreq_read, NULL,
			 NULL, true, true) < 0) {
		pr_err("failed to start FlowReq monitor.");
		return -1;
	}

	return 0;
}

int load_args(int argc, char **argv, const char **conf, int *dryrun)
{
	int c;
	opterr = 0;

	while ((c = getopt(argc, argv, "d")) != -1)
		switch (c)
		{
			case 'd':
				*dryrun = 1;
				break;
			case '?':
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
				return -1;
			default:
				return -1;
		}

	if (optind == argc - 1)
		*conf = argv[optind];
	else if (optind > argc)
		return -1;
	return 0;
}

int main(int argc, char **argv)
{
	const char *conf = DEFAULT_CONFIG;
	pthread_t *workers;
	pthread_t netmon;
	unsigned int i;
	sem_t mon_stop;
	int ret = 0;
	int dryrun = 0;

	if (load_args(argc, argv, &conf, &dryrun)) {
		fprintf(stderr, "Usage: %s [-d] [configfile]\n", argv[0]);
		return -1;
	}

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

	if (dryrun) {
		printf("Configuration and rules files are correct");
		goto free_rules;
	}

	if (*_cfg.logfile && !set_logfile(_cfg.logfile)) {
		pr_err("Cannot redirect output to logfile %s", _cfg.logfile);
		goto free_rules;
	}

	_cfg.srdb = srdb_new(&_cfg.ovsdb_conf);
	if (!_cfg.srdb) {
		pr_err("failed to initialize SRDB.");
		ret = -1;
		goto free_rules;
	}

	if (init_netstate(&_cfg.ns) < 0) {
		pr_err("failed to initialize network state.");
		ret = -1;
		goto free_srdb;
	}

	_cfg.flows = hmap_new(hash_in6, compare_in6);
	if (!_cfg.flows) {
		pr_err("failed to initialize flow map.\n");
		ret = -1;
		goto free_srdb;
	}

	_cfg.req_buffer = sbuf_new(_cfg.req_buffer_size);
	if (!_cfg.req_buffer) {
		pr_err("failed to initialize request queue.\n");
		ret = -1;
		goto free_flows;
	}

	workers = malloc(_cfg.worker_threads * sizeof(pthread_t));
	if (!workers) {
		pr_err("failed to allocate space for worker threads.\n");
		ret = -1;
		goto free_req_buffer;
	}

	for (i = 0; i < _cfg.worker_threads; i++)
		pthread_create(&workers[i], NULL, thread_worker, NULL);

	if (launch_srdb() < 0) {
		pr_err("failed to start srdb monitors.");
		goto free_workers;
	}

	sem_init(&mon_stop, 0, 0);
	pthread_create(&netmon, NULL, thread_netmon, &mon_stop);

	srdb_monitor_join_all(_cfg.srdb);

	for (i = 0; i < _cfg.worker_threads; i++)
		sbuf_push(_cfg.req_buffer, NULL);

	for (i = 0; i < _cfg.worker_threads; i++)
		pthread_join(workers[i], NULL);

	sem_post(&mon_stop);

	pthread_join(netmon, NULL);

	destroy_netstate();

free_workers:
	free(workers);
free_req_buffer:
	sbuf_destroy(_cfg.req_buffer);
free_flows:
	hmap_destroy(_cfg.flows);
free_srdb:
	srdb_destroy(_cfg.srdb);
free_rules:
	destroy_rules(_cfg.rules, _cfg.defrule);
free_conf:
	if (_cfg.providers && _cfg.providers != &internal_provider)
		free(_cfg.providers);
	return ret;
}
