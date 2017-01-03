#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "arraylist.h"
#include "misc.h"
#include "srdb.h"
#include "rules.h"
#include "hashmap.h"
#include "graph.h"
#include "lpm.h"
#include "sr-ctrl.h"
#include "mq.h"

/* lookup usecases:
 * - access control at source (in/out)
 * - access control at destination (in/out)
 * - middlebox on path (src or dst)
 *
 * <default>: default allow|deny
 * <rule>: <action> from|to <matcher> [via PATH] [last <last>] [bw BW] [delay DELAY] [ttl TTL] [idle IDLE]
 * <matcher>: name|addr:data
 * <action>: allow|deny
 * <last>: auto|none|<name|addr>
 * TTL: remove flow after TTL seconds
 * IDLE: remove flow if idle for IDLE seconds
 *
 * lookup algo:
 * - PATH = [] && RES = DEFAULT && LAST_MATCH = NULL && BW = REQ.BW && DELAY = REQ.DELAY
 * - foreach rule:
 *     - if rule matches then LAST_MATCH = rule
 * - if LAST_MATCH not NULL then RES = rule.RES and PATH = rule.PATH
 * - if RES = DENY then return ERROR
 * - if rule.LAST = NULL then rule.LAST = auto
 * - if rule.LAST = auto then PATH += dst_router
 * - if rule.LAST = none then nop
 * - if rule.LAST is addr or name then PATH += rule.LAST
 * - BW = rule.BW
 * - DELAY = rule.DELAY
 * - if BW or DELAY then SEGS = segment(trace(PATH, BW, DELAY))
 *                  else SEGS = PATH
 * - if IS_ERR(SEGS) then return ERROR
 * - return (BINDING,SEGS)
 */

/* on flowreq do:
 *   - lookup destination
 *   -
 */

#define DEFAULT_CONFIG	"sr-ctrl.conf"

struct config {
	char rules_file[SLEN + 1];
	struct ovsdb_config ovsdb_conf;
	unsigned int worker_threads;
	unsigned int req_queue_size;

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
}

static int set_status(struct srdb_flowreq_entry *req, enum flowreq_status st)
{
	struct srdb_table *tbl;

	tbl = srdb_table_by_name(_cfg.srdb->tables, "FlowReq");
	req->status = st;

	return srdb_update(_cfg.srdb, tbl, (struct srdb_entry *)req, "status");
}

static int commit_flow(struct srdb_flowreq_entry *req, struct router *rt,
		       struct flow *fl)
{
	struct srdb_flow_entry flow_entry;
	char addr[INET6_ADDRSTRLEN];
	unsigned int i;
	int ret;

	memset(&flow_entry, 0, sizeof(flow_entry));

	memcpy(flow_entry.destination, fl->dst, SLEN);
	memcpy(flow_entry.source, fl->src, SLEN);
	inet_ntop(AF_INET6, &fl->dstaddr, flow_entry.dstaddr, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &fl->bsid, flow_entry.bsid, INET6_ADDRSTRLEN);

	flow_entry.segments = calloc(fl->segs->elem_count, INET6_ADDRSTRLEN);

	if (!flow_entry.segments)
		return -1;

	for (i = 0; i < fl->segs->elem_count; i++) {
		struct segment *s;
		struct in6_addr *seg_addr;

		s = alist_elem(fl->segs, i);
		if (!s->adjacency) {
			struct router *r;

			r = s->node->data;
			seg_addr = &r->addr;
		} else {
			struct link *l;

			l = s->edge->data;
			seg_addr = &l->remote;
		}

		inet_ntop(AF_INET6, seg_addr, addr, INET6_ADDRSTRLEN);

		// TODO fix that horrible stuff
		strcat(flow_entry.segments, addr);
		if (i < fl->segs->elem_count - 1)
			strcat(flow_entry.segments, ";");
	}

	memcpy(flow_entry.router, rt->name, SLEN);

	flow_entry.bandwidth = fl->bw;
	flow_entry.delay = fl->delay;
	flow_entry.ttl = fl->ttl;
	flow_entry.idle = fl->idle;

	memcpy(flow_entry.request_id, req->request_id, SLEN);

	ret = srdb_insert(_cfg.srdb,
			  srdb_table_by_name(_cfg.srdb->tables, "FlowState"),
			  (struct srdb_entry *)&flow_entry, NULL);

	free(flow_entry.segments);

	return ret;
}

static void generate_bsid(struct router *rt, struct in6_addr *res)
{
	int len;
	char addr[41];

	len = (128 - rt->pbsid.len) >> 3;

	inet_ntop(AF_INET6, &rt->pbsid.addr, addr, 40);

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

static bool prune_delay(struct edge *e, void *arg)
{
	uint32_t delay = (uintptr_t)arg;
	struct link *link;

	link = (struct link *)e->data;

	return link->delay > delay;
}

static struct arraylist *build_segpath(struct graph *g, struct flow *fl,
				       struct arraylist *via)
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

	if (fl->bw)
		graph_prune(gc, prune_bw, (void *)(uintptr_t)fl->bw);
	if (fl->delay)
		graph_prune(gc, prune_delay, (void *)(uintptr_t)fl->delay);

	cur_node = fl->srcrt->node;

	if (via)
		alist_append(path, via);

	alist_insert(path, &fl->dstrt->node);

	for (i = 0; i < path->elem_count; i++) {
		struct arraylist *tmp_paths, *tmp_path, *rev_path;
		struct node *tmp_node;
		struct segment s;

		alist_get(path, i, &tmp_node);

		graph_dijkstra(gc, cur_node, &gres);
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

static void process_request(struct srdb_entry *entry)
{
	struct srdb_flowreq_entry *req = (struct srdb_flowreq_entry *)entry;
	struct router *rt, *dstrt;
	enum flowreq_status rstat;
	struct in6_addr addr;
	struct rule *rule;
	struct flow *fl;

	printf("processing request %s -> %s\n", req->source, req->destination);

	rule = match_rules(_cfg.rules, req->source, req->destination);
	if (!rule)
		rule = _cfg.defrule;

	if (rule->type == RULE_ALLOW)
		rstat = STATUS_ALLOWED;
	else
		rstat = STATUS_DENIED;

	if (rstat == STATUS_DENIED) {
		if (set_status(req, STATUS_DENIED) < 0)
			pr_err("failed to update row uuid %s to status %d\n",
			       req->_row, rstat);
		return;
	}

	/* XXX currently assume only internal flows */

	fl = calloc(1, sizeof(*fl));
	if (!fl) {
		set_status(req, STATUS_ERROR);
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
		free(fl);
		set_status(req, STATUS_NOROUTER);
		return;
	}

	inet_pton(AF_INET6, req->dstaddr, &addr);
	dstrt = lpm_lookup(_cfg.prefixes, &addr);
	if (!dstrt) {
		free(fl);
		set_status(req, STATUS_NOPREFIX);
		return;
	}

	fl->srcrt = rt;
	fl->dstrt = dstrt;

	graph_read_lock(_cfg.graph);
	fl->segs = build_segpath(_cfg.graph, fl, rule->path);
	graph_unlock(_cfg.graph);

	if (!fl->segs) {
		free(fl);
		set_status(req, STATUS_UNAVAILABLE);
		return;
	}

	hmap_write_lock(rt->flows);
	generate_unique_bsid(rt, &fl->bsid);
	hmap_set(rt->flows, &fl->bsid, fl);
	hmap_unlock(rt->flows);

	set_status(req, STATUS_ALLOWED);
	commit_flow(req, rt, fl);
}

static void read_flowreq(struct srdb_entry *entry)
{
	struct srdb_flowreq_entry *req = (struct srdb_flowreq_entry *)entry;

	mq_push(_cfg.req_queue, &req);
}

static void read_nodestate(struct srdb_entry *entry)
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
		return;
	}

	rt = calloc(1, sizeof(*rt));
	if (!rt)
		return;

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
}

static void read_linkstate(struct srdb_entry *entry)
{
	struct srdb_linkstate_entry *link_entry;
	struct router *rt1, *rt2;
	struct link *link;
	struct edge *edge;

	link_entry = (struct srdb_linkstate_entry *)entry;

	link = calloc(1, sizeof(*link));
	if (!link)
		return;

	rt1 = hmap_get(_cfg.routers, link_entry->name1);
	rt2 = hmap_get(_cfg.routers, link_entry->name2);
	if (!rt1 || !rt2) {
		pr_err("unknown router entry for link (`%s', `%s').",
		       link_entry->name1, link_entry->name2);
		return;
	}

	inet_pton(AF_INET6, link_entry->addr1, &link->local);
	inet_pton(AF_INET6, link_entry->addr2, &link->remote);
	link->bw = link_entry->bw;
	link->ava_bw = link_entry->ava_bw;
	link->delay = link_entry->delay;

	graph_write_lock(_cfg.graph);
	edge = graph_add_edge(_cfg.graph, rt1->node, rt2->node, true, link);
	edge->metric = (uint32_t)link_entry->metric ?: UINT32_MAX;
	graph_unlock(_cfg.graph);
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
		mq_pop(_cfg.req_queue, &entry);
		if (!entry)
			break;
		process_request(entry);
		free_srdb_entry(tbl->desc, entry);
	}

	return NULL;
}

struct monitor_arg {
	struct srdb *srdb;
	struct srdb_table *table;
	const char *columns;
};

static void *thread_monitor(void *_arg)
{
	struct monitor_arg *arg = _arg;
	int ret;

	ret = srdb_monitor(arg->srdb, arg->table, arg->columns);

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
	args[0].columns = "";

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
	args[1].columns = "";

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
	args[2].columns = "!delete,!modify";

	pthread_create(&thr[2], NULL, thread_monitor, (void *)&args[2]);
}

int main(int argc, char **argv)
{
	const char *conf = DEFAULT_CONFIG;
	struct monitor_arg margs[3];
	pthread_t mon_thr[3];
	pthread_t *workers;
	unsigned int i;

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
		return -1;
	}

	_cfg.srdb = srdb_new(&_cfg.ovsdb_conf);
	if (!_cfg.srdb) {
		pr_err("failed to initialize SRDB.");
		return -1;
	}

	_cfg.graph = graph_new();
	if (!_cfg.graph) {
		pr_err("failed to initialize network graph.");
		return -1;
	}

	_cfg.routers = hmap_new(hash_str, compare_str);
	if (!_cfg.routers) {
		pr_err("failed to initialize routers map.");
		return -1;
	}

	_cfg.prefixes = lpm_new();
	if (!_cfg.prefixes) {
		pr_err("failed to initialize prefix tree.");
		return -1;
	}

	_cfg.req_queue = mq_init(_cfg.req_queue_size,
				 sizeof(struct srdb_entry *));
	if (!_cfg.req_queue) {
		pr_err("failed to initialize request queue.\n");
		return -1;
	}

	workers = malloc(_cfg.worker_threads * sizeof(pthread_t));
	if (!workers) {
		pr_err("failed to allocate space for worker threads.\n");
		return -1;
	}

	for (i = 0; i < _cfg.worker_threads; i++)
		pthread_create(&workers[i], NULL, thread_worker, NULL);

	launch_srdb(mon_thr, margs);

	for (i = 0; i < _cfg.worker_threads; i++)
		pthread_join(workers[i], NULL);

	for (i = 0; i < sizeof(mon_thr) / sizeof(pthread_t); i++)
		pthread_join(mon_thr[i], NULL);

	free(workers);
	mq_destroy(_cfg.req_queue);
	lpm_destroy(_cfg.prefixes);
	hmap_destroy(_cfg.routers);
	graph_destroy(_cfg.graph, false);
	srdb_destroy(_cfg.srdb);

	return 0;
}
