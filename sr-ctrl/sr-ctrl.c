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

	/* internal data */
	struct srdb *srdb;
	struct arraylist *rules;
	struct rule *defrule;
	struct graph *graph;
	struct hashmap *routers;
};

static struct config _cfg;

static int set_status(struct srdb_flowreq_entry *req, enum flowreq_status st)
{
	struct srdb_descriptor desc;
	struct srdb_table *tbl;

	desc.name = "status";
	desc.type = SRDB_INT;
	desc.data = &st;

	tbl = srdb_table_by_name(_cfg.srdb->tables, "FlowReq");

	return srdb_update(_cfg.srdb, tbl, (struct srdb_entry *)req, &desc);
}

static int commit_flow(struct router *rt, struct flow *fl)
{
	struct srdb_flow_entry flow_entry;
	char addr[INET6_ADDRSTRLEN];
	unsigned int i;
	int ret;

	memset(&flow_entry, 0, sizeof(flow_entry));

	memcpy(flow_entry.destination, fl->dst, SLEN);
	memcpy(flow_entry.source, fl->src, SLEN);
	inet_ntop(AF_INET6, &fl->bsid, flow_entry.bsid, INET6_ADDRSTRLEN);

	flow_entry.segments = calloc(fl->segs->elem_count, INET6_ADDRSTRLEN);

	if (!flow_entry.segments)
		return -1;

	for (i = 0; i < fl->segs->elem_count; i++) {
		struct segment *s;
		struct router *r;

		s = alist_elem(fl->segs, i);
		if (!s->adjacency)
			r = s->node->data;
		else
			r = s->edge->remote->data;

		inet_ntop(AF_INET6, &r->addr, addr, INET6_ADDRSTRLEN);

		snprintf(flow_entry.segments, fl->segs->elem_count *
			 INET6_ADDRSTRLEN, "%s%s%c", flow_entry.segments, addr,
			 (i < fl->segs->elem_count - 1) ? ',' : 0);
	}

	memcpy(flow_entry.router, rt->name, SLEN);

	flow_entry.bandwidth = fl->bw;
	flow_entry.delay = fl->delay;
	flow_entry.ttl = fl->ttl;
	flow_entry.idle = fl->idle;

	ret = srdb_insert(_cfg.srdb,
			  srdb_table_by_name(_cfg.srdb->tables, "FlowState"),
			  (struct srdb_entry *)&flow_entry);

	free(flow_entry.segments);

	return ret;
}

static void generate_bsid(struct router *rt, struct in6_addr *res)
{
	int len;

	len = (128 - rt->pbsid.len) >> 3;

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

	return link->delay < delay;
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

	cur_node = fl->srcnode;

	if (via)
		alist_append(path, via);

	alist_insert(path, &fl->dstnode);

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

		if (graph_minseg(gc, rev_path, res) < 0)
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
	enum flowreq_status rstat;
	struct arraylist *segs;
	struct router *rt;
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
	fl->bw = rule->bw ?: req->bandwidth;
	fl->delay = rule->delay ?: req->delay;
	fl->ttl = rule->ttl;
	fl->idle = rule->idle;

	rt = hmap_get(_cfg.routers, req->router);
	if (!rt) {
		free(fl);
		set_status(req, STATUS_ERROR);
		return;
	}

	if (fl->bw || fl->delay || rule->path) {
		graph_read_lock(_cfg.graph);
		segs = build_segpath(_cfg.graph, fl, rule->path);
		graph_unlock(_cfg.graph);

		if (!segs) {
			free(fl);
			set_status(req, STATUS_UNAVAILABLE);
			return;
		}
	}

	hmap_write_lock(rt->flows);
	generate_unique_bsid(rt, &fl->bsid);
	hmap_set(rt->flows, &fl->bsid, fl);
	hmap_unlock(rt->flows);

	set_status(req, STATUS_ALLOWED);
	commit_flow(rt, fl);
}

#define READ_STRING(b, arg, dst) sscanf(b, #arg " \"%[^\"]\"", (dst)->arg)

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
		pr_err("parse error: unknown line `%s'.", buf);
		ret = -1;
		break;
	}

	fclose(fp);
	return ret;
}

int main(int argc, char **argv)
{
	const char *conf = DEFAULT_CONFIG;
	struct srdb_table *flowreq_tbl;
	int ret;

	if (argc > 2) {
		fprintf(stderr, "Usage: %s [configfile]\n", argv[0]);
		return -1;
	}

	if (argc == 2)
		conf = argv[1];

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
		pr_err("failed to initialize SRDB.\n");
		return -1;
	}

	flowreq_tbl = srdb_table_by_name(_cfg.srdb->tables, "FlowReq");
	flowreq_tbl->read = process_request;

	ret = srdb_monitor(_cfg.srdb, flowreq_tbl, "!initial,!delete,!modify");

	printf("ret: %d\n", ret);

	srdb_destroy(_cfg.srdb);

	return 0;
}
