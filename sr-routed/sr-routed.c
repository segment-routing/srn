#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <zlog.h>

#include <jansson.h>

#include "misc.h"
#include "srdb.h"
#include "hashmap.h"
#include "atomic.h"
#include "libnetlink.h"
#include "seg6_netlink.h"

#define DEFAULT_CONFIG	"sr-routed.conf"

struct config {
	struct ovsdb_config ovsdb_conf;
	char router_name[SLEN + 1];
	char ingress_iface[SLEN + 1];

	struct srdb *srdb;
	struct hashmap *routes;
	__u32 localsid;
	struct rtnl_handle rth;

	char zlog_conf_file[SLEN + 1];
};

struct route {
	struct in6_addr bsid;
	char *segs;
};

static struct config _cfg;
static zlog_category_t *zc;

#define BUFLEN 1024

static int srdb_print(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vzlog_error(zc, fmt, args);
	va_end(args);
	return 0;
}

static int exec_route_add_encap(const char *route, const char *segments)
{
	int ret = add_route(&_cfg.rth, route, _cfg.ingress_iface, _cfg.localsid,
			    segments);
	if (ret) {
		zlog_error(zc, "Cannot insert route %s mapping to %s\n", route,
			segments);
	}
	return ret;
}

static int exec_route_change_encap(const char *route, const char *segments)
{
	int ret = change_route(&_cfg.rth, route, _cfg.ingress_iface,
			       _cfg.localsid, segments);
	if (ret) {
		zlog_error(zc, "Cannot change route %s mapping to %s\n", route,
			segments);
	}
	return ret;
}

static void add_fib_entry(struct route *rt)
{
	char bsid[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &rt->bsid, bsid, INET6_ADDRSTRLEN);

	exec_route_add_encap(bsid, rt->segs);
}

static void update_fib_entry(struct route *rt)
{
	char bsid[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &rt->bsid, bsid, INET6_ADDRSTRLEN);

	exec_route_change_encap(bsid, rt->segs);
}

static int set_status(struct srdb_flow_entry *flow_entry, enum flow_status st)
{
	struct srdb_table *tbl;

	tbl = srdb_table_by_name(_cfg.srdb->tables, "FlowState");
	flow_entry->status = st;

	return srdb_update_sync(_cfg.srdb, tbl, (struct srdb_entry *)flow_entry,
			   FE_STATUS, NULL);
}

static int read_flowstate(struct srdb_entry *entry)
{
	struct srdb_flow_entry *flow_entry = (struct srdb_flow_entry *)entry;
	json_t *segs = NULL;
	json_t *segment = NULL;
	char segs_str [SLEN + 1];
	int i = 0;
	unsigned int j = 0;
	struct route *rt;

	if (strcmp(flow_entry->router, _cfg.router_name)) {
		return 0; /* Do not consider irrelevant flows */
	}

	json_t *segment_lists = json_loads(flow_entry->segments, 0, NULL);
	if (!segment_lists) {
		zlog_error(zc, "Invalid json format for segment lists: %s\n", flow_entry->segments);
		return 0;
	}
	json_t *bsids = json_loads(flow_entry->bsid, 0, NULL);
	if (!bsids) {
		zlog_error(zc, "Invalid json format for bsids: %s\n", flow_entry->bsid);
		return 0;
	}

	/* route bsid -> encap seg6 */

	json_array_foreach(segment_lists, i, segs) {
		unsigned int k = 0;

		rt = malloc(sizeof(*rt));
		inet_pton(AF_INET6, json_string_value(json_array_get(bsids, i)),
			  &rt->bsid);

		json_array_foreach(segs, j, segment) {
			k += snprintf(segs_str + k, SLEN + 1 - k, "%s%s",
				      json_string_value(segment),
				      j == json_array_size(segs) - 1 ? "" : ",");
		}

		rt->segs = strdup(segs_str);

		hmap_write_lock(_cfg.routes);
		hmap_set(_cfg.routes, &rt->bsid, rt);
		hmap_unlock(_cfg.routes);

		add_fib_entry(rt);
	}

	/* Warn the DNS proxy */

	set_status(flow_entry, FLOW_STATUS_RUNNING);

	json_decref(segment_lists);
	json_decref(bsids);

	return 0;
}

static int update_flowstate(struct srdb_entry *entry,
			    struct srdb_entry *diff __unused__,
			    unsigned int fmask)
{
	struct srdb_flow_entry *flow_entry = (struct srdb_flow_entry *)entry;
	json_t *segment_lists, *bsids, *segs, *segment;
	char segs_str[SLEN + 1];
	unsigned int j;
	int i;

	if (strcmp(flow_entry->router, _cfg.router_name)) {
		return 0; /* Do not consider irrelevant flows */
	}

	if (!(fmask & ENTRY_MASK(FE_SEGMENTS)))
		return 0;

	segment_lists = json_loads(flow_entry->segments, 0, NULL);
	bsids = json_loads(flow_entry->bsid, 0, NULL);

	json_array_foreach(segment_lists, i, segs) {
		unsigned int k = 0;
		struct in6_addr addr;
		struct route *rt;

		inet_pton(AF_INET6, json_string_value(json_array_get(bsids, i)),
			  &addr);

		hmap_read_lock(_cfg.routes);
		rt = hmap_get(_cfg.routes, &addr);
		hmap_unlock(_cfg.routes);

		if (!rt)
			continue;

		json_array_foreach(segs, j, segment) {
			k += snprintf(segs_str + k, SLEN + 1 - k, "%s%s",
				      json_string_value(segment),
				      j == json_array_size(segs) - 1 ? "" : ",");
		}

		free(rt->segs);
		rt->segs = strdup(segs_str);

		update_fib_entry(rt);
	}

	json_decref(segment_lists);
	json_decref(bsids);

	return 0;
}

#define READ_STRING(b, arg, dst) sscanf(b, #arg " \"%[^\"]\"", (dst)->arg)
#define READ_INT(b, arg, dst) sscanf(b, #arg " %i", &(dst)->arg)
#define READ_UINT(b, arg, dst) sscanf(b, #arg " %u", &(dst)->arg)

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
				fprintf(stderr, "Unknown option `-%c'.\n",
					optopt);
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

static void config_set_defaults(struct config *cfg)
{
	strcpy(cfg->router_name, "access");
	strcpy(cfg->ovsdb_conf.ovsdb_client, "ovsdb-client");
	strcpy(cfg->ovsdb_conf.ovsdb_server, "tcp:[::1]:6640");
	strcpy(cfg->ovsdb_conf.ovsdb_database, "SR_test");
	strcpy(cfg->ingress_iface, "eth0"); // Non-loopback device
	cfg->ovsdb_conf.ntransacts = 1;
	cfg->localsid = RT_TABLE_MAIN;
	*cfg->zlog_conf_file = '\0';
}

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
		if (READ_STRING(buf, router_name, cfg))
			continue;
		if (READ_INT(buf, ntransacts, &cfg->ovsdb_conf)) {
			if (!cfg->ovsdb_conf.ntransacts)
				cfg->ovsdb_conf.ntransacts = 1;
			continue;
		}
		if (READ_UINT(buf, localsid, cfg))
			continue;
		if (READ_STRING(buf, ingress_iface, cfg))
			continue;
		if (READ_STRING(buf, zlog_conf_file, cfg))
			continue;
		fprintf(stderr, "parse error: unknown line `%s'.", buf);
		ret = -1;
		break;
	}

	fclose(fp);
	return ret;
}

int main(int argc, char **argv)
{
	const char *conf = DEFAULT_CONFIG;
	int dryrun = 0;
	int rc;
	int ret;

	if (load_args(argc, argv, &conf, &dryrun)) {
		fprintf(stderr, "Usage: %s [-d] [configfile]\n", argv[0]);
		ret = -1;
		goto out;
	}

	config_set_defaults(&_cfg);
	if (load_config(conf, &_cfg) < 0) {
		fprintf(stderr, "failed to load configuration file.");
		ret = -1;
		goto out;
	}

	rc = zlog_init(*_cfg.zlog_conf_file ? _cfg.zlog_conf_file : NULL);
	if (rc) {
		fprintf(stderr, "Initiating logs failed\n");
		ret = -1;
		goto out;
	}
	zc = zlog_get_category("sr-routed");
	if (!zc) {
		fprintf(stderr, "Initiating main log category failed\n");
		ret = -1;
		goto out_logs;
	}

	if (dryrun) {
		zlog_info(zc, "Configuration file is correct");
		ret = 0;
		goto out_logs;
	}

	_cfg.routes = hmap_new(hash_in6, compare_in6);
	if (!_cfg.routes) {
		zlog_error(zc, "failed to initialize route map.");
		ret = -1;
		goto out_logs;
	}

	_cfg.srdb = srdb_new(&_cfg.ovsdb_conf, srdb_print);
	if (!_cfg.srdb) {
		zlog_error(zc, "failed to initialize SRDB.");
		ret = -1;
		goto out_logs;
	}

	if (rtnl_open(&_cfg.rth, 0) < 0) {
		zlog_error(zc, "Cannot open netlink socket.");
		ret = -1;
		goto out_srdb;
	}

	if (srdb_monitor(_cfg.srdb, "FlowState", MON_INSERT | MON_UPDATE,
	                 read_flowstate, update_flowstate, NULL, false, true)
	    != MON_STATUS_RUNNING) {
		zlog_error(zc, "failed to start FlowState monitor.");
		ret = -1;
		goto out_rtnl;
	}

	srdb_monitor_join_all(_cfg.srdb);
out_rtnl:
	rtnl_close(&_cfg.rth);
out_srdb:
	srdb_destroy(_cfg.srdb);
out_logs:
	zlog_fini();
out:
	return ret;
}

