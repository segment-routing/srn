#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include <jansson.h>

#include "misc.h"
#include "srdb.h"
#include "hashmap.h"
#include "atomic.h"

#define DEFAULT_CONFIG	"sr-routed.conf"

struct config {
	struct ovsdb_config ovsdb_conf;
	char iproute[SLEN + 1];
	char vnhpref[SLEN + 1];
	char ingress_iface[SLEN + 1];

	struct srdb *srdb;
	struct in6_addr vnhp;
	atomic64_t last_vnh;
	int dns_fd;
	struct hashmap *routes;
};

struct route {
	struct in6_addr bsid;
	struct in6_addr vnh;
	char *segs;
};

static struct config _cfg;

#define BUFLEN 1024
#define MAX_REQUEST 500

static int exec_route_add_encap(const char *route, const char *segments)
{
	char cmd[BUFLEN + 1];
	FILE *fp;
	int ret;

	snprintf(cmd, BUFLEN, "%s route add %s/128 encap seg6 mode encap "
		 "segs %s dev %s 2>/dev/null", _cfg.iproute, route, segments,
		 _cfg.ingress_iface);

	fp = popen(cmd, "r");
	if (!fp) {
		perror("popen");
		return -1;
	}

	ret = pclose(fp);
	if (ret < 0)
		perror("pclose");

	return ret;
}

static int exec_route_change_encap(const char *route, const char *segments)
{
	char cmd[BUFLEN + 1];
	FILE *fp;
	int ret;

	snprintf(cmd, BUFLEN, "%s route change %s/128 encap seg6 mode encap "
		 "segs %s dev %s 2>/dev/null", _cfg.iproute, route, segments,
		 _cfg.ingress_iface);

	fp = popen(cmd, "r");
	if (!fp) {
		perror("popen");
		return -1;
	}

	ret = pclose(fp);
	if (ret < 0)
		perror("pclose");

	return ret;
}

static int exec_sr_set_bsid_map(const char *bsid, const char *vnh)
{
	char cmd[BUFLEN + 1];
	FILE *fp;
	int ret;

	snprintf(cmd, BUFLEN, "%s sr action set %s %s 0 0",
		 _cfg.iproute, bsid, vnh);

	fp = popen(cmd, "r");
	if (!fp) {
		perror("popen");
		return -1;
	}

	ret = pclose(fp);
	if (ret < 0)
		perror("pclose");

	return ret;
}

static void get_vnh(struct in6_addr *res)
{
	int64_t vnh;

	vnh = atomic_inc(&_cfg.last_vnh);
	vnh = htobe64(vnh);

	memcpy(res, &_cfg.vnhp, 8);
	memcpy((char *)res + 8, &vnh, 8);
}

static void add_fib_entry(struct route *rt)
{
	char bsid[INET6_ADDRSTRLEN];
	char vnh[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &rt->vnh, vnh, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &rt->bsid, bsid, INET6_ADDRSTRLEN);

	exec_route_add_encap(vnh, rt->segs);
	exec_sr_set_bsid_map(bsid, vnh);
}

static void update_fib_entry(struct route *rt)
{
	char vnh[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &rt->vnh, vnh, INET6_ADDRSTRLEN);

	exec_route_change_encap(vnh, rt->segs);
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

	json_t *segment_lists = json_loads(flow_entry->segments, 0, NULL);
	if (!segment_lists) {
		fprintf(stderr, "Invalid json format for segment lists: %s\n", flow_entry->segments);
		return 0;
	}
	json_t *bsids = json_loads(flow_entry->bsid, 0, NULL);
	if (!bsids) {
		fprintf(stderr, "Invalid json format for bsids: %s\n", flow_entry->bsid);
		return 0;
	}

	/* to dns fifo: <bsid_1,bsid_2,...> (LAST OPERATION)
	 * to kernel: map bsid_i -> vnh && route vnh/128 -> encap seg6
	 */

	json_array_foreach(segment_lists, i, segs) {
		unsigned int k = 0;

		rt = malloc(sizeof(*rt));
		inet_pton(AF_INET6, json_string_value(json_array_get(bsids, i)),
			  &rt->bsid);
		get_vnh(&rt->vnh);

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

static void config_set_defaults(struct config *cfg)
{
	strcpy(cfg->ovsdb_conf.ovsdb_client, "ovsdb-client");
	strcpy(cfg->ovsdb_conf.ovsdb_server, "tcp:[::1]:6640");
	strcpy(cfg->ovsdb_conf.ovsdb_database, "SR_test");
	strcpy(cfg->iproute, "ip -6");
	strcpy(cfg->vnhpref, "2001:db8::");
	strcpy(cfg->ingress_iface, "lo");
	cfg->ovsdb_conf.ntransacts = 1;
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
		if (READ_INT(buf, ntransacts, &cfg->ovsdb_conf)) {
			if (!cfg->ovsdb_conf.ntransacts)
				cfg->ovsdb_conf.ntransacts = 1;
			continue;
		}
		if (READ_STRING(buf, iproute, cfg))
			continue;
		if (READ_STRING(buf, vnhpref, cfg)) {
			inet_pton(AF_INET6, cfg->vnhpref, &cfg->vnhp);
			continue;
		}
		if (READ_STRING(buf, ingress_iface, cfg))
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

	if (dryrun) {
		printf("Configuration file is correct");
		return 0;
	}

	_cfg.routes = hmap_new(hash_in6, compare_in6);
	if (!_cfg.routes) {
		pr_err("failed to initialize route map.");
		return -1;
	}

	_cfg.ovsdb_conf.ntransacts = 1;
	_cfg.srdb = srdb_new(&_cfg.ovsdb_conf);
	if (!_cfg.srdb) {
		pr_err("failed to initialize SRDB.");
		return -1;
	}

	if (srdb_monitor(_cfg.srdb, "FlowState", MON_INSERT | MON_UPDATE,
	                 read_flowstate, update_flowstate, NULL, false, true)
	    != MON_STATUS_RUNNING) {
		pr_err("failed to start FlowState monitor.");
		srdb_destroy(_cfg.srdb);
		return -1;
	}

	srdb_monitor_join_all(_cfg.srdb);

	srdb_destroy(_cfg.srdb);

	return 0;
}
