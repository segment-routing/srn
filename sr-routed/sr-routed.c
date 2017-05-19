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

#define DEFAULT_CONFIG	"sr-routed.conf"

struct config {
	struct ovsdb_config ovsdb_conf;
	char dns_fifo[SLEN + 1];
	char iproute[SLEN + 1];
	char vnhpref[SLEN + 1];
	char ingress_iface[SLEN + 1];

	struct srdb *srdb;
	struct in6_addr vnhp;
	uint64_t last_vnh;
	int dns_fd;
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

static int exec_sr_set_bsid_map(const char *bsid, const char *vnh)
{
	char cmd[BUFLEN + 1];
	FILE *fp;
	int ret;

	snprintf(cmd, BUFLEN, "%s sr action set %s %s",
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
	uint64_t vnh;

	_cfg.last_vnh++;

	vnh = htobe64(_cfg.last_vnh);

	memcpy(res, &_cfg.vnhp, 8);
	memcpy((char *)res + 8, &vnh, 8);
}

static void add_fib_entry(const char *bsid, const char *segments)
{
	struct in6_addr vnh_addr;
	char vnh[INET6_ADDRSTRLEN];

	get_vnh(&vnh_addr);

	inet_ntop(AF_INET6, &vnh_addr, vnh, INET6_ADDRSTRLEN);
	exec_route_add_encap(vnh, segments);
	exec_sr_set_bsid_map(bsid, vnh);
}

static void send_flow(const json_t *bsids)
{
	char line [SLEN + 1];
	json_t * bsid = NULL;
	unsigned int i = 0;
	unsigned int j = 0;
	json_array_foreach(bsids, i, bsid) {
		j += snprintf(line + j, SLEN - j, "%s%s", json_string_value(bsid),
			      i == json_array_size(bsids) - 1 ? "" : ",");
	}
	line[j] = '\n';

	if (write(_cfg.dns_fd, line, j+1) < 0)
		perror("write");
}

static int init_dns_fifo(void)
{
	int fd;

	mkfifo(_cfg.dns_fifo, 0640);

	fd = open(_cfg.dns_fifo, O_WRONLY);
	if (fd < 0)
		return fd;

	_cfg.dns_fd = fd;
	return 0;
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
		json_array_foreach(segs, j, segment)
			k += snprintf(segs_str + k, SLEN + 1 - k, "%s%s",
				      json_string_value(segment),
				      j == json_array_size(segs) - 1 ? "" : ",");
		add_fib_entry(json_string_value(json_array_get(bsids, i)), segs_str);
	}

	send_flow(bsids);
	set_status(flow_entry, FLOW_STATUS_RUNNING);

	json_decref(segment_lists);
	json_decref(bsids);

	return 0;
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
		if (READ_STRING(buf, dns_fifo, cfg))
			continue;
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

	ret = srdb_monitor(arg->srdb, arg->table, arg->modify, arg->initial, arg->insert, arg->delete);

	return (void *)(intptr_t)ret;
}

static void launch_srdb(pthread_t *thr, struct monitor_arg *args)
{
	struct srdb_table *tbl;

	tbl = srdb_table_by_name(_cfg.srdb->tables, "FlowState");
	srdb_set_read_cb(_cfg.srdb, "FlowState", read_flowstate);
	args[0].srdb = _cfg.srdb;
	args[0].table = tbl;
	args[0].initial = 1;
	args[0].modify = 1;
	args[0].insert = 1;
	args[0].delete = 1;

	pthread_create(&thr[0], NULL, thread_monitor, (void *)&args[0]);
}

int main(int argc, char **argv)
{
	const char *conf = DEFAULT_CONFIG;
	struct monitor_arg marg;
	pthread_t mon_thr[2];

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

	if (init_dns_fifo() < 0) {
		pr_err("failed to initialize DNS pipe.");
		return -1;
	}

	_cfg.ovsdb_conf.ntransacts = 1;
	_cfg.srdb = srdb_new(&_cfg.ovsdb_conf);
	if (!_cfg.srdb) {
		pr_err("failed to initialize SRDB.");
		return -1;
	}

	launch_srdb(mon_thr, &marg);

	pthread_join(mon_thr[0], NULL);

	pthread_join(mon_thr[1], NULL);

	srdb_destroy(_cfg.srdb);

	return 0;
}
