#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

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
	memcpy((char *)res + 4, &vnh, 8);
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

static void send_flow(const char *req, const char *dst, const char *bsid)
{
	char line[BUFLEN];

	snprintf(line, BUFLEN, "%s %s %s\n", req, dst, bsid);

	if (write(_cfg.dns_fd, line, strlen(line)) < 0)
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

static void read_flowstate(struct srdb_entry *entry)
{
	struct srdb_flow_entry *flow_entry = (struct srdb_flow_entry *)entry;

	strreplace(flow_entry->segments, ';', ',');

	/* to dns fifo: <req_uuid, addr, bsid> (LAST OPERATION)
	 * to kernel: map bsid -> vnh && route vnh/128 -> encap seg6
	 */

	add_fib_entry(flow_entry->bsid, flow_entry->segments);
	send_flow(flow_entry->request_uuid, flow_entry->dstaddr,
		  flow_entry->bsid);
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

	tbl = srdb_table_by_name(_cfg.srdb->tables, "FlowState");
	srdb_set_read_cb(_cfg.srdb, "FlowState", read_flowstate);
	args[0].srdb = _cfg.srdb;
	args[0].table = tbl;
	args[0].columns = "";

	pthread_create(&thr[0], NULL, thread_monitor, (void *)&args[0]);
}

int main(int argc, char **argv)
{
	const char *conf = DEFAULT_CONFIG;
	struct monitor_arg marg;
	pthread_t mon_thr;

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

	_cfg.srdb = srdb_new(&_cfg.ovsdb_conf);
	if (!_cfg.srdb) {
		pr_err("failed to initialize SRDB.");
		return -1;
	}

	launch_srdb(&mon_thr, &marg);

	pthread_join(mon_thr, NULL);

	srdb_destroy(_cfg.srdb);

	return 0;
}
