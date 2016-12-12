#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "arraylist.h"
#include "misc.h"
#include "srdb.h"
#include "rules.h"

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
	char ovsdb_client[SLEN + 1];
	char ovsdb_server[SLEN + 1];
	char ovsdb_database[SLEN + 1];
	char rules_file[SLEN + 1];

	/* internal data */
	struct arraylist *rules;
	struct rule *defrule;
	struct srdb_descriptor *flowreq_desc;
	size_t flowreq_desc_size;
};

static struct config cfg;

#define BUFLEN 1024

int ovsdb_monitor(const char *table, const char *columns,
		  void (*callback)(const char *buf))
{
	char line[BUFLEN];
	char cmd[256];
	FILE *fp;
	int ret;

	snprintf(cmd, 256, "%s monitor '%s' '%s' '%s' '%s' -f csv 2>/dev/null",
		 cfg.ovsdb_client, cfg.ovsdb_server, cfg.ovsdb_database, table,
		 columns);

	fp = popen(cmd, "r");
	if (!fp) {
		perror("popen");
		return -1;
	}

	while (fgets(line, BUFLEN, fp)) {
		strip_crlf(line);
		callback(line);
	}

	ret = pclose(fp);
	if (ret < 0)
		perror("pclose");

	/* ret = 256 => server closed connection */

	return ret;
}

int ovsdb_update(const char *table, const char *uuid, const char *fields)
{
	char line[BUFLEN];
	char cmd[256];
	FILE *fp;
	int ret = 0;

	
	snprintf(cmd, 256, "%s transact '%s' '[\"%s\", {\"op\": \"update\", "
			   "\"table\": \"%s\", \"where\": [[\"_uuid\", \"==\","
			   " [\"uuid\", \"%s\"]]], \"row\": {%s}}]' "
			   "2>/dev/null", cfg.ovsdb_client, cfg.ovsdb_server,
			   cfg.ovsdb_database, table, uuid, fields);

	fp = popen(cmd, "r");
	if (!fp) {
		perror("popen");
		return -1;
	}

	while (fgets(line, BUFLEN, fp)) {
		strip_crlf(line);
		if (!strcmp(line, "[{\"count\":1}]"))
			ret = 0;
		else
			ret = -1;
		break;
	}

	if (pclose(fp) < 0)
		perror("pclose");

	return ret;
}

static struct srdb_descriptor flowreq_desc_tmpl[] = {
	{
		.name	= "row",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
	},
	{
		.name	= "action",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
	},
	{
		.name	= "destination",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
	},
	{
		.name	= "dstaddr",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
	},
	{
		.name	= "source",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
	},
	{
		.name	= "bandwidth",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
	},
	{
		.name	= "delay",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
	},
	{
		.name	= "router",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
	},
	{
		.name	= "status",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
	},
	{
		.name	= "_version",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
	},
	{
		.name	= NULL,
	},
};

static inline void fill_flowreq_desc(struct srdb_descriptor *desc,
				     struct srdb_flowreq_entry *req)
{
	desc[0].data = req->_row;
	desc[1].data = req->_action;
	desc[2].data = req->destination;
	desc[3].data = req->dstaddr;
	desc[4].data = req->source;
	desc[5].data = &req->bandwidth;
	desc[6].data = &req->delay;
	desc[7].data = req->router;
	desc[8].data = &req->status;
	desc[9].data = req->_version;
}

static int find_desc_fromname(struct srdb_descriptor *desc, const char *name)
{
	int i;

	for (i = 0; desc[i].name; i++) {
		if (!strcmp(desc[i].name, name))
			return i;
	}

	return -1;
}

static int find_desc_fromidx(struct srdb_descriptor *desc, int idx)
{
	int i;

	for (i = 0; desc[i].name; i++) {
		if (desc[i].index == idx)
			return i;
	}

	return -1;
}

static void fill_srdb_index(struct srdb_descriptor *desc, char **vargs)
{
	int i, idx;

	for (i = 0; *vargs; vargs++, i++) {
		idx = find_desc_fromname(desc, *vargs);
		if (idx < 0)
			continue;
		desc[idx].index = i;
	}
}

static void fill_srdb_entry(struct srdb_descriptor *desc, char **vargs)
{
	int i, idx;

	for (i = 0; *vargs; vargs++, i++) {
		idx = find_desc_fromidx(desc, i);
		if (idx < 0)
			continue;

		switch (desc[idx].type) {
		case SRDB_STR:
			strncpy((char *)desc[idx].data, *vargs, desc[idx].maxlen);
			break;
		case SRDB_INT:
			*(int *)desc[idx].data = strtol(*vargs, NULL, 10);
			break;
		}
	}
}

static char *normalize_rowbuf(const char *buf)
{
	size_t n = 0;
	const char *s;
	char *buf2;

	for (s = buf; *s; s++) {
		if (*s != '"')
			n++;
	}

	buf2 = calloc(1, n);
	if (!buf2)
		return NULL;

	for (n = 0, s = buf; *s; s++) {
		if (*s != '"')
			buf2[n++] = *s;
	}

	return buf2;
}

static void cb_flowreq(const char *buf)
{
	struct srdb_flowreq_entry req;
	struct srdb_descriptor *desc;
	char field_update[SLEN + 1];
	enum flowreq_status rstat;
	struct rule *rule;
	char **vargs;
	char *buf2;
	int vargc;

	if (!buf || !*buf)
		return;

	buf2 = normalize_rowbuf(buf);
	if (!buf2)
		return;

	printf("NORMALIZED BUF: %s\n", buf2);

	vargs = strsplit(buf2, &vargc, ',');
	if (!vargs) {
		free(buf2);
		return;
	}

	memset(&req, 0, sizeof(req));

	/* descriptor */
	if (!strcmp(*vargs, "row")) {
		fill_srdb_index(cfg.flowreq_desc, vargs);
		free(vargs);
		free(buf2);
		return;
	}

	desc = memdup(cfg.flowreq_desc, cfg.flowreq_desc_size);
	if (!desc) {
		free(vargs);
		free(buf2);
		return;
	}

	fill_flowreq_desc(desc, &req);
	fill_srdb_entry(desc, vargs);

	free(desc);
	free(vargs);
	free(buf2);

	/* process req */

	rule = match_rules(cfg.rules, req.source, req.destination);

	printf("matching rule: %p\n", rule);

	if (!rule)
		rule = cfg.defrule;

	printf("matching rule(2): %p\n", rule);

	if (rule->type == RULE_ALLOW)
		rstat = STATUS_ALLOWED;
	else
		rstat = STATUS_DENIED;

	snprintf(field_update, SLEN, "\"status\": %d", rstat);
	if (ovsdb_update("FlowReq", req._row, field_update) < 0)
		pr_err("failed to update row uuid %s to status %d\n", req._row, rstat);
}

static void cb_flowstate(const char *buf __unused)
{
}

static void cb_netstate(const char *buf __unused)
{
}

#define READ_STRING(b, arg, dst) sscanf(b, #arg " \"%[^\"]\"", dst->arg)

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
		if (READ_STRING(buf, ovsdb_client, cfg))
			continue;
		if (READ_STRING(buf, ovsdb_server, cfg))
			continue;
		if (READ_STRING(buf, ovsdb_database, cfg))
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

static int init_srdb(void)
{
	struct srdb_descriptor *desc;
	size_t size;

	size = sizeof(flowreq_desc_tmpl);

	desc = memdup(flowreq_desc_tmpl, size);
	if (!desc)
		return -1;

	cfg.flowreq_desc = desc;
	cfg.flowreq_desc_size = size;

	return 0;
}

int main(int argc, char **argv)
{
	const char *conf = DEFAULT_CONFIG;
	int ret;

	if (argc > 2) {
		fprintf(stderr, "Usage: %s [configfile]\n", argv[0]);
		return -1;
	}

	if (argc == 2)
		conf = argv[1];

	if (load_config(conf, &cfg) < 0) {
		pr_err("failed to load configuration file.");
		return -1;
	}

	cfg.rules = load_rules(cfg.rules_file, &cfg.defrule);
	if (!cfg.rules) {
		pr_err("failed to load rules file.");
		return -1;
	}

	if (init_srdb() < 0) {
		pr_err("failed to initialize SRDB.\n");
		return -1;
	}

	ret = ovsdb_monitor("FlowReq", "!initial,!delete,!modify", cb_flowreq);

	printf("ret: %d\n", ret);

	return 0;
}
