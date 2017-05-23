#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <errno.h>
#include <assert.h>

#include <jansson.h>

#include "srdb.h"
#include "misc.h"
#include "llist.h"

#define BUFLEN 1024
#define JSON_BUFLEN 4096
#define READ_OVSDB_SERVER(b, addr, port) sscanf(b, "tcp:[%[^]]]:%hu", addr, port)
#define BOOL_TO_STR(boolean) ((boolean) ? "true" : "false")

static void *transaction_worker(void *args);
static int srdb_read(const char *uuid, json_t *json, struct srdb_table *tbl);

static int echo_reply(int fd)
{
	const char reply[] = "{\"id\":\"echo\",\"result\":[],\"error\":null}";

	return send(fd, reply, sizeof(reply) - 1, 0);
}

static int parse_ovsdb_update_tables(json_t *table_updates,
				     struct srdb_table *tbl)
{
	json_t *modification;
	const char *uuid;
	int ret = 0;

	json_object_foreach(table_updates, uuid, modification) {
		if ((ret = srdb_read(uuid, modification, tbl))) {
			break;
		}
	}
	return ret;
}

static int parse_ovsdb_monitor_reply(json_t *monitor_reply,
				     struct srdb_table *tbl)
{
	int ret = 0;

	if (!json_is_null(json_object_get(monitor_reply, "error"))) {
		fprintf(stderr, "There is a non-null error message in the monitor reply\n");
		return -1;
	}
	json_t *updates = json_object_get(monitor_reply, "result");
	if (!updates) {
		fprintf(stderr, "Monitor reply parsing issue: No result found\n");
		return -1;
	}
	json_t *table_updates = json_object_get(updates, tbl->name);
	if (table_updates)
		ret = parse_ovsdb_update_tables(table_updates, tbl);

	sem_post(&tbl->initial_read);

	return ret;
}

static int parse_ovsdb_update(json_t *update, struct srdb_table *tbl)
{
	json_t *params, *updates, *table_updates;

	params = json_object_get(update, "params");
	if (!params) {
		pr_err("no params object in json.");
		return -1;
	}

	if (json_array_size(params) < 2) {
		pr_err("params object has invalid array size.");
		return -1;
	}

	updates = json_array_get(params, 1);
	if (!updates) {
		pr_err("cannot fetch updates from params array.");
		return -1;
	}

	table_updates = json_object_get(updates, tbl->name);
	if (!table_updates) {
		pr_err("cannot fetch updates for table %s.", tbl->name);
		return -1;
	}

	return parse_ovsdb_update_tables(table_updates, tbl);
}

static bool is_echo(json_t *msg)
{
	json_t *method = json_object_get(msg, "method");

	if (!method || !json_is_string(method))
		return false;

	if (!strcmp(json_string_value(method), "echo"))
		return true;

	return false;
}

static int ovsdb_socket(const struct ovsdb_config *conf)
{
	int fd = -1;
	char str_addr[BUFLEN+1];
	unsigned short port;

	READ_OVSDB_SERVER(conf->ovsdb_server, str_addr, &port);
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0
	};
	inet_pton(AF_INET6, str_addr, &addr.sin6_addr);

	fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr))) {
		perror("connect to ovsdb server");
		goto close_fd;
	}

	int i = 1;
	if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &i, sizeof(i)) < 0) {
		perror("setsockopt");
		goto close_fd;
	}

out:
	return fd;
close_fd:
	close(fd);
	fd = -1;
	goto out;
}

static void *ovsdb_monitor(void *_args)
{
	struct monitor_desc *desc = _args;
	json_error_t json_error;
	struct srdb_table *tbl;
	struct pollfd pfd;
	struct srdb *srdb;
	int mon_flags;
	json_t *json;
	int fd, len;
	char *buf;
	int ret;

	srdb = desc->srdb;
	tbl = desc->tbl;
	mon_flags = desc->mon_flags;

	fd = ovsdb_socket(srdb->conf);
	if (fd < 0)
		goto out;

	buf = malloc(JSON_BUFLEN);
	if (!buf)
		goto out_close;

	len = snprintf(buf, JSON_BUFLEN, OVSDB_MONITOR_FORMAT,
		       srdb->conf->ovsdb_database, tbl->name,
		       BOOL_TO_STR(mon_flags & MON_UPDATE),
		       BOOL_TO_STR(mon_flags & MON_INITIAL),
		       BOOL_TO_STR(mon_flags & MON_INSERT),
		       BOOL_TO_STR(mon_flags & MON_DELETE));

	ret = send(fd, buf, len, 0);
	if (ret < 0) {
		pr_err("failed to send monitor request (%s).", strerror(errno));
		goto out_close;
	}

	len = 0;
	pfd.fd = fd;
	pfd.events = POLLIN | POLLPRI;

	for (;;) {
		int ready, jpos = 0;

		ready = poll(&pfd, 1, 1);
		if (ready < 0) {
			pr_err("poll (%s).", strerror(errno));
			goto out_close;
		}

		if (!ready)
			continue;

		if (!sem_trywait(&desc->stop))
			goto out_close;

		if (pfd.revents & POLLERR) {
			pr_err("poll_revents (%s).", strerror(errno));
			goto out_close;
		}

		ret = recv(fd, buf + len, JSON_BUFLEN - len, 0);
		if (ret < 0) {
			pr_err("failed to read from monitor socket (%s).",
				strerror(errno));
			goto out_close;
		}

		if (!ret) {
			pr_err("ovsdb server closed the connection.");
			goto out_close;
		}

		len += ret;

		/* loop on buffer and process all valid json */
		do {
			json = json_loadb(buf + jpos, len - jpos,
					  JSON_DISABLE_EOF_CHECK, &json_error);

			if (!json)
				break;

			if (is_echo(json)) {
				if (echo_reply(fd) < 0) {
					pr_err("failed to send echo reply (%s)",
						strerror(errno));
				}
			} else {
				if (json_is_integer(json_object_get(json, "id")))
					parse_ovsdb_monitor_reply(json, tbl);
				else
					parse_ovsdb_update(json, tbl);
			}

			jpos += json_error.position;

			json_decref(json);

		} while (jpos < len - 1);

		if (!json && jpos) {
			/* one or more valid json were processed */
			memmove(buf, buf + jpos, len - jpos);
			len -= jpos;
		} else if (json) {
			/* the full buffer was processed */
			len = 0;
		}

		/* abort if buffer is full and no processing was possible */
		if (len == JSON_BUFLEN) {
			pr_err("max recvq exceeded.");
			goto out_close;
		}
	}

	sem_post(&desc->zombie);

out_close:
	close(fd);
	free(buf);
out:
	/* temp hack to prevent deadlock when ovsdb server is down at startup */
	sem_post(&tbl->initial_read);

	return NULL;
}

static struct transaction *ovsdb_update(struct srdb *srdb, const char *table,
					const char *uuid, json_t *fields)
{
	char *json_buf, *str_fields;
	struct transaction *tr;
	json_t *json_update;

	json_buf = malloc(JSON_BUFLEN);
	if (!json_buf)
		return NULL;

	str_fields = json_dumps(fields, 0);
	if (!str_fields) {
		pr_err("failed to dump json fields.");
		free(json_buf);
		return NULL;
	}

	snprintf(json_buf, JSON_BUFLEN, OVSDB_UPDATE_FORMAT,
		 srdb->conf->ovsdb_database, str_fields, table, uuid);
	free(str_fields);

	json_update = json_loads(json_buf, 0, NULL);
	if (!json_update) {
		pr_err("failed to build json object.");
		free(json_buf);
		return NULL;
	}

	free(json_buf);

	tr = create_transaction(json_update);
	if (!tr) {
		pr_err("failed to build transaction object.");
		json_decref(json_update);
		return NULL;
	}

	sbuf_push(srdb->transactions, tr);

	return tr;
}

static struct transaction *ovsdb_insert(struct srdb *srdb, const char *table,
					json_t *fields)
{
	char *json_buf, *str_fields;
	struct transaction *tr;
	json_t *json_insert;

	json_buf = malloc(JSON_BUFLEN);
	if (!json_buf)
		return NULL;

	str_fields = json_dumps(fields, 0);
	if (!str_fields) {
		pr_err("failed to dump json fields.");
		free(json_buf);
		return NULL;
	}

	snprintf(json_buf, JSON_BUFLEN, OVSDB_INSERT_FORMAT,
		 srdb->conf->ovsdb_database, str_fields, table);
	free(str_fields);

	json_insert = json_loads(json_buf, 0, NULL);
	if (!json_insert) {
		pr_err("failed to build json object.");
		free(json_buf);
		return NULL;
	}

	free(json_buf);

	tr = create_transaction(json_insert);
	if (!tr) {
		pr_err("failed to build transaction object.");
		json_decref(json_insert);
		return NULL;
	}

	sbuf_push(srdb->transactions, tr);

	return tr;
}

static int find_desc_fromindex(struct srdb_descriptor *desc, unsigned int index)
{
	int i;

	for (i = 0; desc[i].name; i++) {
		if (desc[i].index == index)
			return i;
	}

	return -1;
}

static unsigned int fill_srdb_entry(struct srdb_descriptor *desc,
				    struct srdb_entry *entry, const char *uuid,
				    json_t *line_json)
{
	unsigned int index_mask = 0;
	json_t *column_value;
	void *data;
	int i;

	for (i = 0; desc[i].name; i++) {
		if (!strcmp(desc[i].name, "row")) {
			strncpy(entry->row, uuid, desc[i].maxlen);
			continue;
		}

		column_value = json_object_get(line_json, desc[i].name);
		if (!column_value)
			continue;

		if (desc[i].index)
			index_mask |= ENTRY_MASK(desc[i].index);

		if (!strcmp(desc[i].name, "_version")) {
			column_value = json_object_get(line_json, "_version");
			column_value = json_array_get(column_value, 1);
		}

		data = (unsigned char *)entry + desc[i].offset;

		switch (desc[i].type) {
		case SRDB_STR:
			if (!json_is_string(column_value)) {
				pr_err("type str mismatch for field name `%s'.",
					desc[i].name);
			} else {
				strncpy((char *)data,
					json_string_value(column_value),
					desc[i].maxlen);
			}
			break;
		case SRDB_INT:
			if (!json_is_integer(column_value)) {
				pr_err("type int mismatch for field name `%s'.",
					desc[i].name);
			} else {
				*(int *)data = json_integer_value(column_value);
			}
			break;
		case SRDB_VARSTR:
			if (!json_is_string(column_value)) {
				pr_err("type str mismatch for field name `%s'.",
					desc[i].name);
			} else {
				*(char **)data = strndup(json_string_value(column_value),
							 desc[i].maxlen);
			}
			break;
		}
	}

	return index_mask;
}

void free_srdb_entry(struct srdb_descriptor *desc,
		     struct srdb_entry *entry)
{
	struct srdb_descriptor *tmp;

	for (tmp = desc; tmp->name; tmp++) {
		void *data = (unsigned char *)entry + tmp->offset;

		if (tmp->type == SRDB_VARSTR)
			free(*(char **)data);
	}

	free(entry);
}

#define SRDB_BUILTIN_ENTRIES()					\
	{							\
		.name	= "row",				\
		.type	= SRDB_STR,				\
		.maxlen	= SLEN,					\
		.builtin = true,				\
		.offset	= offsetof(struct srdb_entry, row),	\
		.index	= 0,					\
	},							\
	{							\
		.name	= "_version",				\
		.type	= SRDB_STR,				\
		.maxlen	= SLEN,					\
		.builtin = true,				\
		.offset = offsetof(struct srdb_entry, version),	\
		.index	= 0,					\
	}

#define OFFSET_ROUTERIDS(NAME)	offsetof(struct srdb_router_entry, NAME)
static struct srdb_descriptor routerids_desc_tmpl[] = {
	SRDB_BUILTIN_ENTRIES(),

	{
		.name	= "router",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_ROUTERIDS(router),
		.index	= RTE_ROUTER,
	},
	{
		.name	= NULL,
	},
};

#define OFFSET_FLOWREQ(NAME)	offsetof(struct srdb_flowreq_entry, NAME)
static struct srdb_descriptor flowreq_desc_tmpl[] = {
	SRDB_BUILTIN_ENTRIES(),

	{
		.name	= "req_id",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWREQ(request_id),
		.index	= FREQ_REQID,
	},
	{
		.name	= "destination",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWREQ(destination),
		.index	= FREQ_DESTINATION,
	},
	{
		.name	= "dstaddr",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWREQ(dstaddr),
		.index	= FREQ_DSTADDR,
	},
	{
		.name	= "source",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWREQ(source),
		.index	= FREQ_SOURCE,
	},
	{
		.name	= "bandwidth",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
		.offset	= OFFSET_FLOWREQ(bandwidth),
		.index	= FREQ_BANDWIDTH,
	},
	{
		.name	= "delay",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
		.offset	= OFFSET_FLOWREQ(delay),
		.index	= FREQ_DELAY,
	},
	{
		.name	= "router",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset = OFFSET_FLOWREQ(router),
		.index	= FREQ_ROUTER,
	},
	{
		.name	= "proxy",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWREQ(proxy),
		.index	= FREQ_PROXY,
	},
	{
		.name	= "status",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
		.offset	= OFFSET_FLOWREQ(status),
		.index	= FREQ_STATUS,
	},
	{
		.name	= NULL,
	},
};

#define OFFSET_FLOWSTATE(NAME)	offsetof(struct srdb_flow_entry, NAME)
static struct srdb_descriptor flowstate_desc_tmpl[] = {
	SRDB_BUILTIN_ENTRIES(),

	{
		.name	= "destination",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(destination),
		.index	= FE_DESTINATION,
	},
	{
		.name	= "dstaddr",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(dstaddr),
		.index	= FE_DSTADDR,
	},
	{
		.name	= "bsid",
		.type	= SRDB_VARSTR,
		.maxlen	= BUFLEN,
		.offset	= OFFSET_FLOWSTATE(bsid),
		.index	= FE_BSID,
	},
	{
		.name	= "segments",
		.type	= SRDB_VARSTR,
		.maxlen	= BUFLEN,
		.offset	= OFFSET_FLOWSTATE(segments),
		.index	= FE_SEGMENTS,
	},
	{
		.name	= "bandwidth",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(bandwidth),
		.index	= FE_BANDWIDTH,
	},
	{
		.name	= "delay",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(delay),
		.index	= FE_DELAY,
	},
	{
		.name	= "policing",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(policing),
		.index	= FE_POLICING,
	},
	{
		.name	= "source",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(source),
		.index	= FE_SOURCE,
	},
	{
		.name	= "sourceIPs",
		.type	= SRDB_VARSTR,
		.maxlen	= BUFLEN,
		.offset	= OFFSET_FLOWSTATE(sourceIPs),
		.index	= FE_SOURCEIPS,
	},
	{
		.name	= "router",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(router),
		.index	= FE_ROUTER,
	},
	{
		.name	= "proxy",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(proxy),
		.index	= FE_PROXY,
	},
	{
		.name	= "interface",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(interface),
		.index	= FE_INTERFACE,
	},
	{
		.name	= "reverseFlow",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(reverse_flow_uuid),
		.index	= FE_RF_UUID,
	},
	{
		.name	= "request",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(request_id),
		.index	= FE_REQID,
	},
	{
		.name	= "ttl",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(ttl),
		.index	= FE_TTL,
	},
	{
		.name	= "idle",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(idle),
		.index	= FE_IDLE,
	},
	{
		.name	= "timestamp",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(timestamp),
		.index	= FE_TS,
	},
	{
		.name	= "status",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(status),
		.index	= FE_STATUS,
	},
	{
		.name	= NULL,
	},
};

#define OFFSET_LINKSTATE(NAME)	offsetof(struct srdb_linkstate_entry, NAME)
static struct srdb_descriptor linkstate_desc_tmpl[] = {
	SRDB_BUILTIN_ENTRIES(),

	{
		.name	= "name1",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_LINKSTATE(name1),
		.index	= LS_NAME1,
	},
	{
		.name	= "addr1",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_LINKSTATE(addr1),
		.index	= LS_ADDR1,
	},
	{
		.name	= "name2",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_LINKSTATE(name2),
		.index	= LS_NAME2,
	},
	{
		.name	= "addr2",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_LINKSTATE(addr2),
		.index	= LS_ADDR2,
	},
	{
		.name	= "metric",
		.type	= SRDB_INT,
		.offset	= OFFSET_LINKSTATE(metric),
		.index	= LS_METRIC,
	},
	{
		.name	= "bw",
		.type	= SRDB_INT,
		.offset	= OFFSET_LINKSTATE(bw),
		.index	= LS_BW,
	},
	{
		.name	= "ava_bw",
		.type	= SRDB_INT,
		.offset	= OFFSET_LINKSTATE(ava_bw),
		.index	= LS_AVA_BW,
	},
	{
		.name	= "delay",
		.type	= SRDB_INT,
		.offset	= OFFSET_LINKSTATE(delay),
		.index	= LS_DELAY,
	},
	{
		.name	= NULL,
	},
};

#define OFFSET_NODESTATE(NAME)	offsetof(struct srdb_nodestate_entry, NAME)
static struct srdb_descriptor nodestate_desc_tmpl[] = {
	SRDB_BUILTIN_ENTRIES(),

	{
		.name	= "name",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_NODESTATE(name),
		.index	= NODE_NAME,
	},
	{
		.name	= "addr",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_NODESTATE(addr),
		.index	= NODE_ADDR,
	},
	{
		.name	= "prefix",
		.type	= SRDB_VARSTR,
		.maxlen	= BUFLEN,
		.offset	= OFFSET_NODESTATE(prefix),
		.index	= NODE_PREFIX,
	},
	{
		.name	= "pbsid",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_NODESTATE(pbsid),
		.index	= NODE_PBSID,
	},
	{
		.name	= NULL,
	},
};

static struct srdb_table srdb_tables[] = {
	{
		.name		= "RouterIds",
		.entry_size	= sizeof(struct srdb_router_entry),
		.desc_tmpl	= routerids_desc_tmpl,
		.desc_size	= sizeof(routerids_desc_tmpl),
	},
	{
		.name		= "FlowReq",
		.entry_size	= sizeof(struct srdb_flowreq_entry),
		.desc_tmpl	= flowreq_desc_tmpl,
		.desc_size	= sizeof(flowreq_desc_tmpl),
	},
	{
		.name		= "FlowState",
		.entry_size	= sizeof(struct srdb_flow_entry),
		.desc_tmpl	= flowstate_desc_tmpl,
		.desc_size	= sizeof(flowstate_desc_tmpl),
	},
	{
		.name		= "LinkState",
		.entry_size	= sizeof(struct srdb_linkstate_entry),
		.desc_tmpl	= linkstate_desc_tmpl,
		.desc_size	= sizeof(linkstate_desc_tmpl),
	},
	{
		.name		= "NodeState",
		.entry_size	= sizeof(struct srdb_nodestate_entry),
		.desc_tmpl	= nodestate_desc_tmpl,
		.desc_size	= sizeof(nodestate_desc_tmpl),
	},
	{
		.name		= NULL,
	},
};

struct srdb_table *srdb_get_tables(void)
{
	struct srdb_table *tbl;
	unsigned int i;

	tbl = memdup(srdb_tables, sizeof(srdb_tables));
	if (!tbl)
		return NULL;

	for (i = 0; i < sizeof(srdb_tables) / sizeof(struct srdb_table); i++) {
		if (tbl[i].name)
			tbl[i].desc = memdup(tbl[i].desc_tmpl, tbl[i].desc_size);
	}

	return tbl;
}

void srdb_free_tables(struct srdb_table *tbl)
{
	unsigned int i;

	for (i = 0; i < sizeof(srdb_tables) / sizeof(struct srdb_table); i++) {
		if (tbl[i].name)
			free(tbl[i].desc);
	}

	free(tbl);
}

struct srdb_table *srdb_table_by_name(struct srdb_table *tables,
				      const char *name)
{
	struct srdb_table *tbl;

	for (tbl = tables; tbl->name; tbl++) {
		if (!strcmp(tbl->name, name))
			return tbl;
	}

	return NULL;
}

#define OP_INSERT	1
#define OP_UPDATE	2
#define OP_DELETE	3

static int srdb_read(const char *uuid, json_t *json, struct srdb_table *tbl)
{
	struct srdb_entry *entry, *update_entry;
	unsigned int imask, op = 0;
	json_t *new, *old;
	int ret = 0;

	if (!uuid || !json)
		return -1;

	new = json_object_get(json, "new");
	old = json_object_get(json, "old");

	if (new && !old)
		op = OP_INSERT;
	else if (new && old)
		op = OP_UPDATE;
	else if (old)
		op = OP_DELETE;

	if (!op) {
		pr_err("unknown row data configuration.");
		return -1;
	}

	entry = calloc(1, tbl->entry_size);

	switch (op) {
	case OP_INSERT:
		fill_srdb_entry(tbl->desc, entry, uuid, new);

		if (tbl->cb_insert)
			ret = tbl->cb_insert(entry);

		if (!tbl->delayed_free)
			free_srdb_entry(tbl->desc, entry);

		break;
	case OP_UPDATE:
		update_entry = calloc(1, tbl->entry_size);

		/* "new" contains *all* field set, with new values */
		fill_srdb_entry(tbl->desc, entry, uuid, new);

		/* "old" contains only changed fields, with old values */
		imask = fill_srdb_entry(tbl->desc, update_entry, uuid, old);

		if (tbl->cb_update)
			ret = tbl->cb_update(entry, update_entry, imask);

		if (!tbl->delayed_free) {
			free_srdb_entry(tbl->desc, update_entry);
			free_srdb_entry(tbl->desc, entry);
		}

		break;
	case OP_DELETE:
		fill_srdb_entry(tbl->desc, entry, uuid, old);

		if (tbl->cb_delete)
			ret = tbl->cb_delete(entry);

		if (!tbl->delayed_free)
			free_srdb_entry(tbl->desc, entry);

		break;
	}

	return ret;
}

int srdb_monitor(struct srdb *srdb, const char *table, int mon_flags,
		 table_insert_cb_t cb_insert, table_update_cb_t cb_update,
		 table_delete_cb_t cb_delete, bool delayed_free, bool sync)
{
	struct monitor_desc *desc;
	struct srdb_table *tbl;

	tbl = srdb_table_by_name(srdb->tables, table);
	if (!tbl)
		return -1;

	tbl->cb_insert = cb_insert;
	tbl->cb_update = cb_update;
	tbl->cb_delete = cb_delete;
	tbl->delayed_free = delayed_free;
	sem_init(&tbl->initial_read, 0, 0);

	desc = malloc(sizeof(*desc));
	if (!desc)
		return -1;

	desc->srdb = srdb;
	desc->tbl = tbl;
	desc->mon_flags = mon_flags;
	sem_init(&desc->stop, 0, 0);
	sem_init(&desc->zombie, 0, 0);

	llist_node_insert_tail(srdb->monitors, desc);

	pthread_create(&desc->thread, NULL, ovsdb_monitor, desc);

	if (sync)
		sem_wait(&tbl->initial_read);

	return 0;
}

static void write_desc_data(json_t *row, const struct srdb_descriptor *desc,
			   struct srdb_entry *entry)
{
	void *data;

	data = (unsigned char *)entry + desc->offset;

	switch (desc->type) {
	case SRDB_STR:
		json_object_set_new(row, desc->name, json_string((char *)data));
		break;
	case SRDB_INT:
		json_object_set_new(row, desc->name,
				    json_integer(*(int *)data));
		break;
	case SRDB_VARSTR:
		json_object_set_new(row, desc->name,
				    json_string(*(char **)data));
		break;
	}
}

struct srdb_update_transact *srdb_update_prepare(struct srdb *srdb,
						 struct srdb_table *tbl,
						 struct srdb_entry *entry)
{
	struct srdb_update_transact *utr;

	utr = malloc(sizeof(*utr));
	if (!utr)
		return NULL;

	utr->srdb = srdb;
	utr->tbl = tbl;
	utr->entry = entry;
	utr->index_mask = 0;
	utr->fields = json_object();

	return utr;
}

int srdb_update_append(struct srdb_update_transact *utr, unsigned int index)
{
	const struct srdb_descriptor *desc;
	int idx;

	idx = find_desc_fromindex(utr->tbl->desc, index);
	if (idx < 0)
		return -1;

	desc = &utr->tbl->desc[idx];

	write_desc_data(utr->fields, desc, utr->entry);
	utr->index_mask |= ENTRY_MASK(index);

	return 0;
}

void srdb_update_append_mask(struct srdb_update_transact *utr,
			     unsigned int index_mask)
{
	const struct srdb_descriptor *desc;
	unsigned int i;

	for (i = 0; utr->tbl->desc[i].name; i++) {
		desc = &utr->tbl->desc[i];

		if (!desc->index)
			continue;

		if (index_mask & ENTRY_MASK(desc->index))
			write_desc_data(utr->fields, desc, utr->entry);
	}

	utr->index_mask |= index_mask;
}

struct transaction *srdb_update_commit(struct srdb_update_transact *utr)
{
	struct transaction *tr;

	tr = ovsdb_update(utr->srdb, utr->tbl->name, utr->entry->row,
			  utr->fields);

	json_decref(utr->fields);
	free(utr);

	return tr;
}

struct transaction *srdb_update(struct srdb *srdb, struct srdb_table *tbl,
				struct srdb_entry *entry, unsigned int index)
{
	struct srdb_update_transact *utr;

	utr = srdb_update_prepare(srdb, tbl, entry);
	if (!utr)
		return NULL;

	srdb_update_append(utr, index);

	return srdb_update_commit(utr);
}

int srdb_update_result(struct transaction *tr, int *count)
{
	json_t *res, *error, *jres, *jcount, *jerr;
	int ret = 0;

	res = sbuf_pop(tr->result);

	if (!res)
		goto out_error;

	error = json_object_get(res, "error");

	if (!error || !json_is_null(error))
		goto out_error;

	jres = json_array_get(json_object_get(res, "result"), 0);

	jerr = json_object_get(jres, "error");
	if (jerr && !json_is_null(jerr))
		goto out_error;

	jcount = json_object_get(jres, "count");
	if (count)
		*count = json_integer_value(jcount);

out_free:
	if (res)
		json_decref(res);
	free_transaction(tr);
	return ret;
out_error:
	ret = -1;
	goto out_free;
}

int srdb_update_sync(struct srdb *srdb, struct srdb_table *tbl,
		     struct srdb_entry *entry, unsigned int index,
		     int *count)
{
	struct transaction *tr;

	tr = srdb_update(srdb, tbl, entry, index);
	if (!tr)
		return -1;

	return srdb_update_result(tr, count);
}

struct transaction *srdb_insert(struct srdb *srdb, struct srdb_table *tbl,
				struct srdb_entry *entry)
{
	const struct srdb_descriptor *tmp;
	struct transaction *tr = NULL;

	json_t *row = json_object();

	for (tmp = tbl->desc; tmp->name; tmp++) {
		if (!tmp->builtin)
			write_desc_data(row, tmp, entry);
	}

	tr = ovsdb_insert(srdb, tbl->name, row);

	json_decref(row);
	return tr;
}

int srdb_insert_sync(struct srdb *srdb, struct srdb_table *tbl,
		     struct srdb_entry *entry, char *uuid)
{
	json_t *res, *error, *jres, *juuid, *jerr;
	struct transaction *tr;
	int ret = 0;

	tr = srdb_insert(srdb, tbl, entry);
	if (!tr)
		return -1;

	res = sbuf_pop(tr->result);

	if (!res)
		goto out_error;

	error = json_object_get(res, "error");

	if (!error || !json_is_null(error))
		goto out_error;

	jres = json_array_get(json_object_get(res, "result"), 0);

	jerr = json_object_get(jres, "error");
	if (jerr && !json_is_null(jerr))
		goto out_error;

	juuid = json_array_get(json_object_get(jres, "uuid"), 1);
	if (uuid)
		strncpy(uuid, json_string_value(juuid), SLEN + 1);

out_free:
	if (res)
		json_decref(res);
	free_transaction(tr);
	return ret;
out_error:
	ret = -1;
	goto out_free;
}

struct srdb *srdb_new(struct ovsdb_config *conf)
{
	struct srdb *srdb;
	int i;

	srdb = malloc(sizeof(*srdb));
	if (!srdb)
		return NULL;

	srdb->tables = srdb_get_tables();
	if (!srdb->tables)
		goto out_free_srdb;

	srdb->conf = conf;
	srdb->tr_workers = malloc(conf->ntransacts * sizeof(pthread_t));
	if (!srdb->tr_workers)
		goto out_free_tables;

	srdb->monitors = llist_node_alloc();
	if (!srdb->monitors)
		goto out_free_workers;

	srdb->transactions = sbuf_new(2 * conf->ntransacts);
	if (!srdb->transactions)
		goto out_free_monitors;

	for (i = 0; i < conf->ntransacts; i++)
		pthread_create(&srdb->tr_workers[i], NULL, transaction_worker,
			       srdb);

	return srdb;

out_free_monitors:
	llist_node_destroy(srdb->monitors);
out_free_workers:
	free(srdb->tr_workers);
out_free_tables:
	srdb_free_tables(srdb->tables);
out_free_srdb:
	free(srdb);
	return NULL;
}

void srdb_destroy(struct srdb *srdb)
{
	struct llist_node *iter;
	struct monitor_desc *md;
	int i;

	for (i = 0; i < srdb->conf->ntransacts; i++)
		sbuf_push(srdb->transactions, NULL);

	for (i = 0; i < srdb->conf->ntransacts; i++)
		pthread_join(srdb->tr_workers[i], NULL);

	llist_node_foreach(srdb->monitors, iter) {
		md = iter->data;
		sem_post(&md->stop);
		pthread_join(md->thread, NULL);
		free(md);
	}

	llist_node_destroy(srdb->monitors);

	free(srdb->tr_workers);
	sbuf_destroy(srdb->transactions);
	srdb_free_tables(srdb->tables);
	free(srdb);
}

void srdb_monitor_join_all(struct srdb *srdb)
{
	struct llist_node *iter, *tmp;
	struct monitor_desc *md;

	llist_node_foreach_safe(srdb->monitors, iter, tmp) {
		md = iter->data;
		pthread_join(md->thread, NULL);
		llist_node_remove(srdb->monitors, iter);
		free(md);
	}
}

struct transaction *create_transaction(json_t *json)
{
	struct transaction *tr;

	tr = malloc(sizeof(*tr));
	if (!tr)
		return NULL;

	tr->result = sbuf_new(1);
	if (!tr->result) {
		free(tr);
		return NULL;
	}

	tr->json = json;

	return tr;
}

void free_transaction(struct transaction *tr)
{
	json_decref(tr->json);
	sbuf_destroy(tr->result);
	free(tr);
}

static int send_transaction(int fd, json_t *json, unsigned int id)
{
	ssize_t len, ret;
	json_t *method;
	char *json_buf;

	method = json_object_get(json, "method");
	if (!method || strcmp(json_string_value(method), "transact"))
		return -1;

	json_buf = malloc(JSON_BUFLEN);
	if (!json_buf)
		return -1;

	json_object_set_new(json, "id", json_integer(id));

	len = json_dumpb(json, json_buf, JSON_BUFLEN, JSON_COMPACT);
	if (!len)
		goto out_err;

	ret = send(fd, json_buf, len, 0);
	if (ret < 0) {
		pr_err("failed to send transaction (%s).", strerror(errno));
		goto out_err;
	}

	if (ret != len) {
		pr_err("partial send (%ld < %ld) for transaction id %u.", ret,
		       len, id);
		goto out_err;
	}

	ret = 0;

out:
	free(json_buf);
	return ret;
out_err:
	ret = -1;
	goto out;
}

static json_t *recv_transaction_result(int fd)
{
	json_t *json = NULL;
	char *json_buf;
	int ret;

	json_buf = malloc(JSON_BUFLEN);
	if (!json_buf)
		return NULL;

	/* transaction results are small, assume we'll get everything
	 * in one shot.
	 */

	ret = recv(fd, json_buf, JSON_BUFLEN, 0);
	if (ret <= 0)
		goto out;

	json = json_loadb(json_buf, ret, JSON_DISABLE_EOF_CHECK, NULL);

out:
	free(json_buf);
	return json;
}

static json_t *fetch_transaction_result(int fd)
{
	json_t *json, *method, *error;

	/* data available on ovsdb socket
	 * echo, and if pending, transaction result
	 */

	json = recv_transaction_result(fd);
	if (!json)
		return NULL;

	method = json_object_get(json, "method");
	error = json_object_get(json, "error");

	/* ping */
	if (is_echo(json)) {
		if (echo_reply(fd) < 0) {
			pr_err("failed to send echo reply (%s).",
				strerror(errno));
		}

		json_decref(json);
		return NULL;
	}

	/* transaction result */
	if (!method && error)
		return json;

	/* unknown */
	json_decref(json);
	return NULL;
}

static void *transaction_worker(void *args)
{
	struct transaction *tr = NULL;
	unsigned int transact_id = 0;
	struct srdb *srdb = args;
	bool pending = false;
	struct pollfd pfd;
	int fd, ready;
	json_t *json;

	fd = ovsdb_socket(srdb->conf);
	if (fd < 0)
		return NULL;

	pfd.fd = fd;
	pfd.events = POLLIN | POLLPRI;

	for (;;) {
		ready = poll(&pfd, 1, 1);
		if (ready < 0) {
			perror("poll");
			break;
		}

		if (ready) {
			if (pfd.revents & POLLERR) {
				perror("poll_revents");
				break;
			}

			json = fetch_transaction_result(fd);
			if (json && !pending) {
				pr_err("received unknown transaction result.");
				json_decref(json);
			} else if (json) {
				sbuf_push(tr->result, json);
				pending = false;
			}
		}

		/* process new transaction only if no result is pending */
		if (!pending) {
			if (sbuf_trypop(srdb->transactions, (void **)&tr))
				continue;

			if (!tr)
				break;

			if (send_transaction(fd, tr->json, ++transact_id) < 0) {
				pr_err("failed to send transaction id %u\n",
				       transact_id);
				break;
			}

			pending = true;
		}
	}

	close(fd);

	return NULL;
}
