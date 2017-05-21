#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>

#include <jansson.h>

#include "srdb.h"
#include "misc.h"

#define BUFLEN 1024
#define JSON_BUFLEN 5000
#define READ_OVSDB_SERVER(b, addr, port) sscanf(b, "tcp:[%[^]]]:%hu", addr, port)
#define BOOL_TO_STR(boolean) boolean ? "true" : "false"

#define MAX_PENDING_MSG 500

void *transaction_worker(void *args);

static int parse_ovsdb_update_tables(json_t *table_updates, int initial,
				     int (*callback)(const char *,
					     	     json_t *, int, void *),
				     void *arg)
{
	int ret = 0;
	json_t *modification = NULL;
	const char *uuid = NULL;

	json_object_foreach(table_updates, uuid, modification) {
		if ((ret = callback(uuid, modification, initial, arg))) {
			break;
		}
	}
	return ret;
}

static int parse_ovsdb_monitor_reply(json_t *monitor_reply, struct srdb_table *tbl,
	                             int (*callback)(const char *, json_t *, int,
						     void *), void *arg)
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
		ret = parse_ovsdb_update_tables(table_updates, 1, callback, arg);

	sem_post(&tbl->initial_read);

	return ret;
}

static int parse_ovsdb_update(json_t *update, struct srdb_table *tbl,
		              int (*callback)(const char *, json_t *, int, void *),
					      void *arg)
{
	json_t *params = json_object_get(update, "params");
	if (!params) {
		fprintf(stderr, "Update parsing issue: params key not found\n");
		return -1;
	}
	if (json_array_size(params) < 2) {
		fprintf(stderr, "Update parsing issue: No params\n");
		return -1;
	}
	json_t *updates = json_array_get(params, 1);
	if (!updates) {
		fprintf(stderr, "Update parsing issue: No update found\n");
		return -1;
	}
	json_t *table_updates = json_object_get(updates, tbl->name);
	if (!table_updates) {
		fprintf(stderr, "Update parsing issue: No update for table %s found\n", tbl->name);
		return -1;
	}
	return parse_ovsdb_update_tables(table_updates, 0, callback, arg);
}

static inline int parse_ovsdb_echo(json_t *msg)
{
	json_t *method = json_object_get(msg, "method");
	return (!method || !json_is_string(method) || strcmp(json_string_value(method), "echo"));
}

static int ovsdb_socket(const struct ovsdb_config *conf)
{
	int sfd = -1;
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

	sfd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (connect(sfd, (struct sockaddr *) &addr, sizeof(addr))) {
		perror("connect to ovsdb server");
		goto close_sfd;
	}

	int i = 1;
	if (setsockopt(sfd, SOL_TCP, TCP_NODELAY, &i, sizeof(i)) < 0) {
		perror("setsockopt");
		goto close_sfd;
	}

out:
	return sfd;
close_sfd:
	close(sfd);
	sfd = -1;
	goto out;
}

static int ovsdb_monitor(struct srdb *srdb, struct srdb_table *tbl, int modify,
			 int initial, int insert, int delete,
			 int (*callback)(const char *, json_t *, int, void *),
			 void *arg)
{
	int ret;
	char buf[JSON_BUFLEN+1];
	json_t *json = NULL;
	json_error_t json_error;
	size_t length = 0;
	size_t position = 0;
	int stop = 0;
	int err = 0;
	char *echo_reply = "{\"id\":\"echo\",\"result\":[],\"error\":null}";
	size_t echo_reply_len = strlen(echo_reply);

	int sfd = ovsdb_socket(srdb->conf);
	if (sfd < 0) {
		ret = sfd;
		goto out;
	}

	/* Request monitoring */
	ret = snprintf(buf, JSON_BUFLEN + 1, "{\"id\":0,\"method\":\"monitor\",\"params\":[\"%s\",null,{\"%s\":[{\"select\":{\"modify\":%s,\"initial\":%s,\"insert\":%s,\"delete\":%s}}]}]}",
                       srdb->conf->ovsdb_database, tbl->name, BOOL_TO_STR(modify),
		       BOOL_TO_STR(initial), BOOL_TO_STR(insert), BOOL_TO_STR(delete));
	if (ret < 0) {
		fprintf(stderr, "%s: snprintf to create monitoring command failed\n", __func__);
		goto close_sfd;
	}
	if ((ret = send(sfd, buf, ret, 0)) <= 0) {
		perror("Cannot send monitoring command");
		goto close_sfd;
	}

	/* Handle ovsdb monitor reply and updates */
	while (!stop && (ret = recv(sfd, buf + length, JSON_BUFLEN - length, 0)) > 0) { // TODO Assumes jsons of less than JSON_BUFLEN bytes

		length += ret;
		position = 0;

		while(!stop && position < length - 1 && (json = json_loadb(buf + position, length - position, JSON_DISABLE_EOF_CHECK, &json_error))) {

			position += json_error.position;

			if (!parse_ovsdb_echo(json)) {
				if ((err = send(sfd, echo_reply, echo_reply_len, 0)) < 0) {
					perror("Cannot send an echo reply");
				}
			} else {
				if (json_is_integer(json_object_get(json, "id")))
					stop = parse_ovsdb_monitor_reply(json, tbl, callback, arg);
				else
					stop = parse_ovsdb_update(json, tbl, callback, arg);
			}
			json_decref(json);
		}
		if (!json) /* The full json is not yet in the buffer => wait for it */
			memcpy(buf, buf + position, length - position);
		else
			length = 0;
	}

	if (ret < 0) {
		perror("recv() from ovsdb_monitor() failed");
	}

close_sfd:
	close(sfd);
out:
	return ret;
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

static int find_desc_fromname(struct srdb_descriptor *desc, const char *name)
{
	int i;

	for (i = 0; desc[i].name; i++) {
		if (!strcmp(desc[i].name, name))
			return i;
	}

	return -1;
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

static void fill_srdb_entry(struct srdb_descriptor *desc,
			    struct srdb_entry *entry, const char *uuid, json_t *line_json)
{
	void *data;
	int i;
	json_t *column_value;

	for (i = 0; desc[i].name; i++) {
		if (!strcmp(desc[i].name, "row")) {
			strncpy(entry->row, uuid, desc[i].maxlen);
			continue;
		}

		column_value = json_object_get(line_json, desc[i].name);
		if (!column_value) {
			/* XXX This is valid if an updated entry is filled (only changed fields will appear) */
			continue;
		}
		if (!strcmp(desc[i].name, "_version")) {
			column_value = json_object_get(line_json, "_version");
			column_value = json_array_get(column_value, 1);
		}

		data = (unsigned char *)entry + desc[i].offset;

		switch (desc[i].type) {
		case SRDB_STR:
			if (!json_is_string(column_value))
				fprintf(stderr, "String is expected for %s but the json is not of that type\n", desc[i].name);
			else
				strncpy((char *)data, json_string_value(column_value), desc[i].maxlen);
			break;
		case SRDB_INT:
			if (!json_is_integer(column_value))
				fprintf(stderr, "Integer is expected for %s but the json is not of that type\n", desc[i].name);
			else
				*(int *)data = json_integer_value(column_value);
			break;
		case SRDB_VARSTR:
			if (!json_is_string(column_value))
				fprintf(stderr, "String is expected for %s but the json is not of that type\n", desc[i].name);
			else
				*(char **)data = strndup(json_string_value(column_value), desc[i].maxlen);
			break;
		}
	}
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
	},							\
	{							\
		.name	= "action",				\
		.type	= SRDB_STR,				\
		.maxlen	= SLEN,					\
		.builtin = true,				\
		.offset	= offsetof(struct srdb_entry, action),	\
	},							\
	{							\
		.name	= "_version",				\
		.type	= SRDB_STR,				\
		.maxlen	= SLEN,					\
		.builtin = true,				\
		.offset = offsetof(struct srdb_entry, version),	\
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

static int srdb_read(const char *uuid, json_t *json, int initial, void *arg)
{
	int idx;
	struct srdb_table *tbl = arg;
	struct srdb_entry *entry = NULL;
	char *action;
	json_t *new = NULL;
	json_t *old = NULL;
	int ret = 0;

	if (!uuid || !json)
		return -1;

	new = json_object_get(json, "new");
	old = json_object_get(json, "old");

	idx = find_desc_fromname(tbl->desc, "action");
	if (idx < 0) {
		pr_err("field `action' not present in row.");
		free_srdb_entry(tbl->desc, entry);
		ret = -1;
		goto out;
	}

	if (new) {
		entry = calloc(1, tbl->entry_size);
		action = (char *)entry + tbl->desc[idx].offset;
		if (!entry) {
			ret = -1;
			goto out;
		}
	}
	if (old) {
		tbl->update_entry = calloc(1, tbl->entry_size);
		if (!tbl->update_entry) {
			ret = -1;
			goto free_new;
		}
	}


	if (new && !old) {
		sprintf(action, "%s", initial ? "initial" : "insert");
		fill_srdb_entry(tbl->desc, entry, uuid, new);

		if (tbl->read)
			ret = tbl->read(entry);
		if (!tbl->delayed_free)
			free_srdb_entry(tbl->desc, entry);
	} else if (new && old) { /* TODO fix for delayed free / MT */
		strcpy(action, "update");
		fill_srdb_entry(tbl->desc, tbl->update_entry, uuid, old);
		memcpy(entry, tbl->update_entry, tbl->entry_size);
		fill_srdb_entry(tbl->desc, entry, uuid, new);

		if (tbl->read_update)
			ret = tbl->read_update(tbl->update_entry, entry);
		free_srdb_entry(tbl->desc, tbl->update_entry);
		free_srdb_entry(tbl->desc, entry);
		tbl->update_entry = NULL;
	} else if (old) {
		action = (char *)(tbl->update_entry) + tbl->desc[idx].offset;
		strcpy(action, "delete");
		fill_srdb_entry(tbl->desc, tbl->update_entry, uuid, old);
		if (tbl->read_delete)
			ret = tbl->read_delete(tbl->update_entry);
		free_srdb_entry(tbl->desc, tbl->update_entry);
		tbl->update_entry = NULL;
	} else {
		free_srdb_entry(tbl->desc, entry);
		pr_err("unknown action type `%s'.", action);
		ret = -1;
	}

out:
	return ret;
free_new:
	if (entry)
		free_srdb_entry(tbl->desc, entry);
	goto out;
}

int srdb_monitor(struct srdb *srdb, struct srdb_table *tbl, int modify,
		 int initial, int insert, int delete)
{
	int ret;

	ret = ovsdb_monitor(srdb, tbl, modify, initial, insert, delete,
			    srdb_read, tbl);

	return ret;
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
	utr->index_mask |= 1 << index;

	return 0;
}

void srdb_update_append_mask(struct srdb_update_transact *utr,
			     unsigned int index_mask)
{
	const struct srdb_descriptor *desc;
	unsigned int i;

	for (i = 0; utr->tbl->desc[i].name; i++) {
		desc = &utr->tbl->desc[i];
		if (index_mask & (1 << desc->index))
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

	srdb->transactions = sbuf_new(2 * conf->ntransacts);
	if (!srdb->transactions)
		goto out_free_workers;

	for (i = 0; i < conf->ntransacts; i++)
		pthread_create(&srdb->tr_workers[i], NULL, transaction_worker,
			       srdb);

	return srdb;

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
	int i;

	for (i = 0; i < srdb->conf->ntransacts; i++)
		sbuf_push(srdb->transactions, NULL);

	for (i = 0; i < srdb->conf->ntransacts; i++)
		pthread_join(srdb->tr_workers[i], NULL);

	free(srdb->tr_workers);
	sbuf_destroy(srdb->transactions);
	srdb_free_tables(srdb->tables);
	free(srdb);
}

void srdb_set_read_cb(struct srdb *srdb, const char *table,
		      int (*cb)(struct srdb_entry *))
{
	struct srdb_table *tbl;

	tbl = srdb_table_by_name(srdb->tables, table);
	if (!tbl)
		return;

	tbl->read = cb;
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
	if (ret <= 0)
		goto out_err;

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

static int echo_reply(int fd)
{
	const char reply[] = "{\"id\":\"echo\",\"result\":[],\"error\":null}";

	return send(fd, reply, sizeof(reply) - 1, 0);
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
	if (method && !strcmp(json_string_value(method),
			      "echo")) {
		if (echo_reply(fd) < 0)
			pr_err("failed to send echo reply.");

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

void *transaction_worker(void *args)
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
