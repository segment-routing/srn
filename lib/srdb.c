#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <jansson.h>

#include "srdb.h"
#include "misc.h"

#define BUFLEN 1024
#define JSON_BUFLEN 5000
#define READ_OVSDB_SERVER(b, addr, port) sscanf(b, "tcp:[%[^]]]:%hu", addr, port)
#define BOOL_TO_STR(boolean) boolean ? "true" : "false"

static int parse_ovsdb_update_tables(json_t *table_updates, int initial, int (*callback)(const char *uuid, json_t *buf, int initial, void *), void *arg)
{
	int ret = 0;
	json_t *modification = NULL;
	const char *uuid = NULL;

	char *json_str = json_dumps(table_updates, 0); // TODO
	printf("%s: table updates = %s\n" ,__func__, json_str); // TODO
	free(json_str); // TODO

	json_object_foreach(table_updates, uuid, modification) {
		if ((ret = callback(uuid, modification, initial, arg))) {
			json_str = json_dumps(modification, 0); // TODO
			printf("%s: Non-zero value for the table update = %s\n" ,__func__, json_str); // TODO
			free(json_str); // TODO
			break;
		}
	}
	return ret;
}

static int parse_ovsdb_monitor_reply(json_t *monitor_reply, const char *table,
	                                   int (*callback)(const char *uuid, json_t *buf, int initial, void *), void *arg)
{
	if (!json_is_null(json_object_get(monitor_reply, "error"))) {
		fprintf(stderr, "There is a non-null error message in the monitor reply\n");
		return -1;
	}
	json_t *updates = json_object_get(monitor_reply, "result");
	if (!updates) {
		fprintf(stderr, "Monitor reply parsing issue: No result found\n");
		return -1;
	}
	json_t *table_updates = json_object_get(updates, table);
	if (!table_updates) {
		// No initial data
		return 0;
	}
	return parse_ovsdb_update_tables(table_updates, 1, callback, arg);
}

static int parse_ovsdb_update(json_t *update, const char *table,
	                            int (*callback)(const char *uuid, json_t *buf, int initial, void *), void *arg)
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
	json_t *table_updates = json_object_get(updates, table);
	if (!table_updates) {
		fprintf(stderr, "Update parsing issue: No update for table %s found\n", table);
		return -1;
	}
	return parse_ovsdb_update_tables(table_updates, 0, callback, arg);
}

static inline int parse_ovsdb_echo(json_t *msg)
{
	json_t *method = json_object_get(msg, "method");
	return (!method || !json_is_string(method) || strcmp(json_string_value(method), "echo"));
}

static int ovsdb_monitor(const struct ovsdb_config *conf, const char *table,
			 int modify, int initial, int insert, int delete,
			 int (*callback)(const char *uuid, json_t *buf, int initial, void *), void *arg)
{
	int ret;
	int i = 1;
	char str_addr[BUFLEN+1];
	char buf[JSON_BUFLEN+1];
	unsigned short port;
	json_t *json = NULL;
	json_error_t json_error;
	size_t length = 0;
	size_t position = 0;
	int stop = 0;
	int err = 0;
	char *echo_reply = "{\"id\":\"echo\",\"result\":[],\"error\":null}";
	size_t echo_reply_len = strlen(echo_reply);

	/* Init monitoring socket */

	READ_OVSDB_SERVER(conf->ovsdb_server, str_addr, &port);
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0
	};
	inet_pton(AF_INET6, str_addr, &addr.sin6_addr);

	int sfd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	connect(sfd, (struct sockaddr *) &addr, sizeof(addr));

	if (setsockopt(sfd, SOL_TCP, TCP_NODELAY, &i, sizeof(i)) < 0) {
		perror("setsockopt");
		goto close_sfd;
	}

	/* Request monitoring */
	ret = snprintf(buf, JSON_BUFLEN + 1, "{\"id\":0,\"method\":\"monitor\",\"params\":[\"%s\",null,{\"%s\":[{\"select\":{\"modify\":%s,\"initial\":%s,\"insert\":%s,\"delete\":%s}}]}]}",
                 conf->ovsdb_database, table, BOOL_TO_STR(modify), BOOL_TO_STR(initial), BOOL_TO_STR(insert), BOOL_TO_STR(delete));
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

			char *json_str = json_dumps(json, 0); // TODO
			printf("%s: begin inner loop received json = %s - length = %lu - position = %lu\n" ,__func__, json_str, length, position); // TODO
			free(json_str); // TODO

			if (!parse_ovsdb_echo(json)) {
				if ((err = send(sfd, echo_reply, echo_reply_len, 0)) < 0) {
					perror("Cannot send an echo reply");
				}
			} else {
				if (json_is_integer(json_object_get(json, "id"))) {
					stop = parse_ovsdb_monitor_reply(json, table, callback, arg);
				} else {
					stop = parse_ovsdb_update(json, table, callback, arg);
				}
				json_decref(json);
			}
			printf("%s: end inner loop - length = %lu - position = %lu\n" ,__func__, length, position); // TODO
		}
		if (!json) /* The full json is not yet in the buffer => wait for it */
			memcpy(buf, buf + position, length - position);
		else
			length = 0;
		printf("%s: end outer loop - length = %lu - position = %lu\n" ,__func__, length, position); // TODO
	}

	if (ret < 0) {
		perror("recv() from ovsdb_monitor() failed");
	}

	printf("%s: END OF FUNCTION\n", __func__); //TODO

close_sfd:
	close(sfd);
	return ret;
}

// TODO Start socket for update + put nodelay

// TODO Close socket for update

static int ovsdb_update(const struct ovsdb_config *conf, const char *table,
			const char *uuid, const char *fields)
{
	char line[BUFLEN];
	char cmd[BUFLEN];
	int ret = 0;
	FILE *fp;

	// TODO Forge json object as below + send it on the socket in argument

	snprintf(cmd, BUFLEN, "%s transact '%s' '[\"%s\", {\"op\": \"update\", "
			   "\"table\": \"%s\", \"where\": [[\"_uuid\", \"==\","
			   " [\"uuid\", \"%s\"]]], \"row\": {%s}}]' "
			   "2>/dev/null", conf->ovsdb_client,
			   conf->ovsdb_server, conf->ovsdb_database, table,
			   uuid, fields);

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

static int ovsdb_insert(const struct ovsdb_config *conf, const char *table,
			const char *fields, char *uuid)
{
	const char *_start_match = "[{\"uuid\":[\"uuid\",";
	char line[BUFLEN];
	char cmd[BUFLEN];
	int ret = 0;
	FILE *fp;

	snprintf(cmd, BUFLEN, "%s transact '%s' '[\"%s\", {\"op\": \"insert\", "
			      "\"table\": \"%s\", \"row\": {%s}}]' 2>/dev/null",
			      conf->ovsdb_client, conf->ovsdb_server,
			      conf->ovsdb_database, table, fields);

	fp = popen(cmd, "r");
	if (!fp) {
		perror("popen");
		return -1;
	}

	while (fgets(line, BUFLEN, fp)) {
		strip_crlf(line);
		if (!strncmp(line, _start_match, strlen(_start_match)))
			ret = 0;
		else
			ret = 1;
		break;
	}

	if (uuid && !ret)
		sscanf(line, "[{\"uuid\":[\"uuid\",\"%[a-z0-9-]\"]}]", uuid);

	if (pclose(fp) < 0)
		perror("close");

	return ret;
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
			if (strcmp(desc[i].name, "action"))
				fprintf(stderr, "The column %s cannot be found !\n", desc[i].name);
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
				*(int *)data = (int) ntohl((long) json_integer_value(column_value));
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
	},
	{
		.name	= "destination",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWREQ(destination),
	},
	{
		.name	= "dstaddr",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWREQ(dstaddr),
	},
	{
		.name	= "source",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWREQ(source),
	},
	{
		.name	= "bandwidth",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
		.offset	= OFFSET_FLOWREQ(bandwidth),
	},
	{
		.name	= "delay",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
		.offset	= OFFSET_FLOWREQ(delay),
	},
	{
		.name	= "router",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset = OFFSET_FLOWREQ(router),
	},
	{
		.name	= "proxy",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWREQ(proxy),
	},
	{
		.name	= "status",
		.type	= SRDB_INT,
		.maxlen	= sizeof(int),
		.offset	= OFFSET_FLOWREQ(status),
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
	},
	{
		.name	= "dstaddr",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(dstaddr),
	},
	{
		.name	= "bsid",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(bsid),
	},
	{
		.name	= "segments",
		.type	= SRDB_VARSTR,
		.maxlen	= BUFLEN,
		.offset	= OFFSET_FLOWSTATE(segments),
	},
	{
		.name	= "bandwidth",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(bandwidth),
	},
	{
		.name	= "delay",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(delay),
	},
	{
		.name	= "policing",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(policing),
	},
	{
		.name	= "source",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(source),
	},
	{
		.name	= "router",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(router),
	},
	{
		.name	= "proxy",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(proxy),
	},
	{
		.name	= "interface",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(interface),
	},
	{
		.name	= "reverseFlow",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(reverse_flow_uuid),
	},
	{
		.name	= "request",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_FLOWSTATE(request_id),
	},
	{
		.name	= "ttl",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(ttl),
	},
	{
		.name	= "idle",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(idle),
	},
	{
		.name	= "timestamp",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(timestamp),
	},
	{
		.name	= "status",
		.type	= SRDB_INT,
		.offset	= OFFSET_FLOWSTATE(status),
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
	},
	{
		.name	= "addr1",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_LINKSTATE(addr1),
	},
	{
		.name	= "name2",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_LINKSTATE(name2),
	},
	{
		.name	= "addr2",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_LINKSTATE(addr2),
	},
	{
		.name	= "metric",
		.type	= SRDB_INT,
		.offset	= OFFSET_LINKSTATE(metric),
	},
	{
		.name	= "bw",
		.type	= SRDB_INT,
		.offset	= OFFSET_LINKSTATE(bw),
	},
	{
		.name	= "ava_bw",
		.type	= SRDB_INT,
		.offset	= OFFSET_LINKSTATE(ava_bw),
	},
	{
		.name	= "delay",
		.type	= SRDB_INT,
		.offset	= OFFSET_LINKSTATE(delay),
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
	},
	{
		.name	= "addr",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_NODESTATE(addr),
	},
	{
		.name	= "prefix",
		.type	= SRDB_VARSTR,
		.maxlen	= BUFLEN,
		.offset	= OFFSET_NODESTATE(prefix),
	},
	{
		.name	= "pbsid",
		.type	= SRDB_STR,
		.maxlen	= SLEN,
		.offset	= OFFSET_NODESTATE(pbsid),
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

	gettimeofday(&tbl->last_read, NULL);

	if (!uuid || !json)
		return -1;

	new = json_object_get(json, "new");
	old = json_object_get(json, "old");

	char *json_str = json_dumps(json, 0); // TODO
	printf("\n%s: json = %s - old %d - new %d - initial %d\n" ,__func__, json_str, !!old, !!new, initial); // TODO
	free(json_str); // TODO

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


	if (new) {
		sprintf(action, "%s", initial ? "initial" : "insert");
		fill_srdb_entry(tbl->desc, entry, uuid, new);

		printf("%s: entry uuid %s\n" ,__func__, entry->row); // TODO
		printf("%s: entry action %s\n" ,__func__, action); // TODO
		printf("%s: entry version %s\n" ,__func__, entry->version); // TODO

		if (tbl->read)
			ret = tbl->read(entry);
		if (!tbl->delayed_free)
			free_srdb_entry(tbl->desc, entry);
	} else if (new && old) { /* TODO fix for delayed free / MT */
		strcpy(action, "update");
		fill_srdb_entry(tbl->desc, entry, uuid, new);
		memcpy(entry, tbl->update_entry, tbl->entry_size);
		fill_srdb_entry(tbl->desc, tbl->update_entry, uuid, old);

		printf("%s: entry uuid %s\n" ,__func__, entry->row); // TODO
		printf("%s: entry action %s\n" ,__func__, action); // TODO
		printf("%s: entry version %s\n" ,__func__, entry->version); // TODO

		printf("%s: old entry uuid %s\n" ,__func__, tbl->update_entry->row); // TODO
		printf("%s: old entry action %s\n" ,__func__, action); // TODO
		printf("%s: old entry version %s\n" ,__func__, tbl->update_entry->version); // TODO

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

int srdb_monitor(struct srdb *srdb, struct srdb_table *tbl, int modify, int initial, int insert, int delete)
{
	int ret;

	ret = ovsdb_monitor(&srdb->conf, tbl->name, modify, initial, insert, delete, srdb_read, tbl);

	return ret;
}

static int write_desc_data(char *buf, size_t size,
			   const struct srdb_descriptor *desc,
			   struct srdb_entry *entry)
{
	int wr = -1;
	void *data;

	data = (unsigned char *)entry + desc->offset;

	switch (desc->type) {
	case SRDB_STR:
		wr = snprintf(buf, size, "\"%s\": \"%s\"", desc->name,
			      (char *)data);
		break;
	case SRDB_INT:
		wr = snprintf(buf, size, "\"%s\": %d", desc->name,
			      *(int *)data);
		break;
	case SRDB_VARSTR:
		wr = snprintf(buf, size, "\"%s\": \"%s\"", desc->name,
			      *(char **)data);
		break;
	}

	return wr;
}

int srdb_update(struct srdb *srdb, struct srdb_table *tbl,
		struct srdb_entry *entry, const char *fieldname)
{
	const struct srdb_descriptor *desc;
	char field_update[SLEN + 1];
	int ret, idx;

	idx = find_desc_fromname(tbl->desc, fieldname);
	if (idx < 0)
		return -1;

	desc = &tbl->desc[idx];

	// TODO Update the creation of the json
	write_desc_data(field_update, SLEN, desc, entry);
	// TODO Update the creation of the json

	ret = ovsdb_update(&srdb->conf, tbl->name, entry->row, field_update);

	return ret;
}

int srdb_insert(struct srdb *srdb, struct srdb_table *tbl,
		struct srdb_entry *entry, char *uuid)
{
	const struct srdb_descriptor *tmp;
	char fields[BUFLEN + 1];
	char field[SLEN + 1];
	int ret;

	memset(fields, 0, BUFLEN + 1);

	for (tmp = tbl->desc; tmp->name; tmp++) {
		if (!tmp->builtin) {
			// TODO Update the creation of the json
			ret = write_desc_data(field, SLEN, tmp, entry);
			// TODO Update the creation of the json
			if (ret < 0)
				return ret;

			// TODO fix that horrible stuff
			strcat(fields, field);
			if ((tmp+1)->name)
				strcat(fields, ", ");
		}
	}

	ret = ovsdb_insert(&srdb->conf, tbl->name, fields, uuid);

	return ret;
}

struct srdb *srdb_new(const struct ovsdb_config *conf)
{
	struct srdb *srdb;

	srdb = malloc(sizeof(*srdb));
	if (!srdb)
		return NULL;

	srdb->tables = srdb_get_tables();
	if (!srdb->tables) {
		free(srdb);
		return NULL;
	}

	memcpy(&srdb->conf, conf, sizeof(*conf));

	return srdb;
}

void srdb_destroy(struct srdb *srdb)
{
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
